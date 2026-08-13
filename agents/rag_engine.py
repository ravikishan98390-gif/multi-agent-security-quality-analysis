"""
rag_engine.py — Ingestion, embedding, and retrieval engine for secure coding.

Uses Chroma DB and sentence-transformers locally.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TypedDict

import chromadb
from sentence_transformers import SentenceTransformer

CHROMA_DB_PATH = Path(".chroma_db")
COLLECTION_NAME = "secure_coding_rules"

# Lazy initialization of resources
_model: SentenceTransformer | None = None
_chroma_client: chromadb.PersistentClient | None = None
_collection: chromadb.Collection | None = None


class Chunk(TypedDict):
    text: str
    document: str
    section: str


def get_model() -> SentenceTransformer | None:
    """Lazily load the SentenceTransformer model if available."""
    global _model
    if _model is None:
        try:
            # Load small, fast local embedding model (384 dimensions)
            _model = SentenceTransformer("all-MiniLM-L6-v2")
        except Exception:
            _model = None
    return _model


def get_chroma_collection() -> chromadb.Collection | None:
    """Lazily initialize Chroma DB persistent client and return the collection if available."""
    global _chroma_client, _collection
    if _chroma_client is None:
        try:
            CHROMA_DB_PATH.mkdir(parents=True, exist_ok=True)
            # Using PersistentClient for disk persistence
            _chroma_client = chromadb.PersistentClient(path=str(CHROMA_DB_PATH))
        except Exception:
            _chroma_client = None

    if _chroma_client is None:
        return None

    if _collection is None:
        try:
            _collection = _chroma_client.get_or_create_collection(
                name=COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},  # Use cosine similarity
            )
        except Exception:
            _collection = None
    return _collection


def chunk_markdown(filename: str, text: str, chunk_size: int = 600, overlap: int = 150) -> list[Chunk]:
    """
    Split markdown document into logical chunks by section headers and paragraphs.
    Ensures metadata fields (document name, section) are preserved.
    """
    lines = text.splitlines()
    document_title = Path(filename).name

    chunks: list[Chunk] = []
    current_section = "General"
    current_text_lines: list[str] = []
    current_len = 0

    for line in lines:
        stripped = line.strip()
        # Detect headers
        if stripped.startswith("#"):
            # If we have collected content, flush it
            if current_text_lines:
                content = "\n".join(current_text_lines).strip()
                if content:
                    chunks.append({
                        "text": content,
                        "document": document_title,
                        "section": current_section
                    })
                current_text_lines = []
                current_len = 0

            # Update current section
            # e.g., "## Prevention Strategies" -> "Prevention Strategies"
            current_section = stripped.lstrip("#").strip()
            continue

        # Add line to current chunk
        current_text_lines.append(line)
        current_len += len(line) + 1  # include newline char length

        # If we exceed the target chunk size, flush and preserve overlap
        if current_len >= chunk_size:
            content = "\n".join(current_text_lines).strip()
            if content:
                chunks.append({
                    "text": content,
                    "document": document_title,
                    "section": current_section
                })

            # Retain overlap: take last N lines that approximate the overlap length
            overlap_lines: list[str] = []
            overlap_len = 0
            for r_line in reversed(current_text_lines):
                if overlap_len + len(r_line) + 1 <= overlap:
                    overlap_lines.insert(0, r_line)
                    overlap_len += len(r_line) + 1
                else:
                    break

            current_text_lines = overlap_lines
            current_len = overlap_len

    # Flush any remaining content
    if current_text_lines:
        content = "\n".join(current_text_lines).strip()
        if content:
            chunks.append({
                "text": content,
                "document": document_title,
                "section": current_section
            })

    return chunks


def ingest_document(filename: str, markdown_content: str) -> None:
    """Chunk, embed, and store a document in the Chroma vector database."""
    collection = get_chroma_collection()
    model = get_model()

    if collection is None or model is None:
        return

    chunks = chunk_markdown(filename, markdown_content)
    if not chunks:
        return

    ids: list[str] = []
    documents: list[str] = []
    metadatas: list[dict] = []
    texts_to_embed: list[str] = []

    for idx, chunk in enumerate(chunks):
        doc_id = f"{chunk['document']}_{idx}"
        ids.append(doc_id)
        documents.append(chunk["text"])
        metadatas.append({
            "document": chunk["document"],
            "section": chunk["section"]
        })
        # Add grounding context in text to embed for richer vector representation
        embedding_text = f"Document: {chunk['document']}\nSection: {chunk['section']}\nContent: {chunk['text']}"
        texts_to_embed.append(embedding_text)

    # Generate embeddings locally via sentence-transformers
    embeddings = model.encode(texts_to_embed, show_progress_bar=False).tolist()

    # Add to Chroma
    collection.add(
        ids=ids,
        documents=documents,
        metadatas=metadatas,
        embeddings=embeddings
    )


# Maximum cosine distance for a chunk to be considered relevant.
# Chroma cosine distance is in [0, 2]; 0 = identical, 2 = opposite.
# Empirically, chunks above 0.55 are typically off-topic for security queries.
_MAX_DISTANCE: float = 0.55


def retrieve(query: str, k: int = 3, category_hint: str = "") -> list[dict]:
    """
    Retrieve top-k matching secure-coding guideline chunks for a query.

    Parameters
    ----------
    query         : Natural language search query.
    k             : Maximum number of results to return.
    category_hint : Optional vulnerability category (e.g. 'sql_injection').
                    Prepended to the embedded query text to improve semantic
                    alignment with category-specific knowledge base chunks.

    Returns
    -------
    List of dicts: {'text', 'document', 'section', 'distance', 'score'}.
    'score' = 1 - distance  (higher is better, range ≈ 0.45–1.0).
    Low-relevance chunks (distance > _MAX_DISTANCE) are filtered out.
    Falls back to an empty list if embedding/vector DB is unavailable.
    """
    collection = get_chroma_collection()
    model = get_model()

    if collection is None or model is None:
        return []

    # Prepend category hint for richer semantic alignment
    effective_query = f"[{category_hint}] {query}" if category_hint else query

    # Over-fetch slightly then filter by distance threshold
    fetch_k = min(k + 3, 20)

    try:
        query_embedding = model.encode(effective_query, show_progress_bar=False).tolist()
    except Exception:
        return []

    try:
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=fetch_k,
        )
    except Exception:
        return []

    if not results or not results["ids"] or not results["ids"][0]:
        return []

    ids = results["ids"][0]
    docs = results["documents"][0]
    metadata_list = results["metadatas"][0]
    distances = (
        results["distances"][0]
        if "distances" in results and results["distances"]
        else [0.0] * len(ids)
    )

    retrieved: list[dict] = []
    seen_ids: set[str] = set()  # deduplicate by chunk id
    for i in range(len(ids)):
        dist = distances[i]
        chunk_id = ids[i]
        if dist > _MAX_DISTANCE:
            continue  # below relevance threshold
        if chunk_id in seen_ids:
            continue
        seen_ids.add(chunk_id)
        retrieved.append({
            "text": docs[i],
            "document": metadata_list[i].get("document", "Unknown"),
            "section": metadata_list[i].get("section", "Unknown"),
            "distance": round(dist, 4),
            "score": round(1.0 - dist, 4),  # higher = more relevant
        })
        if len(retrieved) >= k:
            break

    # Sort by ascending distance (most relevant first)
    retrieved.sort(key=lambda r: r["distance"])
    return retrieved
