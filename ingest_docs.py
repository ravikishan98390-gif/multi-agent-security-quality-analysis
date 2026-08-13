"""
ingest_docs.py — Ingestion script to build the local secure coding RAG database.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path to resolve agents package imports
sys.path.append(str(Path(__file__).parent))

from agents.rag_engine import ingest_document

DOCS_DIR = Path("knowledge_base_docs")


def main() -> None:
    print("Initializing ingestion...")
    if not DOCS_DIR.exists():
        print(f"Error: Directory '{DOCS_DIR}' does not exist.")
        sys.exit(1)

    md_files = list(DOCS_DIR.glob("*.md"))
    if not md_files:
        print("No markdown files found to ingest.")
        sys.exit(0)

    print(f"Found {len(md_files)} documents to ingest.")

    for path in md_files:
        print(f"Ingesting {path.name}...")
        try:
            content = path.read_text(encoding="utf-8")
            ingest_document(str(path), content)
            print(f"Successfully indexed {path.name}.")
        except Exception as e:
            print(f"Failed to ingest {path.name}: {e}")

    print("Ingestion complete! Local Chroma vector DB built successfully.")


if __name__ == "__main__":
    main()
