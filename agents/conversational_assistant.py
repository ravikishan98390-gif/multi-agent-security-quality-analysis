"""
conversational_assistant.py — RAG-based conversational code assistant.

Answers user questions about findings and secure coding practices by
retrieving relevant OWASP/secure-coding context from the vector store,
then generating a grounded response.

Works fully offline (rule-based fallback) or with OpenAI when an API key
is configured.
"""

from __future__ import annotations

import os
from typing import List

from agents.rag_engine import retrieve


# ---------------------------------------------------------------------------
# Offline rule-based QA (no LLM required)
# ---------------------------------------------------------------------------

_OFFLINE_ANSWERS: dict[str, str] = {
    "sql injection": (
        "SQL injection (OWASP A03:2021) occurs when untrusted data is sent to an interpreter "
        "as part of a command. Prevention: always use parameterized queries or prepared statements; "
        "never concatenate user input into SQL strings. Example: "
        "`cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`."
    ),
    "xss": (
        "Cross-Site Scripting (XSS, OWASP A03:2021) allows attackers to inject client-side scripts. "
        "Prevention: escape all user output in HTML context using context-aware encoding, "
        "set a strict Content-Security-Policy header, and validate/sanitize inputs server-side. "
        "In Jinja2/Flask use `{{ value | e }}` or `Markup.escape()`."
    ),
    "csrf": (
        "CSRF (OWASP A01:2021) tricks a user's browser into making unintended requests. "
        "Prevention: use CSRF tokens (e.g. flask-wtf) on all state-changing forms, "
        "validate the Origin/Referer header, and set `SameSite=Strict` on session cookies."
    ),
    "hardcoded": (
        "Hardcoded credentials in source code (OWASP A02:2021) expose secrets to anyone with "
        "code or version-control access. Store secrets in environment variables or a secrets "
        "manager (AWS Secrets Manager, HashiCorp Vault), and scan with truffleHog or git-secrets "
        "before every commit."
    ),
    "bcrypt": (
        "bcrypt is a password hashing algorithm designed to be slow and work-factor tunable. "
        "Use `passlib.hash.bcrypt` or `bcrypt` library in Python with a cost factor of ≥ 12. "
        "Always use a unique per-password salt (bcrypt generates this automatically)."
    ),
    "argon2": (
        "Argon2 is the winner of the Password Hashing Competition and the current recommended "
        "algorithm for password storage. Use `argon2-cffi` in Python. "
        "It provides memory-hard resistance against GPU-based brute-force attacks."
    ),
    "scrypt": (
        "scrypt is a memory-hard key derivation function suitable for password hashing. "
        "Available in Python's built-in `hashlib.scrypt()`. "
        "Prefer Argon2 for new projects; scrypt is a solid alternative when Argon2 is unavailable."
    ),
    "md5": (
        "MD5 is cryptographically broken and must not be used for security purposes (OWASP A02:2021). "
        "For passwords use bcrypt, Argon2, or scrypt. "
        "For non-password integrity checks (e.g. file checksums), use SHA-256 or stronger."
    ),
    "sha1": (
        "SHA-1 is cryptographically broken and must not be used for passwords or digital signatures. "
        "Replace with SHA-256/SHA-3 for integrity checks, or bcrypt/Argon2 for password storage."
    ),
    "complexity": (
        "High cyclomatic complexity makes code harder to test and maintain. "
        "Reduce it by extracting conditional branches into guard clauses (early returns), "
        "using strategy objects, or replacing long if-chains with lookup tables or polymorphism. "
        "Aim for cyclomatic complexity ≤ 10 per function."
    ),
    "owasp": (
        "The OWASP Top 10 (2021) lists the most critical web application security risks: "
        "A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, "
        "A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable Components, "
        "A07 Identification & Authentication Failures, A08 Software Integrity Failures, "
        "A09 Security Logging Failures, A10 SSRF. See https://owasp.org/Top10/ for detail."
    ),
    "broken access control": (
        "Broken Access Control (OWASP A01:2021) occurs when users can act outside their intended "
        "permissions. Prevention: enforce authorization at every sensitive endpoint, verify resource "
        "ownership (user_id == resource.owner_id), use RBAC or ABAC, and deny by default."
    ),
    "idor": (
        "Insecure Direct Object Reference (IDOR) is a form of broken access control where an "
        "attacker changes a URL parameter (e.g. /users/42 → /users/43) to access another user's "
        "data. Prevention: never expose raw database IDs — validate ownership server-side on every "
        "request, or use opaque UUIDs with ownership checks."
    ),
    "jwt": (
        "JWT (JSON Web Token) vulnerabilities include: accepting 'none' algorithm, weak secrets, "
        "and missing expiry checks. Prevention: whitelist allowed algorithms (e.g. RS256, HS256), "
        "use a strong secret (≥ 256-bit), validate `exp`, `iss`, and `aud` claims on every request. "
        "Use `PyJWT` with explicit `algorithms` parameter."
    ),
    "injection": (
        "Injection flaws (OWASP A03:2021) occur when untrusted data is sent to an interpreter. "
        "Types: SQL, NoSQL, OS command, LDAP, XPath injection. "
        "Prevention: use parameterized queries/prepared statements, avoid eval(), "
        "and validate/allowlist all inputs before passing to interpreters."
    ),
    "deserialization": (
        "Insecure deserialization (OWASP A08:2021) allows attackers to execute arbitrary code "
        "by manipulating serialized objects. Prevention: avoid deserializing untrusted data with "
        "`pickle`, `yaml.load()`, or Java's ObjectInputStream — use JSON with strict schema "
        "validation or message-pack with type whitelisting instead."
    ),
}


def _offline_answer(message: str) -> str | None:
    msg_lower = message.lower()
    for keyword, answer in _OFFLINE_ANSWERS.items():
        if keyword in msg_lower:
            return answer
    return None


# ---------------------------------------------------------------------------
# LLM-grounded answer via OpenAI
# ---------------------------------------------------------------------------

def _llm_answer(
    message: str,
    context_chunks: list[dict],
    history: list[dict] | None = None,
    code_context: str | None = None,
    findings: list[dict] | None = None,
    language: str | None = None
) -> str | None:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        import openai
        client = openai.OpenAI(api_key=api_key)

        context_text = "\n\n".join(
            f"[Source {i+1}: {c['document']} / {c['section']}" +
            (f" (relevance: {c.get('score', ''):.2f})" if c.get('score') else "") +
            f"]\n{c['text']}"
            for i, c in enumerate(context_chunks)
        )

        # Build code context if available
        code_context_text = ""
        if code_context:
            code_lines = code_context.split('\n')
            truncated_code = '\n'.join(code_lines[:50])  # First 50 lines
            if len(code_lines) > 50:
                truncated_code += f"\n... ({len(code_lines) - 50} more lines)"
            code_context_text = f"\n\nSOURCE CODE ({language or 'unknown'}):\n```{language or 'text'}\n{truncated_code}\n```"

        # Build findings context
        findings_context_text = ""
        if findings:
            findings_context_text = "\n\nFINDINGS:\n"
            for f in findings[:10]:  # Top 10 findings
                findings_context_text += f"- Line {f.get('line')}: [{f.get('severity')}] {f.get('title')}\n"

        system_prompt = (
            "You are SecureCodeBot, a specialized secure-coding assistant with deep OWASP expertise.\n\n"
            "CONTEXT (OWASP knowledge base excerpts — use these as your primary source):\n"
            f"{context_text}"
            f"{code_context_text}"
            f"{findings_context_text}"
            "\n\nRULES:\n"
            "  1. Answer using the context above as your primary source.\n"
            "  2. If the context does not fully cover the question, supplement with your general "
            "     security knowledge but clearly label it as general advice.\n"
            "  3. Be concise: 2–4 sentences for simple questions, up to 6 for complex ones.\n"
            "  4. Always mention the OWASP category if relevant (e.g. 'OWASP A03:2021').\n"
            "  5. End with a concrete, actionable code example or one-line fix when possible.\n"
            "  6. Cite the source document at the end if used (format: [Source: DocName / Section]).\n"
            "  7. If asked to fix code, provide both the vulnerable and secure versions side-by-side.\n"
            "  8. Do NOT use excessive caveats or repeat the question back."
        )

        messages: list[dict] = [{"role": "system", "content": system_prompt}]

        # Include conversation history for multi-turn context
        if history:
            for turn in history[-6:]:  # cap at last 6 turns to stay within token budget
                role = turn.get("role", "user")
                content = turn.get("content", "")
                if role in ("user", "assistant") and content:
                    messages.append({"role": role, "content": content})

        messages.append({"role": "user", "content": message})

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            temperature=0.15,
        )
        return response.choices[0].message.content.strip()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def answer(
    message: str, 
    k: int = 5, 
    history: list[dict] | None = None,
    code_context: str | None = None,
    findings: list[dict] | None = None,
    language: str | None = None,
    filename: str | None = None
) -> dict:
    """
    Answer a user question using RAG retrieval + optional LLM generation.
    Now with full code context for code-aware analysis and fixes.

    Parameters
    ----------
    message : The user's natural language question.
    k       : Number of knowledge base chunks to retrieve (default: 5).
    history : Optional list of previous conversation turns for multi-turn context.
              Each entry: {"role": "user" | "assistant", "content": str}
    code_context : Optional full source code for context-aware analysis
    findings : Optional list of findings for referenced context
    language : Programming language ("python" or "java")
    filename : Original filename

    Returns
    -------
    {
        "reply": str,                    # The assistant's answer
        "sources": list[str],            # Source document references
        "referencedFindingIds": list,    # Finding IDs mentioned in response
        "codeFix": {...} | None          # Suggested code fix if applicable
    }
    """
    # 1. Retrieve context from knowledge base
    chunks: list[dict] = []
    sources: list[str] = []
    try:
        chunks = retrieve(message, k=k)
        sources = list({
            f"{c['document']} — {c['section']}"
            for c in chunks
            if c.get("document") and c.get("section")
        })
    except Exception:
        pass

    # 2. Try LLM-grounded answer (with code context if available)
    reply = _llm_answer(
        message, 
        chunks, 
        history=history,
        code_context=code_context,
        findings=findings,
        language=language
    ) if chunks else None

    # 3. Fall back to offline keyword answer
    if not reply:
        reply = _offline_answer(message)

    # 4. Fallback: quote the top 2 RAG hits with source attribution
    if not reply and chunks:
        parts = []
        for hit in chunks[:2]:
            parts.append(
                f"Based on '{hit['section']}' in {hit['document']}: {hit['text'][:300]}..."
            )
        reply = "\n\n".join(parts)

    if not reply:
        reply = (
            "I don't have specific information on that topic in my knowledge base. "
            "Please consult the OWASP documentation at https://owasp.org/Top10/ "
            "for authoritative guidance."
        )

    # Extract referenced findings from the message/response
    referenced_finding_ids = []
    if findings:
        reply_lower = (reply or "").lower()
        for f in findings:
            if (f.get("title", "").lower() in reply_lower or 
                f.get("description", "").lower()[:30] in reply_lower or
                f"line {f.get('line')}" in reply_lower):
                referenced_finding_ids.append(f.get("id"))

    return {
        "reply": reply, 
        "sources": sources,
        "referencedFindingIds": referenced_finding_ids[:5],  # Top 5
        "codeFix": None  # LLM can generate this in future
    }
