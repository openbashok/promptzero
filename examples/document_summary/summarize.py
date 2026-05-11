"""
summarize.py — Summarize a document via api-pii proxy.

The document text is sent to Claude through the local api-pii proxy,
which anonymizes all PII and sensitive data before the request leaves
your environment, then restores the real values in the summary.

Usage:
    python summarize.py <file>                      # default: general summary
    python summarize.py <file> --mode executive     # business-focused, no technical detail
    python summarize.py <file> --mode technical     # detailed, preserve structure
    python summarize.py <file> --lang es            # respond in Spanish

Supported file types: .pdf, .docx, .txt, .md, .log, .csv

Requirements:
    pip install -r requirements.txt
    # api-pii must be running: python ../../main.py
"""

import argparse
import os
import sys
from pathlib import Path

import anthropic
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROXY_URL   = os.getenv("API_PII_URL", "http://localhost:8000")
API_KEY     = os.getenv("ANTHROPIC_API_KEY", "placeholder")  # proxy forwards the real key
MODEL       = os.getenv("MODEL", "claude-opus-4-6")
MAX_TOKENS  = int(os.getenv("MAX_TOKENS", "2048"))

PROMPTS = {
    "general": (
        "Summarize the following document clearly and concisely. "
        "Preserve all relevant names, organizations, dates, and key figures. "
        "Structure the summary with a brief overview followed by the main points."
    ),
    "executive": (
        "Write an executive summary of the following document. "
        "Focus on business impact, key decisions, and action items. "
        "Avoid technical jargon. Maximum 3 paragraphs."
    ),
    "technical": (
        "Provide a detailed technical summary of the following document. "
        "Preserve all technical terms, identifiers, and numerical values. "
        "Use bullet points for findings or key items."
    ),
}


# ---------------------------------------------------------------------------
# Text extraction
# ---------------------------------------------------------------------------

def extract_text(path: Path) -> str:
    suffix = path.suffix.lower()

    if suffix == ".pdf":
        try:
            import pypdf
        except ImportError:
            sys.exit("pypdf not installed. Run: pip install pypdf")
        reader = pypdf.PdfReader(path)
        pages = [page.extract_text() or "" for page in reader.pages]
        return "\n\n".join(p for p in pages if p.strip())

    if suffix in (".docx", ".doc"):
        try:
            import docx
        except ImportError:
            sys.exit("python-docx not installed. Run: pip install python-docx")
        doc = docx.Document(path)
        return "\n".join(p.text for p in doc.paragraphs if p.text.strip())

    # Plain text fallback (.txt, .md, .log, .csv, etc.)
    return path.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Summarize via api-pii proxy
# ---------------------------------------------------------------------------

def summarize(text: str, mode: str, lang: str, session_id: str) -> str:
    system_prompt = PROMPTS.get(mode, PROMPTS["general"])
    if lang and lang != "en":
        system_prompt += f" Respond in {lang}."

    client = anthropic.Anthropic(
        api_key=API_KEY,
        base_url=PROXY_URL,  # all traffic goes through api-pii
    )

    message = client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=system_prompt,
        messages=[{"role": "user", "content": f"Document:\n\n{text}"}],
        extra_headers={"x-session-id": session_id},
    )

    return message.content[0].text


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Summarize a document via api-pii proxy (PII-safe).",
    )
    parser.add_argument("file", help="Path to the document (pdf, docx, txt, log, csv…)")
    parser.add_argument(
        "--mode", choices=["general", "executive", "technical"],
        default="general", help="Summary style (default: general)",
    )
    parser.add_argument(
        "--lang", default="en",
        help="Response language, e.g. 'es', 'fr', 'pt' (default: en)",
    )
    parser.add_argument(
        "--session", default=None,
        help="Session ID to reuse an existing mapping table (optional)",
    )
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        sys.exit(f"File not found: {path}")

    # Use filename as session ID if not provided — consistent mapping per document
    session_id = args.session or f"doc-{path.stem}"

    print(f"Reading {path.name}...", file=sys.stderr)
    text = extract_text(path)
    if not text.strip():
        sys.exit("Could not extract text from the document.")

    print(
        f"Sending to Claude via api-pii proxy [{args.mode} / {args.lang}]...\n",
        file=sys.stderr,
    )

    summary = summarize(text, args.mode, args.lang, session_id)
    print(summary)


if __name__ == "__main__":
    main()
