"""
demo_claude.py — End-to-end PromptZero PoC against the real Claude API.

Sends a fictitious dataset to Claude *through* the local PromptZero proxy
and prints every stage of the journey:

    ① ORIGINAL  (loaded from disk)
    ② SANITIZED (what reaches api.anthropic.com — pulled from the proxy
                 mapping endpoint so we can show it side-by-side)
    ③ RAW CLAUDE RESPONSE (still contains the synthetic values)
    ④ DESANITIZED RESPONSE (what your app actually sees — real values restored)

This is the full pitch in a single command. Use it on stage.

Prereq:
    # 1) Proxy running on http://localhost:8000
    cd ../../ && python main.py

    # 2) Dependencies
    pip install -r requirements.txt

    # 3) Real API key in .env (or ANTHROPIC_API_KEY env var)
    cp ../../.env.example ../../.env

Usage:
    python demo_claude.py                                          # pentest, technical mode
    python demo_claude.py --dataset data/01_personal_records.json --task summary
    python demo_claude.py --dataset data/04_incident_response.json --task executive
    python demo_claude.py --no-color --out demo.txt
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

import anthropic
import httpx
from dotenv import load_dotenv

load_dotenv()


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROXY_URL  = os.getenv("API_PII_URL", "http://localhost:8000")
API_KEY    = os.getenv("ANTHROPIC_API_KEY", "")
MODEL      = os.getenv("MODEL", "claude-opus-4-6")
MAX_TOKENS = int(os.getenv("MAX_TOKENS", "2048"))


TASK_PROMPTS = {
    "technical": (
        "You are a senior penetration testing consultant. Given the following structured "
        "input, produce a CONCISE technical summary in Markdown (≤500 words) covering: "
        "the top 3 findings, their business impact, and a recommended remediation plan. "
        "Preserve hostnames, IPs, and identifiers exactly as they appear in the input."
    ),
    "executive": (
        "You are writing a board-level executive summary. From the following input, "
        "produce a concise Markdown brief (≤300 words) describing the overall risk, "
        "the top 3 business impacts, and the top 3 recommendations. "
        "Avoid technical jargon, IP addresses, and CVE numbers."
    ),
    "summary": (
        "Summarize the following document in 5–8 bullet points. Preserve all names, "
        "organizations, identifiers, and figures exactly as they appear in the input."
    ),
    "triage": (
        "You are a SOC tier-2 analyst. Triage the following incident report: rate the "
        "severity, list the indicators of compromise, propose the next 5 containment "
        "steps in priority order, and identify which stakeholders to notify."
    ),
}


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

BAR = "═" * 78
SUB = "─" * 78

GREEN = "\033[32m"
RED   = "\033[31m"
CYAN  = "\033[36m"
YEL   = "\033[33m"
DIM   = "\033[2m"
BOLD  = "\033[1m"
END   = "\033[0m"


def color(text: str, c: str, on: bool) -> str:
    return f"{c}{text}{END}" if on else text


def banner(title: str, c: str, on: bool, out) -> None:
    out.write(color(BAR, c, on) + "\n")
    out.write(color(f"  {title}", c + BOLD, on) + "\n")
    out.write(color(BAR, c, on) + "\n")


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated {len(text) - limit:,} chars]"


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def load_dataset(path: Path) -> str:
    raw = path.read_text(encoding="utf-8")
    try:
        return json.dumps(json.loads(raw), indent=2, ensure_ascii=False)
    except json.JSONDecodeError:
        return raw


# ---------------------------------------------------------------------------
# Proxy interactions
# ---------------------------------------------------------------------------

def check_proxy_health() -> dict:
    try:
        resp = httpx.get(f"{PROXY_URL}/health", timeout=5.0)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        sys.exit(
            f"[error] PromptZero proxy not reachable at {PROXY_URL}\n"
            f"        Start it with: cd ../../ && python main.py\n"
            f"        Underlying error: {exc}"
        )


def fetch_mapping(session_id: str) -> dict:
    try:
        resp = httpx.get(f"{PROXY_URL}/sessions/{session_id}/mappings", timeout=5.0)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        print(f"[warn] Could not fetch mapping table: {exc}", file=sys.stderr)
        return {}


def call_claude(text: str, system: str, session_id: str) -> str:
    if not API_KEY:
        sys.exit(
            "[error] ANTHROPIC_API_KEY is not set. Add it to ../../.env or export it.\n"
            "        Tip: the proxy will forward your real key to api.anthropic.com — "
            "the dataset values do NOT leave your machine."
        )

    client = anthropic.Anthropic(api_key=API_KEY, base_url=PROXY_URL)
    msg = client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=system,
        messages=[{
            "role": "user",
            "content": f"Document to analyze:\n\n{text}",
        }],
        extra_headers={"x-session-id": session_id},
    )
    return msg.content[0].text


def reconstruct_sanitized(text: str, mapping: dict) -> str:
    """Simulate what Claude saw by applying mapping real → fake locally."""
    out = text
    for real, fake in sorted(
        mapping.get("mappings", {}).items(),
        key=lambda x: len(x[0]),
        reverse=True,
    ):
        out = out.replace(real, fake)
    return out


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def run(args, out) -> None:
    color_on = (out is sys.stdout) and sys.stdout.isatty() and not args.no_color

    # 1. Health check
    health = check_proxy_health()
    banner(
        f"PromptZero — end-to-end demo  |  proxy {PROXY_URL}  |  "
        f"NLP: {'on' if health.get('nlp_enabled') else 'off'}",
        GREEN, color_on, out,
    )
    out.write("\n")

    # 2. Load dataset
    path = Path(args.dataset)
    if not path.exists():
        sys.exit(f"[error] Dataset not found: {path}")

    text = load_dataset(path)
    out.write(color(f"  dataset       {path.name} ({len(text):,} chars)\n", DIM, color_on))
    out.write(color(f"  task          {args.task}\n", DIM, color_on))
    out.write(color(f"  model         {MODEL}\n", DIM, color_on))
    session_id = args.session or f"poc-{path.stem}-{uuid.uuid4().hex[:6]}"
    out.write(color(f"  session_id    {session_id}\n\n", DIM, color_on))

    # 3. Original
    banner("① ORIGINAL  —  fictitious sensitive data on your disk", RED, color_on, out)
    out.write(truncate(text, args.max_preview) + "\n\n")

    # 4. Call Claude through the proxy
    system = TASK_PROMPTS[args.task]
    out.write(color("  Sending through PromptZero…\n", DIM, color_on))
    response_text = call_claude(text, system, session_id)

    # 5. Pull the mapping table from the proxy
    mapping = fetch_mapping(session_id)
    sanitized_preview = reconstruct_sanitized(text, mapping)

    # 6. Sanitized
    out.write("\n")
    banner("② SANITIZED  —  exactly what api.anthropic.com received", GREEN, color_on, out)
    out.write(truncate(sanitized_preview, args.max_preview) + "\n\n")

    # 7. Raw Claude response (still contains fake values)
    raw_response_with_fakes = reconstruct_sanitized(response_text, mapping)
    banner("③ RAW CLAUDE RESPONSE  —  before desanitization", YEL, color_on, out)
    out.write(truncate(raw_response_with_fakes, args.max_preview) + "\n\n")

    # 8. Desanitized (what the app sees)
    banner("④ DESANITIZED  —  what your application actually receives", CYAN, color_on, out)
    out.write(response_text + "\n\n")

    # 9. Mapping summary
    mappings = mapping.get("mappings", {})
    counters = mapping.get("counters_by_type", {})
    banner(f"MAPPING TABLE  —  {len(mappings)} entries", CYAN, color_on, out)
    for kind, n in sorted(counters.items(), key=lambda x: -x[1]):
        out.write(f"  • {kind:<16} {n}\n")
    out.write("\n")
    for real, fake in list(mappings.items())[:25]:
        real_show = real.replace("\n", "\\n")
        if len(real_show) > 40:
            real_show = real_show[:37] + "..."
        out.write(f"  {real_show:<42} →  {fake}\n")
    if len(mappings) > 25:
        out.write(color(f"  ... and {len(mappings) - 25} more entries\n", DIM, color_on))


def main() -> None:
    here = Path(__file__).resolve().parent
    default_dataset = here / "data" / "02_pentest_engagement.json"

    parser = argparse.ArgumentParser(
        description="PromptZero end-to-end PoC against the real Claude API via the local proxy.",
    )
    parser.add_argument(
        "--dataset", default=str(default_dataset),
        help="Path to a JSON dataset",
    )
    parser.add_argument(
        "--task", choices=list(TASK_PROMPTS), default="technical",
        help="Claude task type (default: technical)",
    )
    parser.add_argument(
        "--session", default=None,
        help="Session id (default: auto-generated)",
    )
    parser.add_argument(
        "--max-preview", type=int, default=2500,
        help="Max chars to show per section (default 2500)",
    )
    parser.add_argument(
        "--out", default=None,
        help="Write full transcript to a file instead of stdout (no colors)",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colors",
    )
    args = parser.parse_args()

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            args.no_color = True
            run(args, f)
        print(f"[info] Transcript written to {args.out}", file=sys.stderr)
    else:
        run(args, sys.stdout)


if __name__ == "__main__":
    main()
