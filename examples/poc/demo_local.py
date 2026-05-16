"""
demo_local.py — Standalone PromptZero demo (no Claude API call).

Runs the Sanitizer directly on a fictitious dataset and shows the full
journey of sensitive data:

    ORIGINAL  →  SANITIZED (what Claude would see)  →  DESANITIZED (what you get back)

Also prints the bidirectional mapping table so you can audit every replacement.

Use this script in pitches, demos, security reviews, and CI checks — it
proves the proxy works without ever leaving your machine.

Usage:
    python demo_local.py                                     # uses 02_pentest_engagement.json
    python demo_local.py data/01_personal_records.json
    python demo_local.py data/03_injection_catalog.json --max-preview 4000
    python demo_local.py data/04_incident_response.json --json   # JSON output

Exit code 0 always — this is a demo, not a test runner.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running directly from examples/poc/ without installing the package
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from sanitizer import Sanitizer, nlp_available  # noqa: E402


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

BAR  = "═" * 78
SUB  = "─" * 78
ARROW = "    ↓"

GREEN = "\033[32m"
RED   = "\033[31m"
CYAN  = "\033[36m"
DIM   = "\033[2m"
BOLD  = "\033[1m"
END   = "\033[0m"


def color(text: str, c: str, enabled: bool) -> str:
    return f"{c}{text}{END}" if enabled else text


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated {len(text) - limit:,} chars]"


def banner(title: str, c: str, enabled: bool) -> None:
    print(color(BAR, c, enabled))
    print(color(f"  {title}", c + BOLD, enabled))
    print(color(BAR, c, enabled))


def render_mapping(sanitizer: Sanitizer, color_on: bool) -> None:
    snapshot = sanitizer.table.snapshot()
    counters = snapshot["counters_by_type"]
    mappings = snapshot["mappings"]

    banner(f"MAPPING TABLE  —  {len(mappings)} entries", CYAN, color_on)

    if not mappings:
        print(color("  (no sensitive values detected)", DIM, color_on))
        return

    print(color("  Counters by kind:", BOLD, color_on))
    for kind, n in sorted(counters.items(), key=lambda x: -x[1]):
        print(f"    • {kind:<16} {n}")
    print()

    print(color(f"  {'REAL VALUE':<42} →  FAKE VALUE", BOLD, color_on))
    print(color(f"  {SUB}", DIM, color_on))
    for real, fake in mappings.items():
        real_show = truncate(real, 40).replace("\n", "\\n")
        fake_show = fake.replace("\n", "\\n")
        print(f"  {real_show:<42} →  {fake_show}")


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def run(path: Path, max_preview: int, color_on: bool, json_out: bool) -> None:
    raw = path.read_text(encoding="utf-8")

    # Pretty-print JSON inputs so the diff is human-readable
    try:
        parsed = json.loads(raw)
        text   = json.dumps(parsed, indent=2, ensure_ascii=False)
    except json.JSONDecodeError:
        text = raw

    sanitizer = Sanitizer()
    sanitized = sanitizer.sanitize(text)

    # Simulate Claude's reply by echoing the sanitized text back —
    # in a real call this would be Claude's response containing fake values.
    simulated_claude_response = (
        "Based on the input you sent me, here is my analysis:\n\n"
        + sanitized
    )
    desanitized = sanitizer.desanitize(simulated_claude_response)

    if json_out:
        out = {
            "input_file": str(path),
            "nlp_enabled": nlp_available(),
            "original_chars": len(text),
            "sanitized_chars": len(sanitized),
            "mapping": sanitizer.table.snapshot(),
            "sanitized_preview": sanitized[:max_preview],
            "desanitized_preview": desanitized[:max_preview],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return

    # Header
    print()
    banner(
        f"PromptZero — local demo  |  dataset: {path.name}  |  "
        f"NLP: {'on' if nlp_available() else 'off'}",
        GREEN, color_on,
    )
    print()

    # 1) Original
    banner("① ORIGINAL  —  contains real (fictional) sensitive data", RED, color_on)
    print(truncate(text, max_preview))
    print()
    print(color(ARROW, DIM, color_on))
    print(color("  PromptZero detects → replaces with synthetic values", DIM, color_on))
    print(color(ARROW, DIM, color_on))
    print()

    # 2) Sanitized
    banner("② SANITIZED  —  exactly what Claude receives", GREEN, color_on)
    print(truncate(sanitized, max_preview))
    print()
    print(color(ARROW, DIM, color_on))
    print(color("  Claude answers using these synthetic values", DIM, color_on))
    print(color(ARROW, DIM, color_on))
    print()

    # 3) Desanitized
    banner("③ DESANITIZED  —  what your app sees in the response", CYAN, color_on)
    print(truncate(desanitized, max_preview))
    print()

    # Mapping table
    render_mapping(sanitizer, color_on)

    # Footer
    print()
    print(color(BAR, GREEN, color_on))
    print(color(
        f"  Original: {len(text):,} chars   Sanitized: {len(sanitized):,} chars   "
        f"Mappings: {len(sanitizer.table.snapshot()['mappings'])}",
        BOLD, color_on,
    ))
    print(color(BAR, GREEN, color_on))
    print()


def main() -> None:
    here = Path(__file__).resolve().parent
    default_dataset = here / "data" / "02_pentest_engagement.json"

    parser = argparse.ArgumentParser(
        description="PromptZero local demo — runs the sanitizer on a fictitious dataset.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
datasets shipped with the PoC:
  data/01_personal_records.json     PII-heavy HR/CRM export
  data/02_pentest_engagement.json   full pentest engagement (default)
  data/03_injection_catalog.json    injection payload catalog
  data/04_incident_response.json    incident response report
  data/05_customer_support_chat.json customer support chat transcripts
        """,
    )
    parser.add_argument(
        "dataset", nargs="?", default=str(default_dataset),
        help="Path to a JSON dataset (default: data/02_pentest_engagement.json)",
    )
    parser.add_argument(
        "--max-preview", type=int, default=2500,
        help="Max chars to show per section (default 2500)",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colors",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit a JSON report instead of the human-readable view",
    )
    args = parser.parse_args()

    path = Path(args.dataset)
    if not path.is_absolute():
        # Resolve relative to script location so users can run from anywhere
        candidate = here / args.dataset
        if candidate.exists():
            path = candidate

    if not path.exists():
        sys.exit(f"[error] Dataset not found: {path}")

    color_on = sys.stdout.isatty() and not args.no_color
    run(path, args.max_preview, color_on, args.json)


if __name__ == "__main__":
    main()
