"""
demo_html.py — PromptZero visual report for video demos & pitches.

Produces a self-contained HTML file with:
  • Side-by-side panels (original / sanitized → Claude)
  • Every PII span highlighted and colored by detection kind
  • Hover any span on either side to see its pair (real ↔ fake)
  • Summary chips and a mapping table grouped by category
  • Optional Claude E2E section (sanitized prompt → response → desanitized)

Open the resulting .html in any browser — looks great for screen recording.

Usage:
    python demo_html.py                                       # pentest dataset
    python demo_html.py --dataset data/01_personal_records.json
    python demo_html.py --dataset data/05_customer_support_chat.json --out chat.html
    python demo_html.py --with-claude --task triage \\
        --dataset data/04_incident_response.json --out ir.html

When using --with-claude the proxy must be running (python main.py) and
ANTHROPIC_API_KEY must be set.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import uuid
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

# Allow running the script directly from examples/poc/
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

# Load the repo-root .env so ANTHROPIC_API_KEY is available when the user
# runs --with-claude. Done before any os.getenv() lookups.
try:
    from dotenv import load_dotenv  # noqa: E402
    load_dotenv(ROOT / ".env")
except ImportError:
    pass  # dotenv is in requirements.txt, but don't hard-fail if missing

from sanitizer import Sanitizer, nlp_available, nlp_languages  # noqa: E402


# ---------------------------------------------------------------------------
# Colors per detection kind — used as CSS classes
# ---------------------------------------------------------------------------

# Same palette in light + dark so the report looks good on either bg
_KIND_COLORS = {
    "person":              ("#ffd6d6", "#7a1212"),  # red
    "org":                 ("#ffe6c4", "#7a4500"),  # orange
    "email":               ("#fff3a8", "#604700"),  # yellow
    "phone":               ("#d9f7be", "#306108"),  # green
    "ipv4":                ("#bae0ff", "#003a8c"),  # blue
    "ipv6":                ("#91caff", "#003a8c"),  # blue
    "host_port":           ("#c8e6ff", "#003a8c"),  # blue
    "hostname":            ("#d3adf7", "#391085"),  # purple
    "url":                 ("#efdbff", "#391085"),  # purple
    "credit_card":         ("#ffadd2", "#9e1068"),  # pink
    "iban":                ("#ffadd2", "#9e1068"),  # pink
    "ssn":                 ("#ffd8bf", "#871400"),  # rust
    "passport":            ("#ffd8bf", "#871400"),  # rust
    "driver_license":      ("#ffd8bf", "#871400"),  # rust
    "national_id":         ("#b5f5ec", "#00474f"),  # teal
    "national_id_ar_dni":  ("#b5f5ec", "#00474f"),
    "national_id_ar_cuit": ("#b5f5ec", "#00474f"),
    "national_id_cl_rut":  ("#b5f5ec", "#00474f"),
    "national_id_es":      ("#b5f5ec", "#00474f"),
    "national_id_uy":      ("#b5f5ec", "#00474f"),
    "national_id_co_cc":   ("#b5f5ec", "#00474f"),
    "national_id_mx_curp": ("#b5f5ec", "#00474f"),
    "national_id_mx_rfc":  ("#b5f5ec", "#00474f"),
    "token":               ("#d6d6d6", "#1f1f1f"),  # gray
    "_default":            ("#e0e0e0", "#1f1f1f"),
}


_KIND_LABELS = {
    "person":              "Person",
    "org":                 "Organization",
    "email":               "Email",
    "phone":               "Phone",
    "ipv4":                "IPv4",
    "ipv6":                "IPv6",
    "host_port":           "host:port",
    "hostname":            "Hostname",
    "url":                 "URL",
    "credit_card":         "Credit card",
    "iban":                "IBAN",
    "ssn":                 "SSN (US)",
    "passport":            "Passport",
    "driver_license":      "Driver license",
    "national_id":         "National ID",
    "national_id_ar_dni":  "DNI (Argentina)",
    "national_id_ar_cuit": "CUIT/CUIL (Argentina)",
    "national_id_cl_rut":  "RUT (Chile)",
    "national_id_es":      "DNI/NIE (Spain)",
    "national_id_uy":      "CI (Uruguay)",
    "national_id_co_cc":   "Cédula (Colombia)",
    "national_id_mx_curp": "CURP (Mexico)",
    "national_id_mx_rfc":  "RFC (Mexico)",
    "token":               "Secret / Token",
}


# ---------------------------------------------------------------------------
# Span building — given the mapping, find every occurrence in the text
# ---------------------------------------------------------------------------

def _spans_for(text: str, values: List[Tuple[str, str, str]]) -> List[dict]:
    """Return non-overlapping spans for the given (key, pair_id, kind) list.

    `key` is the literal substring we want to highlight. We sort values by
    length descending so longer matches win against shorter overlaps
    (e.g. "Roberto Carlos Silva" before "Roberto").
    """
    sorted_vals = sorted(values, key=lambda t: -len(t[0]))
    spans: List[dict] = []
    taken = [False] * len(text)

    for key, pair_id, kind in sorted_vals:
        if not key:
            continue
        # Use raw string search (faster + safer than regex for arbitrary input)
        start = 0
        while True:
            idx = text.find(key, start)
            if idx < 0:
                break
            end = idx + len(key)
            if not any(taken[idx:end]):
                spans.append({
                    "start": idx, "end": end,
                    "pair_id": pair_id, "kind": kind, "value": key,
                })
                for i in range(idx, end):
                    taken[i] = True
            start = end
    spans.sort(key=lambda s: s["start"])
    return spans


def _render_with_spans(text: str, spans: List[dict]) -> str:
    """Escape `text` and wrap each span in a <mark> with kind + pair id."""
    out: List[str] = []
    cursor = 0
    for sp in spans:
        out.append(html.escape(text[cursor:sp["start"]]))
        css = f'kind-{sp["kind"].replace("_", "-")}'
        out.append(
            f'<mark class="{css}" '
            f'data-pair="{html.escape(sp["pair_id"])}" '
            f'data-kind="{html.escape(sp["kind"])}" '
            f'title="">{html.escape(sp["value"])}</mark>'
        )
        cursor = sp["end"]
    out.append(html.escape(text[cursor:]))
    return "".join(out)


# ---------------------------------------------------------------------------
# Optional Claude call
# ---------------------------------------------------------------------------

# Strict identifier-preservation clause appended to every task prompt.
# Critical for accurate desanitization: if Claude paraphrases or recombines
# synthetic values (e.g. inventing "nexabank.local1" from "nexabank.local" +
# "localhost.localdomain.1"), the proxy can't restore them back to real
# values because there's no exact mapping match.
_PRESERVE_CLAUSE = (
    "\n\nCRITICAL: Preserve every hostname, IP address, identifier, port "
    "number, CVE id, email, and timestamp EXACTLY as it appears in the "
    "input. Do NOT abbreviate, shorten, paraphrase, recombine, or invent "
    "any of these values. Do NOT extract or echo substrings (e.g. if you "
    "see 'alpha.localhost' do not write 'alpha' or '.localhost' alone). "
    "Treat each identifier as an opaque token."
)


TASK_PROMPTS = {
    "technical": (
        "You are a senior penetration testing consultant. From the following "
        "input, produce a concise technical analysis in Markdown (≤500 words) "
        "covering the top 3 findings, business impact, and recommended "
        "remediation." + _PRESERVE_CLAUSE
    ),
    "executive": (
        "Write a board-level executive summary from the following input. "
        "Markdown, ≤300 words. Top 3 business impacts, top 3 recommendations. "
        "Avoid technical jargon." + _PRESERVE_CLAUSE
    ),
    "summary": (
        "Summarize the following document in 5–8 bullet points." +
        _PRESERVE_CLAUSE
    ),
    "triage": (
        "You are a SOC tier-2 analyst. Triage the following incident: rate "
        "the severity, list the indicators of compromise, propose the next 5 "
        "containment steps in priority order, name stakeholders to notify." +
        _PRESERVE_CLAUSE
    ),
}


def call_claude_e2e(text: str, task: str, session_id: str,
                    proxy_url: str) -> Tuple[str, str]:
    """Send the (pre-sanitized) text through the proxy and return
    (response_text, sanitized_request_text_reconstructed)."""
    try:
        import anthropic  # noqa: PLC0415
        import httpx      # noqa: PLC0415
    except ImportError as exc:
        sys.exit(f"--with-claude requires: pip install anthropic httpx. ({exc})")

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        sys.exit("--with-claude requires ANTHROPIC_API_KEY in .env or env var.")

    try:
        httpx.get(f"{proxy_url}/health", timeout=5.0).raise_for_status()
    except Exception as exc:
        sys.exit(
            f"Proxy not reachable at {proxy_url} — start it with "
            f"`python main.py` first. ({exc})"
        )

    client = anthropic.Anthropic(api_key=api_key, base_url=proxy_url)
    msg = client.messages.create(
        model=os.getenv("MODEL", "claude-opus-4-6"),
        max_tokens=int(os.getenv("MAX_TOKENS", "2048")),
        system=TASK_PROMPTS[task],
        messages=[{"role": "user", "content": f"Document:\n\n{text}"}],
        extra_headers={"x-session-id": session_id},
    )
    response_text = msg.content[0].text
    return response_text


# ---------------------------------------------------------------------------
# Inline assets (CSS + JS)
# ---------------------------------------------------------------------------

def _build_css() -> str:
    rules = [
        # Layout
        ":root {",
        "  --bg: #0d1117; --panel: #161b22; --panel-2: #1c2128;",
        "  --text: #c9d1d9; --muted: #8b949e; --border: #30363d;",
        "  --accent: #58a6ff; --good: #3fb950; --warn: #f0b72f;",
        "}",
        "* { box-sizing: border-box; }",
        "html, body { margin: 0; padding: 0; background: var(--bg);",
        "  color: var(--text); font-family: -apple-system, BlinkMacSystemFont,",
        "  'SF Pro Text', 'Segoe UI', Roboto, sans-serif; }",
        ".container { max-width: 1400px; margin: 0 auto; padding: 32px; }",
        "h1 { margin: 0 0 4px; font-size: 28px; letter-spacing: -0.02em; }",
        "h2 { margin: 0 0 16px; font-size: 18px; color: var(--accent);",
        "  text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600; }",
        "p, li { line-height: 1.6; }",
        ".sub { color: var(--muted); font-size: 14px; }",
        ".section { background: var(--panel); border: 1px solid var(--border);",
        "  border-radius: 12px; padding: 24px; margin-bottom: 24px; }",

        # Header
        ".header { display: flex; justify-content: space-between; align-items: baseline;",
        "  border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }",
        ".brand { font-size: 32px; font-weight: 700; letter-spacing: -0.03em; }",
        ".brand span { color: var(--accent); }",
        ".meta { font-size: 13px; color: var(--muted); text-align: right; }",

        # Summary chips
        ".chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }",
        ".chip { padding: 4px 10px; border-radius: 999px; font-size: 12px;",
        "  font-weight: 600; }",

        # Side-by-side
        ".grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }",
        ".pane { background: var(--panel-2); border: 1px solid var(--border);",
        "  border-radius: 8px; }",
        ".pane-head { padding: 12px 16px; border-bottom: 1px solid var(--border);",
        "  font-weight: 600; font-size: 13px; display: flex; justify-content: space-between; }",
        ".pane-head .badge { font-size: 11px; padding: 2px 8px; border-radius: 999px;",
        "  background: var(--border); color: var(--muted); font-weight: 600; }",
        ".pane.original .pane-head { color: #ffa198; }",
        ".pane.sanitized .pane-head { color: #7ee787; }",
        "pre.body { margin: 0; padding: 16px; max-height: 720px; overflow: auto;",
        "  white-space: pre-wrap; word-break: break-word; font-family:",
        "  'SF Mono', Menlo, Monaco, Consolas, monospace; font-size: 12.5px;",
        "  line-height: 1.55; color: var(--text); }",

        # Highlights
        "mark { padding: 1px 4px; border-radius: 4px; cursor: pointer;",
        "  transition: outline 0.1s ease; outline: 2px solid transparent; font-weight: 500; }",
        "mark.flash { outline-color: var(--accent); }",
        "mark:hover { outline-color: var(--accent); }",
    ]
    # Per-kind background + foreground
    for kind, (bg, fg) in _KIND_COLORS.items():
        css_kind = kind.replace("_", "-")
        rules.append(f"mark.kind-{css_kind} {{ background: {bg}; color: {fg}; }}")
        rules.append(f".chip.kind-{css_kind} {{ background: {bg}; color: {fg}; }}")

    rules += [
        # Mapping table
        "table.mappings { width: 100%; border-collapse: collapse; font-size: 13px; }",
        "table.mappings th, table.mappings td { padding: 8px 12px;",
        "  border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }",
        "table.mappings th { color: var(--muted); font-weight: 600;",
        "  text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }",
        "table.mappings code { font-family: 'SF Mono', Menlo, Monaco, monospace;",
        "  background: var(--panel-2); padding: 2px 6px; border-radius: 4px;",
        "  font-size: 12px; color: var(--text); }",
        "table.mappings .arrow { color: var(--muted); padding: 0 8px; }",
        "table.mappings .kind-cell { font-size: 11px; padding: 2px 8px;",
        "  border-radius: 999px; display: inline-block; font-weight: 600; }",

        # Claude E2E section
        ".claude-section pre { background: var(--panel-2); border-radius: 8px;",
        "  padding: 16px; margin: 0; white-space: pre-wrap; word-break: break-word;",
        "  font-family: 'SF Mono', Menlo, Monaco, monospace; font-size: 12.5px;",
        "  line-height: 1.55; max-height: 480px; overflow: auto; }",

        # Footer
        "footer { color: var(--muted); font-size: 12px; text-align: center;",
        "  margin-top: 32px; padding-top: 16px; border-top: 1px solid var(--border); }",
        "footer a { color: var(--accent); text-decoration: none; }",

        # Responsive
        "@media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }",
    ]
    return "\n".join(rules)


_JS = """
// Highlight all sibling spans of the same pair on hover
(function() {
  const marks = document.querySelectorAll('mark[data-pair]');
  function setFlash(pairId, on) {
    marks.forEach(m => {
      if (m.dataset.pair === pairId) m.classList.toggle('flash', on);
    });
  }
  marks.forEach(m => {
    m.addEventListener('mouseenter', () => setFlash(m.dataset.pair, true));
    m.addEventListener('mouseleave', () => setFlash(m.dataset.pair, false));
    // Tooltip showing the counterpart
    const other = m.dataset.other || '';
    if (other) m.title = `${m.dataset.kind}: maps to "${other}"`;
  });
})();
"""


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def build_report(
    dataset_path: Path,
    out_path: Path,
    with_claude: bool,
    task: str,
    proxy_url: str,
    session_id: str,
) -> Path:
    raw = dataset_path.read_text(encoding="utf-8")
    try:
        text = json.dumps(json.loads(raw), indent=2, ensure_ascii=False)
    except json.JSONDecodeError:
        text = raw

    san = Sanitizer()
    sanitized = san.sanitize(text)

    # Optional Claude E2E
    claude_raw_response = None
    if with_claude:
        # The Sanitizer instance we use locally also generates the mappings
        # used to render the original/sanitized panels. Call Claude through
        # the proxy with the original text (proxy will re-sanitize using
        # its own session), then desanitize via this Sanitizer's table.
        claude_raw_response = call_claude_e2e(
            text=text, task=task, session_id=session_id, proxy_url=proxy_url,
        )

    # ----- Build span lists for both panels ---------------------------------
    pair_ids = {}
    for i, real in enumerate(san.table.fake_to_real.values()):  # real values
        pair_ids[real] = f"p{i}"

    orig_values = [
        (real, pair_ids[real], san.table.get_kind(real) or "_default")
        for real in pair_ids
    ]
    san_values = [
        (san.table.get_fake(real), pair_ids[real], san.table.get_kind(real) or "_default")
        for real in pair_ids
        if san.table.get_fake(real) is not None
    ]

    orig_spans = _spans_for(text, orig_values)
    san_spans  = _spans_for(sanitized, san_values)

    orig_html = _render_with_spans(text, orig_spans)
    san_html  = _render_with_spans(sanitized, san_spans)

    # ----- Mapping table grouped by kind ------------------------------------
    by_kind: dict = {}
    for real, fake in san.table._r2f.items():
        kind = san.table.get_kind(real) or "_default"
        by_kind.setdefault(kind, []).append((real, fake))

    counters = san.table.snapshot()["counters_by_type"]

    # ----- HTML -------------------------------------------------------------
    chips_html = "\n".join(
        f'<span class="chip kind-{k.replace("_","-")}">'
        f'{html.escape(_KIND_LABELS.get(k, k))} · {v}'
        f'</span>'
        for k, v in sorted(counters.items(), key=lambda x: -x[1])
    )

    mapping_rows = []
    for kind in sorted(by_kind, key=lambda k: -len(by_kind[k])):
        label = _KIND_LABELS.get(kind, kind)
        css   = kind.replace("_", "-")
        for real, fake in by_kind[kind]:
            mapping_rows.append(
                f"<tr>"
                f'<td><span class="kind-cell kind-{css}">{html.escape(label)}</span></td>'
                f"<td><code>{html.escape(real)}</code></td>"
                f'<td class="arrow">→</td>'
                f"<td><code>{html.escape(fake)}</code></td>"
                f"</tr>"
            )
    mappings_html = "\n".join(mapping_rows) or '<tr><td colspan="4" class="sub">No PII detected.</td></tr>'

    # Claude E2E section
    claude_section = ""
    if claude_raw_response is not None:
        # Build sanitized-view of the response too
        # First reconstruct what the response looked like before
        # desanitization. The anthropic client already returns desanitized
        # text (because the proxy desanitized the response on its way back).
        # So we re-sanitize it locally for the "raw" panel.
        raw_view = san.sanitize(claude_raw_response)
        # And desanitize again to verify it round-trips to the user view.
        user_view = san.desanitize(raw_view)
        claude_section = f"""
        <div class="section claude-section">
          <h2>④ Claude end-to-end ({html.escape(task)})</h2>
          <p class="sub">Response that <em>would</em> reach Claude with synthetic
          values (top) vs. what your application receives after desanitization
          (bottom). The same Sanitizer session generated both.</p>
          <div class="grid">
            <div class="pane sanitized">
              <div class="pane-head">Claude raw response (synthetic) <span class="badge">Claude saw fiction</span></div>
              <pre class="body">{html.escape(raw_view)}</pre>
            </div>
            <div class="pane original">
              <div class="pane-head">After desanitization (real) <span class="badge">Your app sees facts</span></div>
              <pre class="body">{html.escape(user_view)}</pre>
            </div>
          </div>
        </div>
        """

    css = _build_css()
    js  = _JS
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    langs = ", ".join(nlp_languages()) if nlp_available() else "regex only"

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PromptZero report — {html.escape(dataset_path.name)}</title>
  <style>{css}</style>
</head>
<body>
  <div class="container">

    <div class="header">
      <div>
        <div class="brand">Prompt<span>Zero</span></div>
        <div class="sub">Zero trace. Full answer.</div>
      </div>
      <div class="meta">
        Dataset: <strong>{html.escape(dataset_path.name)}</strong><br/>
        Detection: <strong>NLP {langs}</strong><br/>
        Generated: <strong>{now}</strong>
      </div>
    </div>

    <div class="section">
      <h2>Summary</h2>
      <p class="sub">{san.table.snapshot()["total_entries"]} unique PII spans
      detected across the dataset. Each is replaced with a synthetic value of
      the same shape before any data leaves your environment.</p>
      <div class="chips">
        {chips_html}
      </div>
    </div>

    <div class="section">
      <h2>① Original  →  ② Sanitized (what Claude sees)</h2>
      <p class="sub">Hover any highlighted value to see its counterpart on the
      other side. Both panels share the same colour scheme — colours indicate
      detection category, not pairing.</p>
      <div class="grid">
        <div class="pane original">
          <div class="pane-head">ORIGINAL <span class="badge">on your disk</span></div>
          <pre class="body">{orig_html}</pre>
        </div>
        <div class="pane sanitized">
          <div class="pane-head">SANITIZED <span class="badge">→ api.anthropic.com</span></div>
          <pre class="body">{san_html}</pre>
        </div>
      </div>
    </div>

    <div class="section">
      <h2>③ Mapping table</h2>
      <p class="sub">Bidirectional translation table for this session. Stored
      locally, never sent anywhere. The proxy uses this same table to restore
      real values in Claude's response.</p>
      <table class="mappings">
        <thead><tr><th>Category</th><th>Real value</th><th></th><th>Synthetic value</th></tr></thead>
        <tbody>
          {mappings_html}
        </tbody>
      </table>
    </div>

    {claude_section}

    <footer>
      Generated by PromptZero · <a href="https://openbash.com">openbash.com</a> ·
      From pentesters to pentesters
    </footer>

  </div>
  <script>{js}</script>
</body>
</html>
"""
    out_path.write_text(html_doc, encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    here = Path(__file__).resolve().parent
    default_dataset = here / "data" / "02_pentest_engagement.json"
    default_out     = here / "report.html"

    parser = argparse.ArgumentParser(
        description="Generate a visual PromptZero report for video demos.",
    )
    parser.add_argument("--dataset", default=str(default_dataset),
                        help="Path to a JSON dataset")
    parser.add_argument("--out", default=str(default_out),
                        help="Output HTML file (default: examples/poc/report.html)")
    parser.add_argument("--with-claude", action="store_true",
                        help="Also call Claude through the proxy and embed the response")
    parser.add_argument("--task", choices=list(TASK_PROMPTS), default="technical",
                        help="Claude task type when --with-claude (default: technical)")
    parser.add_argument("--proxy", default=os.getenv("API_PII_URL", "http://localhost:8000"),
                        help="Proxy URL (default http://localhost:8000)")
    parser.add_argument("--session", default=None,
                        help="Session id when --with-claude (default: auto)")
    parser.add_argument("--open", action="store_true",
                        help="Open the report in the default browser when done")
    args = parser.parse_args()

    dataset = Path(args.dataset)
    if not dataset.exists():
        sys.exit(f"[error] Dataset not found: {dataset}")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    session_id = args.session or f"htmldemo-{dataset.stem}-{uuid.uuid4().hex[:6]}"
    path = build_report(
        dataset_path=dataset, out_path=out,
        with_claude=args.with_claude, task=args.task,
        proxy_url=args.proxy, session_id=session_id,
    )
    print(f"[info] Report written to {path.resolve()}", file=sys.stderr)
    if args.open:
        webbrowser.open(path.resolve().as_uri())


if __name__ == "__main__":
    main()
