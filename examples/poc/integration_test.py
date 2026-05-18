#!/usr/bin/env python3
"""
integration_test.py — drive real Claude calls through the local PromptZero
proxy and verify the four invariants that any real-world deployment cares
about:

  L (leak)        no real PII appears in the sanitized upstream payload
  R (round-trip)  every fake the model emitted gets desanitized in the reply
  A (awareness)   the model does not call out the synthetic placeholders
                  ("test data", "placeholder", "fictional", …) — that means
                  our fakes are obvious enough that the model changes its
                  behaviour
  N (NER recall)  every real value we know we put in the prompt shows up in
                  the session's mapping table — anything that doesn't is a
                  silent leak that wasn't caught by detection

Usage:
  # 1. Start the proxy with DEBUG_AUDIT=1 (so /sessions/<id>/audit works)
  # 2. Run:
  python3 examples/poc/integration_test.py \\
      --proxy http://127.0.0.1:8002 \\
      --model claude-haiku-4-5

Exit code is the number of failed scenarios. The runner is meant to be
re-run after every sanitizer change to spot regressions.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import httpx


# --- ANSI ---------------------------------------------------------------
RESET = "\033[0m"
DIM   = "\033[2m"
BOLD  = "\033[1m"
GREEN = "\033[32m"
RED   = "\033[31m"
YEL   = "\033[33m"
CYAN  = "\033[36m"


# --- Scenarios ----------------------------------------------------------
@dataclass
class Scenario:
    name: str
    user_prompt: str
    # Real values that MUST be detected and mapped. The runner asserts
    # each appears as a `real` value in the session's mapping table after
    # the call (otherwise the value reached Anthropic in clear).
    expected_real: list[str]
    # Optional list of regex patterns that, if matched in the model's
    # reply, count as "awareness" — the model has noticed something is
    # off about the data and is commenting on it. These break the
    # transparency illusion.
    awareness_patterns: list[str] = field(default_factory=lambda: [
        # The model commenting on the *input* being placeholder/synthetic.
        # Words like "obfuscate", "redact", "anonymize" are normal
        # security vocabulary that appears in recommendations — exclude
        # them and rely on phrases that imply meta-awareness.
        r"\bplaceholder",
        r"\bsynthetic\b",
        r"\bfictional\b",
        r"\bfictitious\b",
        r"\bnot real\b",
        r"\bdummy data\b",
        r"\bsample data\b",
        r"\b(?:these|those|the)\s+(?:names|values|domains)\s+(?:look|are|seem)",
        r"appear[s]? to be (test|sample|dummy|sanitiz)",
    ])
    system: Optional[str] = None
    max_tokens: int = 600


@dataclass
class MultiTurnScenario:
    """A scenario that drives several /v1/messages calls in the same
    session, then runs the same four checks against the final reply +
    accumulated mappings + accumulated audit log."""
    name: str
    turns: list[dict]               # list of {"user": "..."} per turn
    expected_real: list[str]
    awareness_patterns: list[str] = field(default_factory=lambda: [
        r"\bplaceholder",
        r"\bsynthetic\b",
        r"\bfictional\b",
        r"\bfictitious\b",
        r"\bnot real\b",
        r"\bdummy data\b",
        r"\bsample data\b",
        r"appear[s]? to be (test|sample|dummy|sanitiz)",
    ])
    max_tokens: int = 600


MULTITURN: list[MultiTurnScenario] = [
    MultiTurnScenario(
        name="conversation-history",
        # Multi-turn: by turn 3 the conversation history contains the
        # previous turns. Sanitizer must rewrite the assistant's prior
        # replies (which contain real values after desanitization) when
        # we send them back upstream. If history sanitization is broken,
        # the leak will surface on turn 2 or 3.
        turns=[
            {"user": (
                "I'm auditing nexabank.com. The first user I want to focus on "
                "is Joaquín Mosqueira (joaco@nexabank.com), CISO. "
                "Source IP from the last login: 200.32.45.10. "
                "What initial checks would you suggest?"
            )},
            {"user": (
                "Good. Now also include Sofía Mansilla (sofia@nexabank.com), "
                "DBA. Her last login came from 185.220.101.34. "
                "Update the checklist to cover both users."
            )},
            {"user": (
                "Summarise everything we have so far in three bullets — "
                "include both names and both IPs."
            )},
        ],
        expected_real=[
            "nexabank.com",
            "Joaquín Mosqueira",
            "joaco@nexabank.com",
            "200.32.45.10",
            "Sofía Mansilla",
            "sofia@nexabank.com",
            "185.220.101.34",
        ],
    ),
]


SCENARIOS: list[Scenario] = [
    Scenario(
        name="pentest-report",
        user_prompt=(
            "I just ran an external recon against copetel.com.ar for client "
            "Banco Galicia (auditor: Mariano Lombardi, mariano@copetel.com.ar). "
            "Findings: port 22 open on 200.32.45.10, port 443 with expired cert "
            "on monitoring.copetel.com.ar (190.210.55.7), and a leaked admin "
            "credential header in HTTP responses: X-Admin-Token: "
            "AbCdEf1234567890ZZyyXXwwVVuu7788. "
            "Draft a one-paragraph executive summary for the client. "
            "Preserve identifiers exactly as in the input, do not abbreviate "
            "or recombine."
        ),
        expected_real=[
            "copetel.com.ar",
            "Mariano Lombardi",
            "mariano@copetel.com.ar",
            "Banco Galicia",
            "200.32.45.10",
            "monitoring.copetel.com.ar",
            "190.210.55.7",
            "AbCdEf1234567890ZZyyXXwwVVuu7788",
        ],
    ),
    Scenario(
        name="log-triage",
        user_prompt=(
            "Triage these auth-server log lines and tell me which user(s) "
            "look compromised:\n"
            "2026-05-17T03:14:22Z user=jbravo@nexabank.com ip=45.77.12.91 ok\n"
            "2026-05-17T03:14:23Z user=jbravo@nexabank.com ip=185.220.101.34 ok\n"
            "2026-05-17T03:14:24Z user=alopez@nexabank.com ip=200.32.45.10 ok\n"
            "2026-05-17T03:14:25Z user=jbravo@nexabank.com ip=46.166.139.111 ok\n"
            "Reply with: usernames, source IPs, and a verdict."
        ),
        expected_real=[
            "jbravo@nexabank.com",
            "alopez@nexabank.com",
            "nexabank.com",
            "45.77.12.91",
            "185.220.101.34",
            "200.32.45.10",
            "46.166.139.111",
        ],
    ),
    Scenario(
        name="transformation-resistance",
        # Stress the model's tendency to abbreviate / restructure names.
        # The reply MUST contain every name verbatim — if it abbreviates
        # to initials or summarizes, R round-trip will fail.
        user_prompt=(
            "We have four engineers on call this week:\n"
            "- Mariano Lombardi (lead)\n"
            "- Sofía Mansilla (db)\n"
            "- Antonella Bertoldi (frontend)\n"
            "- Joaquín Mosqueira (security)\n"
            "Write a one-line greeting for each, addressed by their full name. "
            "Preserve identifiers exactly as in the input, do not abbreviate "
            "or recombine."
        ),
        expected_real=[
            "Mariano Lombardi",
            "Sofía Mansilla",
            "Antonella Bertoldi",
            "Joaquín Mosqueira",
        ],
    ),
    Scenario(
        name="json-payload",
        # Sanitization must walk arbitrary JSON, not just text. The
        # model is asked to echo back the structure.
        user_prompt=(
            'Parse this incident JSON and tell me which fields are sensitive:\n'
            '{"reporter": "Mariano Lombardi", '
            '"email": "mariano@nexabank.com", '
            '"affected_host": "internal-vpn.nexabank.com", '
            '"source_ip": "200.32.45.10", '
            '"creds_leaked": {"api_key": "ak_live_9F3KdYz28HqWvNbXm7TpRsQ4LjUe2GcA"}}\n'
            "Just list the fields and why."
        ),
        expected_real=[
            "Mariano Lombardi",
            "mariano@nexabank.com",
            "nexabank.com",
            "internal-vpn.nexabank.com",
            "200.32.45.10",
            "ak_live_9F3KdYz28HqWvNbXm7TpRsQ4LjUe2GcA",
        ],
    ),
    Scenario(
        name="code-review",
        user_prompt=(
            "Review this snippet from Andrea Pellegrini's PR at acme-bank.com. "
            "The function connects to db.internal.acme-bank.com with hardcoded "
            "credentials and forwards every row to https://siem.acme-bank.com:8443. "
            "Tell me the top 3 issues.\n\n"
            "```python\n"
            "def export_users():\n"
            "    conn = psycopg2.connect("
            "host='db.internal.acme-bank.com', "
            "user='admin', "
            "password='S3cur3P@ss!2026', "
            "dbname='users')\n"
            "    for row in conn.cursor().execute('SELECT * FROM users'):\n"
            "        requests.post('https://siem.acme-bank.com:8443/ingest', "
            "json=row)\n"
            "```"
        ),
        expected_real=[
            "Andrea Pellegrini",
            "acme-bank.com",
            "db.internal.acme-bank.com",
            "siem.acme-bank.com",
            "S3cur3P@ss!2026",
        ],
    ),
]


# --- Helpers ------------------------------------------------------------
def call_proxy(
    proxy: str,
    model: str,
    scenario: Scenario,
    session_id: str,
    timeout: float = 90.0,
) -> tuple[int, dict]:
    body: dict = {
        "model": model,
        "max_tokens": scenario.max_tokens,
        "messages": [{"role": "user", "content": scenario.user_prompt}],
    }
    if scenario.system:
        body["system"] = scenario.system

    r = httpx.post(
        f"{proxy}/v1/messages",
        json=body,
        headers={"x-session-id": session_id},
        timeout=timeout,
    )
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"error": "non-json", "text": r.text[:500]}


def extract_reply_text(resp: dict) -> str:
    out: list[str] = []
    for block in resp.get("content", []) or []:
        if isinstance(block, dict) and block.get("type") == "text":
            out.append(block.get("text", ""))
    return "\n".join(out)


def fetch_audit(proxy: str, session_id: str) -> dict:
    r = httpx.get(f"{proxy}/sessions/{session_id}/audit", timeout=10.0)
    return r.json()


def fetch_mappings(proxy: str, session_id: str) -> dict:
    r = httpx.get(f"{proxy}/sessions/{session_id}/mappings", timeout=10.0)
    return r.json()


# --- Checks -------------------------------------------------------------
@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


def check_leak(scenario: Scenario, audit: dict) -> CheckResult:
    """Real values must NOT appear in the sanitized upstream payload."""
    entries = audit.get("entries", []) or []
    if not entries:
        return CheckResult("L leak", False, "no audit entries recorded")
    sanitized = json.dumps(entries[-1].get("sanitized_request", {}), ensure_ascii=False)
    leaked = [v for v in scenario.expected_real if v in sanitized]
    if leaked:
        sample = ", ".join(repr(v) for v in leaked[:5])
        return CheckResult("L leak", False, f"{len(leaked)} real value(s) reached upstream: {sample}")
    return CheckResult("L leak", True, f"sanitized payload clean ({len(sanitized)} chars)")


def check_round_trip(reply: str, mappings: dict) -> CheckResult:
    """No fake value should remain in the desanitized reply."""
    fakes = list((mappings.get("mappings") or {}).values())
    residue = [f for f in fakes if f and f in reply]
    if residue:
        sample = ", ".join(repr(v) for v in residue[:5])
        return CheckResult("R round-trip", False, f"{len(residue)} fake(s) left in reply: {sample}")
    return CheckResult("R round-trip", True, f"all {len(fakes)} fakes desanitized cleanly")


def check_awareness(scenario: Scenario, reply: str) -> CheckResult:
    """Model should not call out the synthetic placeholders."""
    hits: list[str] = []
    low = reply.lower()
    for pat in scenario.awareness_patterns:
        m = re.search(pat, low)
        if m:
            hits.append(m.group(0))
    if hits:
        return CheckResult("A awareness", False, f"model commented on synthetic data: {hits[:3]}")
    return CheckResult("A awareness", True, "model did not flag synthetic data")


def check_ner_recall(scenario: Scenario, mappings: dict) -> CheckResult:
    """Every expected real value should be present in the mapping table.
    Values not detected by the sanitizer reached Anthropic unredacted —
    silent leak."""
    forward = mappings.get("mappings") or {}
    detected: set[str] = set(forward.keys())
    missed: list[str] = []
    for v in scenario.expected_real:
        # A value is "covered" if it's a key in mappings, OR if it's
        # entirely contained inside one of the detected real values (e.g.
        # "copetel.com.ar" gets covered by detecting
        # "monitoring.copetel.com.ar").
        if v in detected:
            continue
        if any(v in d for d in detected):
            continue
        missed.append(v)
    if missed:
        return CheckResult("N ner-recall", False, f"undetected: {missed}")
    return CheckResult("N ner-recall", True, f"all {len(scenario.expected_real)} expected values detected")


# --- Runner -------------------------------------------------------------
def run_scenario(
    proxy: str, model: str, scenario: Scenario, verbose: bool = False
) -> tuple[Scenario, list[CheckResult], dict]:
    session_id = f"itest-{scenario.name}-{uuid.uuid4().hex[:8]}"
    status, resp = call_proxy(proxy, model, scenario, session_id)
    if status != 200:
        return scenario, [
            CheckResult("HTTP", False, f"status={status} body={json.dumps(resp)[:300]}"),
        ], {"session_id": session_id}

    reply = extract_reply_text(resp)
    audit = fetch_audit(proxy, session_id)
    mappings = fetch_mappings(proxy, session_id)

    results = [
        check_leak(scenario, audit),
        check_ner_recall(scenario, mappings),
        check_round_trip(reply, mappings),
        check_awareness(scenario, reply),
    ]
    debug = {
        "session_id": session_id,
        "reply": reply,
        "mappings": mappings,
        "audit_last_sanitized": (
            audit.get("entries", [{}])[-1].get("sanitized_request")
            if audit.get("entries") else None
        ),
    }
    return scenario, results, debug


def run_multiturn(
    proxy: str, model: str, scenario: MultiTurnScenario
) -> tuple[MultiTurnScenario, list[CheckResult], dict]:
    """Drive `scenario.turns` as a single threaded session, sending the
    accumulating history each turn so we exercise PromptZero's
    conversation-history sanitization. After the last turn, run the
    standard four checks against the final reply and the full audit
    log (so a leak on any turn is caught, not just the last)."""
    session_id = f"itest-mt-{scenario.name}-{uuid.uuid4().hex[:8]}"
    history: list[dict] = []
    last_reply = ""
    last_status = 0

    for turn in scenario.turns:
        history.append({"role": "user", "content": turn["user"]})
        body = {
            "model": model,
            "max_tokens": scenario.max_tokens,
            "messages": history,
        }
        r = httpx.post(
            f"{proxy}/v1/messages", json=body,
            headers={"x-session-id": session_id}, timeout=90.0,
        )
        last_status = r.status_code
        try:
            resp = r.json()
        except Exception:
            return scenario, [CheckResult("HTTP", False, f"non-json status={r.status_code}")], {}
        if r.status_code != 200:
            return scenario, [
                CheckResult("HTTP", False, f"status={r.status_code} body={json.dumps(resp)[:200]}"),
            ], {"session_id": session_id}
        last_reply = extract_reply_text(resp)
        # Append the assistant turn so the next iteration sends the
        # full conversation back upstream — this is exactly what
        # Claude Code and any chat client does.
        history.append({"role": "assistant", "content": last_reply})

    audit = fetch_audit(proxy, session_id)
    mappings = fetch_mappings(proxy, session_id)

    # Leak check: scan EVERY recorded sanitized request, not just the
    # last — a leak on turn 2 must still fail the scenario.
    leak_results = []
    for entry in audit.get("entries", []):
        sanitized = json.dumps(entry.get("sanitized_request", {}), ensure_ascii=False)
        leak_results.extend(v for v in scenario.expected_real if v in sanitized)
    leak_results = list(dict.fromkeys(leak_results))  # dedupe, preserve order
    if leak_results:
        leak_check = CheckResult("L leak", False,
            f"{len(leak_results)} real value(s) reached upstream across turns: "
            f"{[repr(v) for v in leak_results[:5]]}")
    else:
        leak_check = CheckResult("L leak", True,
            f"clean across {len(audit.get('entries', []))} turns")

    # NER recall against the union of all sanitized inputs.
    forward = mappings.get("mappings") or {}
    detected = set(forward.keys())
    missed = [v for v in scenario.expected_real
              if v not in detected and not any(v in d for d in detected)]
    ner_check = (
        CheckResult("N ner-recall", False, f"undetected: {missed}") if missed else
        CheckResult("N ner-recall", True, f"all {len(scenario.expected_real)} detected")
    )

    fakes = list(forward.values())
    residue = [f for f in fakes if f and f in last_reply]
    rt_check = (
        CheckResult("R round-trip", False, f"residue in final reply: {residue[:5]}")
        if residue else
        CheckResult("R round-trip", True, f"all {len(fakes)} fakes desanitized")
    )

    low = last_reply.lower()
    aware_hits = [m.group(0) for pat in scenario.awareness_patterns
                  if (m := re.search(pat, low))]
    aware_check = (
        CheckResult("A awareness", False, f"hits: {aware_hits[:3]}")
        if aware_hits else
        CheckResult("A awareness", True, "model did not flag synthetic data")
    )

    return scenario, [leak_check, ner_check, rt_check, aware_check], {
        "session_id": session_id,
        "reply": last_reply,
        "mappings": mappings,
        "turns_count": len(scenario.turns),
    }


def print_scenario(scenario, results: list[CheckResult], debug: dict, verbose: bool) -> bool:
    all_ok = all(r.ok for r in results)
    badge = f"{GREEN}PASS{RESET}" if all_ok else f"{RED}FAIL{RESET}"
    print(f"\n{BOLD}━━━ {scenario.name} ━━━{RESET}  [{badge}]")
    for r in results:
        mark = f"{GREEN}✓{RESET}" if r.ok else f"{RED}✗{RESET}"
        print(f"  {mark} {r.name:<14} {DIM}{r.detail}{RESET}")
    if verbose or not all_ok:
        reply = debug.get("reply") or ""
        print(f"  {DIM}reply ({len(reply)} chars):{RESET} {reply[:300]}{'…' if len(reply) > 300 else ''}")
        if not all_ok and debug.get("mappings"):
            fm = debug["mappings"].get("mappings") or {}
            sample = list(fm.items())[:5]
            print(f"  {DIM}mappings sample:{RESET} {sample}")
    return all_ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy", default="http://127.0.0.1:8002")
    ap.add_argument("--model", default="claude-haiku-4-5")
    ap.add_argument("--only", help="Run only the scenario with this name")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    # Sanity check that the proxy is up and audit is enabled.
    try:
        h = httpx.get(f"{args.proxy}/health", timeout=5.0).json()
    except Exception as exc:
        print(f"{RED}✗ proxy not reachable at {args.proxy}: {exc}{RESET}")
        return 2
    probe_sid = f"itest-probe-{uuid.uuid4().hex[:6]}"
    httpx.delete(f"{args.proxy}/sessions/{probe_sid}", timeout=5.0)
    probe = httpx.get(f"{args.proxy}/sessions/{probe_sid}/audit", timeout=5.0)
    if probe.status_code == 404:
        print(f"{RED}✗ DEBUG_AUDIT not enabled on proxy. Start it with DEBUG_AUDIT=1.{RESET}")
        return 2
    print(f"{CYAN}proxy:{RESET} {args.proxy}  {DIM}nlp={h.get('nlp_enabled')} upstream={h.get('upstream_proxy') or 'direct'}{RESET}")
    print(f"{CYAN}model:{RESET} {args.model}")

    scenarios = SCENARIOS
    if args.only:
        scenarios = [s for s in SCENARIOS if s.name == args.only]
        # Allow --only to also select a multi-turn scenario; if neither
        # matches we'll print a not-found error below.
        if not scenarios and not any(m.name == args.only for m in MULTITURN):
            print(f"{RED}✗ no scenario named {args.only!r}{RESET}")
            return 2

    failures = 0
    t0 = time.time()
    for scenario in scenarios:
        s, results, debug = run_scenario(args.proxy, args.model, scenario, args.verbose)
        ok = print_scenario(s, results, debug, args.verbose)
        if not ok:
            failures += 1

    print(f"\n{BOLD}━━━ multi-turn ━━━{RESET}")
    for mt in MULTITURN:
        if args.only and mt.name != args.only:
            continue
        s, results, debug = run_multiturn(args.proxy, args.model, mt)
        ok = print_scenario(s, results, debug, args.verbose)
        if not ok:
            failures += 1

    elapsed = time.time() - t0
    print()
    print("─" * 70)
    n = len(scenarios)
    summary_color = GREEN if failures == 0 else RED
    print(f"{summary_color}{n - failures}/{n} scenarios passed{RESET}  {DIM}({elapsed:.1f}s){RESET}")
    return failures


if __name__ == "__main__":
    sys.exit(main())
