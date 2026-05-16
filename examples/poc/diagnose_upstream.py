"""
diagnose_upstream.py — Why isn't traffic showing up in Burp?

Runs five checks, top to bottom, with clear PASS / FAIL output:

  1. Is the PromptZero proxy reachable at http://localhost:8000?
  2. Does /health show the UPSTREAM_PROXY env var you expect?
  3. Is the upstream proxy port (e.g. 127.0.0.1:8080 for Burp) listening?
  4. Can httpx complete a request through the configured upstream proxy?
     → goes to https://api.anthropic.com/v1/models so Burp captures one
       real PromptZero-like request shape
  5. Does a real /v1/messages request through the running proxy succeed?

If any step fails it tells you exactly what to fix.

Usage:
    python diagnose_upstream.py
    python diagnose_upstream.py --proxy http://127.0.0.1:8000        # different PromptZero port
    python diagnose_upstream.py --skip-claude                        # don't hit api.anthropic.com
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import urllib.parse
from pathlib import Path

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(ROOT / ".env")

GREEN = "\033[32m"
RED   = "\033[31m"
YEL   = "\033[33m"
DIM   = "\033[2m"
BOLD  = "\033[1m"
END   = "\033[0m"

color_on = sys.stdout.isatty()


def c(text: str, code: str) -> str:
    return f"{code}{text}{END}" if color_on else text


def section(num: int, title: str) -> None:
    print()
    print(c(f"━━━ {num}. {title} ━━━", BOLD))


def ok(msg: str) -> None:
    print(c("  ✓ PASS", GREEN) + f"  {msg}")


def fail(msg: str, hint: str = "") -> None:
    print(c("  ✗ FAIL", RED) + f"  {msg}")
    if hint:
        for line in hint.split("\n"):
            print(c(f"          → {line}", YEL))


def warn(msg: str) -> None:
    print(c("  ! WARN", YEL) + f"  {msg}")


def info(msg: str) -> None:
    print(c(f"  · {msg}", DIM))


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_proxy_reachable(proxy_url: str) -> bool:
    section(1, f"PromptZero proxy reachable at {proxy_url}")
    try:
        r = httpx.get(f"{proxy_url}/health", timeout=5.0)
        r.raise_for_status()
        body = r.json()
        ok(f"/health responded {r.status_code}")
        info(f"NLP enabled: {body.get('nlp_enabled')}")
        info(f"Active sessions: {body.get('active_sessions')}")
        return True
    except Exception as exc:
        fail(
            f"Could not reach {proxy_url}/health  ({exc})",
            "Start the proxy in another terminal:\n"
            "  cd <repo-root> && source .venv/bin/activate && python main.py",
        )
        return False


def check_upstream_config(proxy_url: str, expect_proxy: str | None) -> dict:
    section(2, "Proxy /health reports the upstream config you expect")
    r = httpx.get(f"{proxy_url}/health", timeout=5.0)
    body = r.json()
    info(f"raw /health → {body}")

    health_upstream = body.get("upstream_proxy")
    health_verify   = body.get("upstream_verify")

    env_upstream    = os.getenv("UPSTREAM_PROXY", "").strip() or None
    env_ca          = os.getenv("UPSTREAM_CA_BUNDLE", "").strip() or None
    env_verify_raw  = os.getenv("UPSTREAM_VERIFY", "true").lower()
    env_verify      = env_verify_raw not in ("0", "false", "no", "off")

    info(f"Your .env says UPSTREAM_PROXY={env_upstream}")
    info(f"Your .env says UPSTREAM_CA_BUNDLE={env_ca}")
    info(f"Your .env says UPSTREAM_VERIFY={env_verify_raw} → {env_verify}")
    info(f"The running proxy says upstream_proxy={health_upstream}")
    info(f"The running proxy says upstream_verify={health_verify}")

    if env_upstream and not health_upstream:
        fail(
            "Your .env has UPSTREAM_PROXY set but the running proxy doesn't see it.",
            "The proxy reads .env ONCE at startup. Stop and restart `python main.py`\n"
            "after editing .env.",
        )
        return body

    if expect_proxy and health_upstream != expect_proxy:
        fail(
            f"Expected upstream_proxy={expect_proxy}, proxy is using {health_upstream}",
            "Edit .env and restart `python main.py`.",
        )
    elif health_upstream:
        ok(f"Proxy is configured to route through {health_upstream}")
    else:
        warn(
            "No upstream proxy is configured — traffic goes DIRECTLY to "
            "api.anthropic.com. Burp will see nothing."
        )

    return body


def check_burp_port_listening(upstream_url: str | None) -> bool:
    section(3, "Upstream proxy port is actually listening")
    if not upstream_url:
        warn("No UPSTREAM_PROXY set — skipping (nothing to check).")
        return True

    parsed = urllib.parse.urlparse(upstream_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    info(f"Testing TCP connect to {host}:{port} (5s timeout) …")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((host, port))
        ok(f"{host}:{port} accepted a TCP connection")
        return True
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        fail(
            f"{host}:{port} did not accept a TCP connection ({exc})",
            "Make sure Burp is open AND that the Proxy listener is enabled:\n"
            "  Burp → Proxy → Settings → Proxy listeners → [127.0.0.1:8080] Running\n"
            "If Burp is running, double-check the port matches UPSTREAM_PROXY in .env.",
        )
        return False
    finally:
        sock.close()


def check_httpx_through_upstream(
    upstream_url: str | None,
    ca_bundle: str | None,
    verify: bool,
    skip: bool,
) -> bool:
    section(4, "httpx can complete a real upstream request through Burp")
    if skip:
        warn("--skip-claude passed; skipping.")
        return True
    if not upstream_url:
        warn("No UPSTREAM_PROXY set — skipping.")
        return True

    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key or api_key == "your-api-key-here":
        fail(
            "No ANTHROPIC_API_KEY set in .env — can't test against api.anthropic.com.",
            "Put your real key in .env first.",
        )
        return False

    kwargs = {"proxy": upstream_url, "timeout": 30.0}
    if ca_bundle:
        kwargs["verify"] = ca_bundle
        info(f"Using CA bundle: {ca_bundle}")
    elif not verify:
        kwargs["verify"] = False
        info("TLS verification DISABLED")
    else:
        info("TLS verification enabled with system trust store")

    info(f"Sending GET https://api.anthropic.com/v1/models via {upstream_url} …")
    try:
        with httpx.Client(**kwargs) as client:
            r = client.get(
                "https://api.anthropic.com/v1/models",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                },
            )
        info(f"HTTP {r.status_code}")
        if r.status_code == 200:
            ok("Upstream call succeeded — this request should be visible in Burp now.")
            return True
        ok(f"Upstream call returned HTTP {r.status_code} (still proves the proxy "
           f"is in the path; check Burp).")
        return True
    except httpx.ConnectError as exc:
        fail(
            f"httpx couldn't even open a connection through {upstream_url}: {exc}",
            "The upstream proxy port is not reachable. Re-check step 3.",
        )
    except (httpx.HTTPError, OSError) as exc:
        msg = str(exc)
        if "certificate" in msg.lower() or "ssl" in msg.lower():
            fail(
                f"TLS handshake failed: {exc}",
                "Burp is doing TLS interception with its own CA. Either:\n"
                "  a) Export Burp's CA cert in PEM format and set\n"
                "       UPSTREAM_CA_BUNDLE=/path/to/burp-ca.pem in .env\n"
                "  b) Or for a quick demo set UPSTREAM_VERIFY=false in .env",
            )
        else:
            fail(
                f"httpx call failed: {exc}",
                "Inspect Burp's Dashboard or Event log for the matching event.",
            )
    return False


def check_e2e_through_proxy(
    proxy_url: str, skip: bool,
) -> bool:
    section(5, "End-to-end: a real /v1/messages through PromptZero works")
    if skip:
        warn("--skip-claude passed; skipping.")
        return True

    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key or api_key == "your-api-key-here":
        warn("No ANTHROPIC_API_KEY; skipping.")
        return True

    payload = {
        "model": "claude-haiku-4-5",
        "max_tokens": 80,
        "messages": [{
            "role": "user",
            "content": (
                "Reply with exactly the word OK. "
                "Context: server db-prod.nexabank.local at 10.10.1.22, "
                "user r.silva@nexabank.com."
            ),
        }],
    }
    try:
        r = httpx.post(
            f"{proxy_url}/v1/messages",
            json=payload,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "x-session-id": "diagnose-upstream-test",
            },
            timeout=60.0,
        )
        info(f"HTTP {r.status_code}")
        if r.status_code != 200:
            fail(
                f"PromptZero returned {r.status_code}",
                f"Body excerpt: {r.text[:300]}",
            )
            return False
        text = r.json()["content"][0]["text"]
        ok(f"Claude responded: {text[:120]!r}")

        # Confirm sanitization happened by inspecting the session
        m = httpx.get(
            f"{proxy_url}/sessions/diagnose-upstream-test/mappings", timeout=5.0,
        ).json()
        mappings = m.get("mappings", {})
        if "db-prod.nexabank.local" in mappings and "10.10.1.22" in mappings:
            ok(
                f"Session mapped {len(mappings)} value(s) — "
                f"db-prod.nexabank.local → {mappings['db-prod.nexabank.local']}, "
                f"10.10.1.22 → {mappings['10.10.1.22']}"
            )
        else:
            warn(
                f"Expected db-prod.nexabank.local and 10.10.1.22 in the mapping table, "
                f"got: {list(mappings)[:5]}"
            )
        return True
    except Exception as exc:
        fail(f"PromptZero request failed: {exc}")
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Diagnose why traffic isn't showing up in Burp / mitmproxy.",
    )
    parser.add_argument("--proxy", default="http://localhost:8000",
                        help="PromptZero proxy URL")
    parser.add_argument("--skip-claude", action="store_true",
                        help="Skip steps that contact api.anthropic.com")
    args = parser.parse_args()

    print(c("PromptZero upstream-traffic diagnostic", BOLD))
    print(c(f"  .env loaded from: {ROOT / '.env'}", DIM))

    ok_1 = check_proxy_reachable(args.proxy)
    if not ok_1:
        sys.exit(2)

    health = check_upstream_config(
        proxy_url=args.proxy,
        expect_proxy=os.getenv("UPSTREAM_PROXY", "").strip() or None,
    )
    upstream = health.get("upstream_proxy")
    ca_bundle = os.getenv("UPSTREAM_CA_BUNDLE", "").strip() or None
    verify = os.getenv("UPSTREAM_VERIFY", "true").lower() not in (
        "0", "false", "no", "off",
    )

    check_burp_port_listening(upstream)
    check_httpx_through_upstream(upstream, ca_bundle, verify, args.skip_claude)
    check_e2e_through_proxy(args.proxy, args.skip_claude)

    print()
    if upstream:
        print(c(
            f"If you still don't see traffic, switch to Burp's "
            f"Dashboard tab → Event log: every blocked TLS handshake "
            f"is logged there with the exact reason.",
            DIM,
        ))
    print()


if __name__ == "__main__":
    main()
