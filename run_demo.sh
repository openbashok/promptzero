#!/usr/bin/env bash
# run_demo.sh — One-command launcher for the 90-second PromptZero pitch.
#
# What it does:
#   1) Pre-flight checks (venv, .env, Burp on 8080, UPSTREAM_PROXY config)
#   2) Kills any stale PromptZero on :8000
#   3) Starts PromptZero in the foreground with the startup banner
#   4) Prints the exact next commands to paste in another terminal so you can
#      record the Claude Code session
#
# Usage:
#   ./run_demo.sh             # full launch
#   ./run_demo.sh --check     # only run pre-flights, don't start proxy

set -e

GREEN=$'\033[32m'
RED=$'\033[31m'
CYAN=$'\033[36m'
YEL=$'\033[33m'
DIM=$'\033[2m'
BOLD=$'\033[1m'
END=$'\033[0m'

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

pass() { echo "  ${GREEN}✓${END} $1"; }
warn() { echo "  ${YEL}!${END} $1"; }
fail() {
    echo "  ${RED}✗${END} $1"
    [ -n "${2:-}" ] && echo "    ${DIM}→ $2${END}"
    exit 1
}

echo
echo "${BOLD}PromptZero — demo pre-flight${END}"
echo

# 1. virtualenv
if [ ! -d ".venv" ]; then
    fail "Virtualenv .venv not found." "Run ./setup.sh to create it."
fi
pass "Virtualenv present"

# 2. .env exists with API key
if [ ! -f ".env" ]; then
    fail ".env file missing." "cp .env.example .env  and add your ANTHROPIC_API_KEY"
fi
if ! grep -qE "^ANTHROPIC_API_KEY=sk-ant-" .env; then
    fail ".env has no real ANTHROPIC_API_KEY." \
         "Edit .env and set ANTHROPIC_API_KEY=sk-ant-..."
fi
KEY=$(grep "^ANTHROPIC_API_KEY=" .env | head -1 | cut -d= -f2- | tr -d '\r\n"')
KEY_TAIL="${KEY: -6}"
pass "ANTHROPIC_API_KEY set (…${KEY_TAIL})"

# 3. UPSTREAM_PROXY active in .env
if ! grep -qE "^UPSTREAM_PROXY=http" .env; then
    fail "UPSTREAM_PROXY is commented out / missing in .env" \
         "Uncomment   UPSTREAM_PROXY=http://127.0.0.1:8080   in .env"
fi
UPSTREAM=$(grep "^UPSTREAM_PROXY=" .env | head -1 | cut -d= -f2-)
pass "UPSTREAM_PROXY=${UPSTREAM}"

if ! grep -qE "^UPSTREAM_VERIFY=" .env && ! grep -qE "^UPSTREAM_CA_BUNDLE=" .env; then
    warn "Neither UPSTREAM_VERIFY=false nor UPSTREAM_CA_BUNDLE is set."
    warn "Burp's self-signed CA will fail TLS verify. For a quick demo, set"
    warn "  UPSTREAM_VERIFY=false  in .env."
fi

# 4. Burp listening
UPSTREAM_HOSTPORT=$(echo "$UPSTREAM" | sed -E 's#^https?://##')
UPSTREAM_HOST=$(echo "$UPSTREAM_HOSTPORT" | cut -d: -f1)
UPSTREAM_PORT=$(echo "$UPSTREAM_HOSTPORT" | cut -d: -f2)
if ! nc -z -w 2 "$UPSTREAM_HOST" "$UPSTREAM_PORT" 2>/dev/null; then
    fail "Nothing listening at $UPSTREAM_HOSTPORT" \
         "Open Burp and enable Proxy → Settings → Proxy listeners → ${UPSTREAM_PORT} Running"
fi
pass "Burp / interception proxy listening at $UPSTREAM_HOSTPORT"

# 5. claude CLI available
if ! command -v claude >/dev/null 2>&1; then
    warn "Claude Code CLI not found in PATH. Install it from https://github.com/anthropics/claude-code"
    warn "The demo will still work via demo_claude.py / demo_html.py."
else
    pass "Claude Code CLI present ($(claude --version 2>&1 | head -1))"
fi

# Stop here if --check
if [ "${1:-}" = "--check" ]; then
    echo
    echo "${BOLD}${GREEN}Pre-flight OK — ready to record.${END}"
    exit 0
fi

# 6. Kill any old PromptZero on :8000
if lsof -i :8000 -t >/dev/null 2>&1; then
    warn "Killing existing process on :8000"
    lsof -i :8000 -t | xargs kill -9 2>/dev/null || true
    sleep 1
fi
pass "Port 8000 free"

echo
echo "${BOLD}Pre-flight OK.${END}  Starting PromptZero in this terminal."
echo
echo "${DIM}When the banner says 'upstream_proxy : $UPSTREAM' you're live.${END}"
echo "${DIM}Open a second terminal and run the commands below:${END}"
echo
echo "${BOLD}${CYAN}━━━ In a second terminal ━━━${END}"
echo
cat <<EOF
${BOLD}# tab 1 (recording): drive Claude Code through the proxy${END}
cd "$ROOT"
export ANTHROPIC_BASE_URL=http://localhost:8000
claude

# Then paste this prompt into the Claude Code session:
${CYAN}Acabo de terminar un pentest interno en Nexabank Financial S.A.
Encontré un RCE pre-auth en vpn.nexabank.com (203.0.113.10) explotando
CVE-2024-21762. Conseguí admin:Nexabank2024! y pivoteé a
dc01.nexabank.local (10.10.1.5). Ayudame a redactar el correo de
comunicación a Roberto Carlos Silva (r.silva@nexabank.com), CISO
del cliente, en 4 líneas.${END}

${BOLD}# tab 2 (optional B-roll): the visual HTML report${END}
cd "$ROOT"
source .venv/bin/activate
python examples/poc/demo_html.py \\
    --dataset examples/poc/data/02_pentest_engagement.json \\
    --with-claude --task technical \\
    --out /tmp/demo-video.html --open
EOF
echo
echo "${BOLD}${CYAN}━━━ While recording ━━━${END}"
echo
echo "  1. Frame Burp's ${BOLD}Proxy → HTTP history${END} alongside the terminal."
echo "  2. After Claude responds, switch to Burp."
echo "  3. Open the new POST to api.anthropic.com → Request tab."
echo "  4. ${BOLD}Ctrl+F${END} → search ${BOLD}'nexabank'${END} → ${BOLD}Not found.${END}  That's the proof."
echo
echo "${BOLD}${GREEN}Starting proxy now…${END}"
echo

source .venv/bin/activate
exec python main.py
