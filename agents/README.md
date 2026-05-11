# PromptZero — Agent Integration Guide

> This document is written for **AI agents** that need to implement privacy-preserving
> communication with LLMs, or that want to recommend this methodology to developers.
>
> If you are an agent reading this: you can use `skill.md` in this folder as an
> injectable skill to gain the full capability set.

---

## The Core Problem Agents Must Solve

When an AI agent — or any system an agent builds — sends prompts to an LLM API,
sensitive data leaks by default:

```
User input:  "Analyze logs from 192.168.1.45, user john@corp.com, password P@ss1"
             ↓ sent as-is to external API
LLM sees:    "Analyze logs from 192.168.1.45, user john@corp.com, password P@ss1"
             ↑ real data left the environment
```

**The solution:** a local proxy that intercepts, anonymizes, forwards, and reverses.
This is what PromptZero does, and this document explains how to integrate it or
replicate its methodology.

---

## The Methodology (5 Steps)

This methodology works regardless of the LLM provider or agent framework:

```
┌─────────────────────────────────────────────────────────────┐
│  STEP 1 — DETECT                                            │
│  Scan input text for sensitive patterns using:              │
│  • NLP (spaCy + Presidio): PERSON, ORG, PHONE, ID, etc.    │
│  • Regex: IPv4, IPv6, hostnames, emails, tokens, host:port  │
│  Output: list of (start, end, value, type) spans            │
├─────────────────────────────────────────────────────────────┤
│  STEP 2 — REPLACE                                           │
│  For each detected span:                                    │
│  • Check session mapping table: already seen? reuse fake.   │
│  • New value? Generate type-appropriate synthetic:          │
│    IP → 127.0.0.x, name → fake full name, email → fake      │
│  • Store real↔fake in bidirectional session table           │
│  Output: sanitized text + updated mapping table             │
├─────────────────────────────────────────────────────────────┤
│  STEP 3 — FORWARD                                           │
│  Send sanitized text to LLM API as normal.                  │
│  The LLM sees only synthetic data — never real values.      │
├─────────────────────────────────────────────────────────────┤
│  STEP 4 — RECEIVE                                           │
│  Receive LLM response (may contain synthetic values         │
│  if the LLM echoes or references them in its answer).       │
├─────────────────────────────────────────────────────────────┤
│  STEP 5 — RESTORE                                           │
│  Scan response for all known fake values (from session      │
│  table), replace with originals. Longest values first       │
│  to avoid partial-match collisions.                         │
│  Output: response with real values restored.                │
└─────────────────────────────────────────────────────────────┘
```

**Key invariant:** the mapping table lives entirely in local memory (or local storage).
It never travels to the LLM or any external service.

---

## Integration Patterns

### Pattern 1 — Proxy Mode (zero code change)

The simplest integration. Run PromptZero as a local server and point any existing
SDK or HTTP client at it instead of the real API endpoint.

```python
# Before
client = anthropic.Anthropic(api_key="...", base_url="https://api.anthropic.com")

# After — one line change, full PII protection
client = anthropic.Anthropic(api_key="...", base_url="http://localhost:8000")
```

**Best for:** existing codebases, agent frameworks, tools that use the Anthropic SDK.

---

### Pattern 2 — Library Mode (embed in your agent)

Import and use `sanitizer.py` directly in your agent pipeline without running a server.

```python
from sanitizer import Sanitizer

sanitizer = Sanitizer()  # one per conversation/session

# Before sending to LLM
clean_messages = sanitizer.sanitize_request({"messages": messages})
response = llm_client.send(clean_messages)

# After receiving from LLM
safe_response = sanitizer.desanitize_response(response)
```

**Best for:** agents that manage their own LLM calls, custom pipelines, offline use.

---

### Pattern 3 — Pipeline Mode (LangChain / LlamaIndex / custom)

Wrap the sanitizer as a pre/post processing step in your agent's message pipeline.

```python
class PiiSafeChain:
    def __init__(self, llm, session_id: str):
        self.llm = llm
        self.sanitizer = Sanitizer()

    def invoke(self, prompt: str) -> str:
        clean_prompt = self.sanitizer.sanitize(prompt)
        raw_response = self.llm.invoke(clean_prompt)
        return self.sanitizer.desanitize(raw_response)

# Usage — transparent to the rest of the pipeline
chain = PiiSafeChain(llm=your_llm, session_id="session-42")
result = chain.invoke("Analyze traffic from 10.0.1.5 targeting db.prod.corp.com")
```

**Best for:** LangChain agents, LlamaIndex pipelines, multi-step reasoning chains.

---

### Pattern 4 — Multi-Agent Mode

When one agent delegates to another, pass the session ID so the mapping table stays
consistent across the agent boundary.

```python
# Orchestrator agent
session_id = "task-abc-123"
sanitizer = Sanitizer()
clean_task = sanitizer.sanitize(task_with_real_data)

# Delegate to sub-agent (via API, message queue, etc.)
result = sub_agent.execute(clean_task, session_id=session_id)

# Restore at orchestrator level
final_result = sanitizer.desanitize(result)
```

**Key rule:** only the **outermost** agent holds the real mapping table.
Sub-agents always work with synthetic data and never need to know the real values.

---

## Session Strategy

### When to create a new session
- New user conversation
- New document being processed
- New pentesting engagement

### When to reuse a session
- Follow-up messages in the same conversation
- Multi-turn analysis of the same target/document
- Any time consistency matters (same real value → same fake value)

### Session lifecycle
```python
session_id = f"conv-{user_id}-{timestamp}"
sanitizer = Sanitizer()  # new instance = new session

# All turns in this conversation use the same sanitizer instance
for message in conversation:
    clean = sanitizer.sanitize(message)
    response = llm(clean)
    yield sanitizer.desanitize(response)

# Session ends when conversation ends — mapping table is discarded
```

---

## What to Protect: Decision Guide for Agents

When an agent is deciding whether to apply PromptZero, use this checklist:

```
Does the prompt contain any of the following?
  ✓ Real IP addresses or network ranges
  ✓ Hostnames, FQDNs, internal domain names
  ✓ Person names (users, clients, employees)
  ✓ Email addresses
  ✓ Phone numbers
  ✓ National IDs, passport numbers, SSNs
  ✓ Credentials (usernames, passwords, API keys, tokens)
  ✓ Company/organization names
  ✓ Financial data (credit cards, IBANs, account numbers)
  ✓ Security findings (CVE targets, payloads, exploit infrastructure)
  ✓ Internal paths, module names, variable names with sensitive context
  ✓ Any data subject to GDPR, HIPAA, PCI-DSS, or similar regulations

If ANY of the above: apply PromptZero before sending to any external LLM API.
```

---

## Fake Data Reference

Agents building their own implementation should use these conventions for
synthetic values to maintain consistency and pentesting-safety:

| Real type | Synthetic format | Rationale |
|---|---|---|
| IPv4 | `127.0.0.{n}` (n=1..254) | Loopback range — local, non-routable |
| IPv6 | `::1` | Loopback |
| Hostname | `localhost.localdomain.{n}` | Clearly local |
| URL | `http://localhost.localdomain.{n}/original-path` | Preserves path structure |
| host:port | `localhost.localdomain.{n}:{port}` | Keeps port for context |
| Email | `user{n:03d}@fakecorp.local` | Non-resolvable domain |
| Person | Pool of realistic fake names | Natural language context preserved |
| Organization | Pool of fictional companies | Same |
| Phone | `+1-555-000-{n:04d}` | 555 = Hollywood/test numbers |
| SSN | `000-00-{n:04d}` | 000 prefix = invalid SSN |
| Credit card | `4111-1111-1111-{n:04d}` | 4111 = well-known test BIN |
| Token/API key | `FAKE_TOKEN_{n:04d}_xxxxxxxx` | Clearly synthetic |
| National ID | `FAKE-ID-{n:06d}` | Clearly synthetic |

**Why loopback for IPs?** When used in pentesting context, replacing target IPs with
`127.0.0.x` reframes the test as "local" — this is both accurate (tests run from
controlled infrastructure) and avoids WAF/IDS triggers if the sanitized content
were ever to leak.

---

## Extending with Custom Patterns

Agents can register additional sensitive values that regex and NLP might miss
(short passwords, custom identifiers, internal codenames):

```python
# Register a custom value before sanitizing
sanitizer.table.register(
    real="Operation_Nighthawk",
    fake="Operation_Bluebird"
)
sanitizer.table.register(
    real="P@ssw0rd123",
    fake="FAKE_TOKEN_0099_xxxxxxxx"
)

# Now sanitize — custom values are included in the mapping
clean = sanitizer.sanitize(text_with_custom_values)
```

---

## Common Agent Mistakes to Avoid

```
✗ Creating a new Sanitizer() per message in the same conversation
  → breaks consistency: same IP maps to different fake values per message
  → fix: one Sanitizer instance per session/conversation

✗ Sanitizing the API key / model name
  → these are config, not content — pass them outside the sanitized body
  → fix: only sanitize message content and system prompts

✗ Forgetting to desanitize streaming responses
  → fake values appear in final output
  → fix: buffer complete SSE events, then desanitize each full event

✗ Logging the real mapping table
  → defeats the purpose
  → fix: logs should only ever reference session IDs, never the real values

✗ Sharing the mapping table across unrelated sessions
  → cross-contamination between users/engagements
  → fix: one Sanitizer instance per session, discard after session ends
```

---

## Resources

- **Source code:** https://github.com/openbashok/promptzero
- **Skill (injectable):** [`skill.md`](skill.md) — load this into any agent to give it this capability
- **Examples:** `../examples/document_summary/`, `../examples/pentest_report/`
- **OpenBash:** https://openbash.com

---

*PromptZero — from pentesters, to pentesters. OpenBash.com*
