"""
main.py — Transparent Claude API proxy with PII/sensitive-data sanitization.

Drop-in replacement for https://api.anthropic.com — just point your SDK or
HTTP client to http://localhost:8000 instead. Compatible with the official
Anthropic SDKs and the Claude Code CLI (`ANTHROPIC_BASE_URL=…`).

Endpoint behaviour:
  • POST /v1/messages                — sanitized in, desanitized out (streaming OK)
  • POST /v1/messages/count_tokens   — sanitized so the count reflects the
                                       prompt that would actually be sent
  • everything else under /v1/*      — forwarded unchanged (models list,
                                       organizations, files, batches, …)

Session lifecycle:
  • Pass  x-session-id: <id>  to reuse a mapping table across requests
    (same conversation → same fake values → consistent desanitization).
  • Omit the header to get a one-shot session (new UUID per request).
  • DELETE /sessions/<id> to reset a session's mapping table.
"""

import asyncio
import os
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from sanitizer import Sanitizer, _get_analyzer, nlp_available

load_dotenv()

CLAUDE_BASE_URL = "https://api.anthropic.com"
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
PORT = int(os.getenv("PORT", "8000"))

# Upstream proxy (for inspecting what PromptZero sends to api.anthropic.com).
# Typical use: route through Burp Suite at http://127.0.0.1:8080 to verify
# during a demo that no real PII leaves the machine. Optional.
UPSTREAM_PROXY = os.getenv("UPSTREAM_PROXY", "").strip() or None
# When true, skip TLS verification on the upstream hop. Useful when the
# upstream proxy (Burp / mitmproxy / Charles) does TLS interception with
# its own CA that you haven't imported. Default: verify.
UPSTREAM_VERIFY = os.getenv("UPSTREAM_VERIFY", "true").lower() not in (
    "0", "false", "no", "off",
)
# Optional explicit CA bundle path for the upstream hop (lets you keep
# verification on while trusting Burp's exported CA cert).
UPSTREAM_CA_BUNDLE = os.getenv("UPSTREAM_CA_BUNDLE", "").strip() or None


def _httpx_client(**extra) -> httpx.AsyncClient:
    """Build an httpx.AsyncClient pre-wired with the configured upstream
    proxy / TLS settings. Used everywhere we talk to api.anthropic.com so
    inspection through Burp is a single env-var flip away."""
    kwargs = {"timeout": 120.0}
    if UPSTREAM_PROXY:
        kwargs["proxy"] = UPSTREAM_PROXY
    if UPSTREAM_CA_BUNDLE:
        kwargs["verify"] = UPSTREAM_CA_BUNDLE
    elif not UPSTREAM_VERIFY:
        kwargs["verify"] = False
    kwargs.update(extra)
    return httpx.AsyncClient(**kwargs)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-warm the NLP engine at startup so the first request isn't slow
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _get_analyzer)
    yield


app = FastAPI(
    title="PromptZero",
    description="Zero trace. Full answer. — Transparent Claude API proxy that keeps sensitive data in your environment.",
    version="2.2.0",
    lifespan=lifespan,
)

# In-memory session store  { session_id -> Sanitizer }
_sessions: dict[str, Sanitizer] = {}


def _get_session(session_id: str) -> Sanitizer:
    if session_id not in _sessions:
        _sessions[session_id] = Sanitizer()
    return _sessions[session_id]


# ---------------------------------------------------------------------------
# Management endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "active_sessions": len(_sessions),
        "nlp_enabled": nlp_available(),
        "upstream_proxy": UPSTREAM_PROXY,
        "upstream_verify": (
            UPSTREAM_CA_BUNDLE if UPSTREAM_CA_BUNDLE
            else (True if UPSTREAM_VERIFY else False)
        ),
    }


@app.get("/sessions/{session_id}/mappings")
async def get_mappings(session_id: str):
    """Return the current real↔fake mapping table for a session (debug)."""
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    return _sessions[session_id].table.snapshot()


@app.delete("/sessions/{session_id}")
async def clear_session(session_id: str):
    """Wipe a session's mapping table (forces fresh fake values next time)."""
    _sessions.pop(session_id, None)
    return {"status": "cleared", "session_id": session_id}


# ---------------------------------------------------------------------------
# Streaming helper — buffers complete SSE events before desanitizing
# ---------------------------------------------------------------------------

async def _stream_desanitized(
    url: str,
    payload: dict,
    headers: dict,
    sanitizer: Sanitizer,
) -> AsyncIterator[str]:
    """
    Forward a streaming response from Claude and desanitize each SSE event.
    SSE events are delimited by double-newlines, so we buffer until we have
    a complete event before running desanitization — this avoids the risk of
    a fake value being split across two chunks.

    Owns its own httpx client so the lifecycle matches the stream consumer
    (the StreamingResponse iterates after the route handler returns, so the
    client must outlive the route function).
    """
    buffer = ""
    async with _httpx_client() as client:
        async with client.stream("POST", url, json=payload, headers=headers) as resp:
            async for chunk in resp.aiter_text():
                buffer += chunk
                # SSE events end with \n\n
                while "\n\n" in buffer:
                    event, buffer = buffer.split("\n\n", 1)
                    yield sanitizer.desanitize(event) + "\n\n"
        # Flush any remaining data
        if buffer:
            yield sanitizer.desanitize(buffer)


# ---------------------------------------------------------------------------
# Main proxy — /v1/messages
# ---------------------------------------------------------------------------

@app.post("/v1/messages")
async def proxy_messages(
    request: Request,
    x_api_key: Optional[str] = Header(None),
    x_session_id: Optional[str] = Header(None),
    anthropic_version: Optional[str] = Header(None),
    anthropic_beta: Optional[str] = Header(None),
):
    # --- API key resolution ---
    api_key = x_api_key or ANTHROPIC_API_KEY
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="No API key provided. Set ANTHROPIC_API_KEY in .env or pass x-api-key header.",
        )

    # --- Session ---
    session_id = x_session_id or str(uuid.uuid4())
    sanitizer = _get_session(session_id)

    # --- Sanitize request body ---
    body = await request.json()
    clean_body = sanitizer.sanitize_request(body)

    # --- Build upstream headers ---
    upstream_headers = {
        "x-api-key": api_key,
        "anthropic-version": anthropic_version or "2023-06-01",
        "content-type": "application/json",
    }
    if anthropic_beta:
        upstream_headers["anthropic-beta"] = anthropic_beta

    target_url = f"{CLAUDE_BASE_URL}/v1/messages"
    streaming = body.get("stream", False)

    if streaming:
        # The streaming generator owns its own httpx client.
        return StreamingResponse(
            _stream_desanitized(target_url, clean_body, upstream_headers, sanitizer),
            media_type="text/event-stream",
            headers={"x-session-id": session_id},
        )

    # Non-streaming
    async with _httpx_client() as client:
        resp = await client.post(target_url, json=clean_body, headers=upstream_headers)
        response_data = resp.json()
        desanitized = sanitizer.desanitize_response(response_data)

        return JSONResponse(
            content=desanitized,
            status_code=resp.status_code,
            headers={"x-session-id": session_id},
        )


# ---------------------------------------------------------------------------
# /v1/messages/count_tokens — sanitize so the count matches what we'd send
# ---------------------------------------------------------------------------

@app.post("/v1/messages/count_tokens")
async def proxy_count_tokens(
    request: Request,
    x_api_key: Optional[str] = Header(None),
    x_session_id: Optional[str] = Header(None),
    anthropic_version: Optional[str] = Header(None),
    anthropic_beta: Optional[str] = Header(None),
):
    api_key = x_api_key or ANTHROPIC_API_KEY
    if not api_key:
        raise HTTPException(status_code=401, detail="No API key provided.")

    session_id = x_session_id or str(uuid.uuid4())
    sanitizer = _get_session(session_id)

    body = await request.json()
    clean_body = sanitizer.sanitize_request(body)

    upstream_headers = {
        "x-api-key": api_key,
        "anthropic-version": anthropic_version or "2023-06-01",
        "content-type": "application/json",
    }
    if anthropic_beta:
        upstream_headers["anthropic-beta"] = anthropic_beta

    async with _httpx_client(timeout=60.0) as client:
        resp = await client.post(
            f"{CLAUDE_BASE_URL}/v1/messages/count_tokens",
            json=clean_body,
            headers=upstream_headers,
        )
        return JSONResponse(
            content=resp.json(),
            status_code=resp.status_code,
            headers={"x-session-id": session_id},
        )


# ---------------------------------------------------------------------------
# Catch-all proxy — forwards anything else to api.anthropic.com unchanged.
# Lets the Claude Code CLI and the official SDKs exercise the full API
# surface (models, organizations, files, batches, …) without breaking the
# routes that do require sanitization.
# ---------------------------------------------------------------------------

# Headers we never forward — they belong to the hop, not the request.
_HOP_BY_HOP = {
    "host", "content-length", "connection", "transfer-encoding",
    "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailers", "upgrade", "accept-encoding",
}


@app.api_route(
    "/v1/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def passthrough(request: Request, path: str):
    """Forward unhandled /v1/* requests to Claude unchanged."""
    target_url = f"{CLAUDE_BASE_URL}/v1/{path}"

    # Reconstruct upstream headers, injecting our API key if the caller
    # didn't provide one. We strip hop-by-hop headers so httpx can set its
    # own.
    incoming = {k.lower(): v for k, v in request.headers.items()}
    upstream_headers = {
        k: v for k, v in incoming.items() if k not in _HOP_BY_HOP
    }
    if "x-api-key" not in upstream_headers and ANTHROPIC_API_KEY:
        upstream_headers["x-api-key"] = ANTHROPIC_API_KEY
    upstream_headers.setdefault("anthropic-version", "2023-06-01")

    body_bytes = await request.body()

    async with _httpx_client() as client:
        resp = await client.request(
            method=request.method,
            url=target_url,
            content=body_bytes if body_bytes else None,
            params=request.query_params,
            headers=upstream_headers,
        )

    # Strip hop-by-hop response headers, keep everything else verbatim.
    response_headers = {
        k: v for k, v in resp.headers.items() if k.lower() not in _HOP_BY_HOP
    }
    return JSONResponse(
        content=resp.json() if resp.headers.get("content-type", "").startswith("application/json") else None,
        status_code=resp.status_code,
        headers=response_headers,
    ) if resp.headers.get("content-type", "").startswith("application/json") else \
        StreamingResponse(
            iter([resp.content]),
            status_code=resp.status_code,
            headers=response_headers,
            media_type=resp.headers.get("content-type"),
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)
