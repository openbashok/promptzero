"""
main.py — Transparent Claude API proxy with PII/sensitive-data sanitization.

Drop-in replacement for https://api.anthropic.com — just point your SDK or
HTTP client to http://localhost:8000 instead.

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-warm the NLP engine at startup so the first request isn't slow
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _get_analyzer)
    yield


app = FastAPI(
    title="api-pii",
    description="Transparent Claude API proxy — sanitizes PII/sensitive data before it leaves your environment.",
    version="0.2.0",
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
    return {"status": "ok", "active_sessions": len(_sessions), "nlp_enabled": nlp_available()}


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
    client: httpx.AsyncClient,
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
    """
    buffer = ""
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

    async with httpx.AsyncClient(timeout=120.0) as client:
        if streaming:
            return StreamingResponse(
                _stream_desanitized(client, target_url, clean_body, upstream_headers, sanitizer),
                media_type="text/event-stream",
                headers={"x-session-id": session_id},
            )

        # Non-streaming
        resp = await client.post(target_url, json=clean_body, headers=upstream_headers)
        response_data = resp.json()
        desanitized = sanitizer.desanitize_response(response_data)

        return JSONResponse(
            content=desanitized,
            status_code=resp.status_code,
            headers={"x-session-id": session_id},
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)
