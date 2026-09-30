"""Refuse an oversized request body before anything reads it into Python.

Every endpoint here declares its body as a parameter and the caller as a dependency:

    def parse(body: ParseBody, principal: Principal = Depends(require_principal)):

FastAPI has to materialize every parameter before it can call that function, so the body
is read and parsed BEFORE ``require_principal`` can refuse the caller. The caller gets
their 401 and the memory has already been spent. Measured locally: a rejected 24MB body
still cost 120MB of resident memory, because JSON text expands several times over as
Python objects.

Nothing inside an endpoint can fix that -- by the time the function runs, the bytes are
already objects. This is therefore pure ASGI middleware, wrapping ``receive`` so the
decision happens against the raw stream:

* a declared Content-Length above the limit is refused without pulling a single byte;
* a body with no declared length (chunked) is counted as it arrives and cut off once it
  passes the limit, so the framing cannot be used to dodge the check.

Two details are load-bearing and were both measured:

**The drain is bounded by a clock, not just by bytes.** The browser reaches this API only
through the Next proxy, which truncates a proxied body at its own limit while still
forwarding the caller's original Content-Length. Waiting for the rest of a body that will
never arrive pins a connection here and a socket there for the proxy's full timeout --
turning a bounded memory problem into a cheaper connection-exhaustion one.

**No explicit ``Connection: close``.** uvicorn already closes when the request asked it to,
which is always true through the proxy. Forcing it here makes uvicorn close the transport
immediately instead of draining, which turns a clean 413 into a reset the caller reads as
a network fault rather than an answer.

This bounds the cost of ONE request. It does not bound how many arrive at once -- that is
``--limit-concurrency`` in scripts/serve.sh and the concurrency block in fly.toml, which
belong to the same defence and were sized together.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable

from .dataset_imports import MAX_UPLOAD_BYTES

logger = logging.getLogger(__name__)

# 256 KiB. The largest body any endpoint legitimately receives is an annotations PUT, and
# that is bounded server-side by experiment_metadata.NOTE_TEXT_MAX (8,000 characters) plus
# ten short tags -- about 100KB once every character is JSON-escaped at its worst. The
# margin is therefore roughly 2.6x over a limit the server itself enforces, so it cannot
# quietly grow into the ceiling.
#
# Sized down from 1 MiB deliberately: JSON was measured expanding up to 13x into Python
# objects, and /parse holds the interpreter for about 0.3s per megabyte, so every extra
# megabyte allowed here is bought several times over in memory and once in blocked CPU.
MAX_REQUEST_BODY_BYTES = 256 * 1024

# Exactly one route legitimately sends more: the CSV import, which is the product's
# headline feature. Matched on method AND exact path -- other JSON routes live under the
# same prefix, and a prefix rule would hand them the upload allowance.
_ROUTE_LIMITS: dict[tuple[str, str], int] = {
    ("POST", "/dataset-imports"): MAX_UPLOAD_BYTES,
}

# How long to keep accepting bytes we intend to throw away, so that a caller who is
# genuinely mid-upload gets a real answer instead of a reset. Beyond this the request is
# answered anyway; the proxy in front may have stopped sending long ago.
_DRAIN_SECONDS = 0.5
_DRAIN_BYTES = 4 * 1024 * 1024

Message = dict
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


def _limit_for(scope: dict) -> int:
    return _ROUTE_LIMITS.get(
        (scope.get("method", ""), scope.get("path", "")), MAX_REQUEST_BODY_BYTES)


def _declared_length(scope: dict) -> int | None:
    for name, value in scope.get("headers", []):
        if name.lower() == b"content-length":
            try:
                return int(value)
            except ValueError:
                # h11 rejects a malformed Content-Length before ASGI, so this is
                # unreachable over a socket; treat it as unusable rather than as zero.
                return None
    return None


async def _send_refusal(send: Send, limit: int) -> None:
    body = json.dumps({"detail": {
        "code": "REQUEST_BODY_TOO_LARGE",
        "message": (
            f"This request body is larger than the {limit // 1024} KB this endpoint "
            f"accepts. Import a CSV through the Data workspace if you meant to send a "
            f"dataset."
        ),
    }}).encode()
    await send({
        "type": "http.response.start",
        "status": 413,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"cache-control", b"private, no-store"),
        ],
    })
    await send({"type": "http.response.body", "body": body})


async def _drain(receive: Receive) -> None:
    """Absorb what is left of a refused body, bounded by both bytes and a clock."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _DRAIN_SECONDS
    absorbed = 0
    while absorbed < _DRAIN_BYTES:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return
        try:
            message = await asyncio.wait_for(receive(), timeout=remaining)
        except (TimeoutError, asyncio.TimeoutError):
            return
        if message["type"] != "http.request":
            return
        absorbed += len(message.get("body", b""))
        if not message.get("more_body", False):
            return


class RequestBodyLimit:
    """ASGI middleware capping the request body, before routing and before auth."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope: dict, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = _limit_for(scope)
        declared = _declared_length(scope)
        if declared is not None and declared > limit:
            # The cheapest possible refusal: the body is never pulled into Python.
            logger.info("refused oversized body path=%s declared=%d limit=%d",
                        scope.get("path"), declared, limit)
            await _send_refusal(send, limit)
            return

        state = {"seen": 0, "refused": False}

        async def guarded_receive() -> Message:
            message = await receive()
            if message.get("type") == "http.request":
                state["seen"] += len(message.get("body", b""))
                if state["seen"] > limit:
                    # Tell the application the caller is gone. It unwinds promptly, and
                    # everything it tries to say is discarded in favour of the refusal.
                    state["refused"] = True
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Message) -> None:
            if state["refused"]:
                return
            await send(message)

        await self.app(scope, guarded_receive, guarded_send)

        if state["refused"]:
            logger.info("refused oversized body path=%s streamed=%d limit=%d",
                        scope.get("path"), state["seen"], limit)
            await _drain(receive)
            await _send_refusal(send, limit)
