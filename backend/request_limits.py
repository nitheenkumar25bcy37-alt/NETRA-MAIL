"""Bound request bodies before JSON and multipart parsers allocate memory."""
import asyncio
import time
from threading import BoundedSemaphore


class RequestBodyLimit:
    def __init__(self, app, maximum_bytes: int):
        self.app = app
        self.maximum_bytes = maximum_bytes
        self.slots = BoundedSemaphore(8)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            return await self.app(scope, receive, send)
        if not self.slots.acquire(blocking=False):
            await send({"type": "http.response.start", "status": 503, "headers": [(b"retry-after", b"2"), (b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": b'{"detail":"Processing capacity reached; retry shortly"}'})
            return
        try:
            return await self._bounded_request(scope, receive, send)
        finally:
            self.slots.release()

    async def _bounded_request(self, scope, receive, send):
        chunks = []
        total = 0
        deadline = time.monotonic() + 30
        status = None
        while True:
            try:
                event = await asyncio.wait_for(receive(), timeout=max(0.001, deadline - time.monotonic()))
            except TimeoutError:
                status = 408
                break
            if event["type"] == "http.disconnect":
                return
            chunk = event.get("body", b"")
            total += len(chunk)
            maximum = min(self.maximum_bytes, 16384) if scope.get("path") == "/api/v2/mailbox/analyze" else self.maximum_bytes
            if total > maximum:
                status = 413
                break
            chunks.append(chunk)
            if not event.get("more_body", False):
                break
        if status:
            await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": b'{"detail":"Request body exceeded size or time limit"}'})
            return
        body = b"".join(chunks)
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()
        await self.app(scope, replay, send)
