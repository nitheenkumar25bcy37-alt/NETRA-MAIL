import asyncio

from backend.request_limits import RequestBodyLimit


def test_chunked_upload_is_bounded_before_application():
    async def run():
        called = False
        sent = []
        chunks = iter([
            {"type": "http.request", "body": b"1234", "more_body": True},
            {"type": "http.request", "body": b"5678", "more_body": False},
        ])
        async def application(scope, receive, send):
            nonlocal called
            called = True
        async def receive():
            return next(chunks)
        async def send(message):
            sent.append(message)
        await RequestBodyLimit(application, 6)({"type": "http", "method": "POST"}, receive, send)
        assert not called
        assert sent[0]["status"] == 413
    asyncio.run(run())


def test_valid_body_is_replayed_without_modification():
    async def run():
        captured = []
        async def app(scope, receive, send):
            captured.append((await receive())["body"])
        async def receive():
            return {"type": "http.request", "body": b"payload", "more_body": False}
        async def send(message):
            pass
        await RequestBodyLimit(app, 8)({"type": "http", "method": "POST"}, receive, send)
        assert captured == [b"payload"]
    asyncio.run(run())


def test_capacity_limit_rejects_before_reading_body():
    async def run():
        sent = []
        async def unexpected(*args):
            raise AssertionError("Request should not have entered processing")
        async def send(event):
            sent.append(event)
        middleware = RequestBodyLimit(unexpected, 100)
        for _ in range(8):
            assert middleware.slots.acquire(blocking=False)
        await middleware({"type": "http", "method": "POST"}, unexpected, send)
        assert sent[0]["status"] == 503
        for _ in range(8):
            middleware.slots.release()
    asyncio.run(run())
