import pytest
from starlette.types import Message, Receive, Scope, Send

from dionysus.middleware.request_size import RequestBodyLimitMiddleware


@pytest.mark.anyio
async def test_request_body_limit_rejects_streaming_body_over_cap() -> None:
    response_messages: list[Message] = []
    body_messages = iter(
        [
            {"type": "http.request", "body": b"abcd", "more_body": True},
            {"type": "http.request", "body": b"efgh", "more_body": False},
        ]
    )

    async def receive() -> Message:
        return next(body_messages)

    async def send(message: Message) -> None:
        response_messages.append(message)

    async def downstream_app(scope: Scope, receive: Receive, send: Send) -> None:
        assert scope["type"] == "http"
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = RequestBodyLimitMiddleware(downstream_app, max_body_bytes=6)

    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/imports/trivy",
            "headers": [],
        },
        receive,
        send,
    )

    assert response_messages[0]["type"] == "http.response.start"
    assert response_messages[0]["status"] == 413
    assert response_messages[1]["body"] == b"Request body too large"
