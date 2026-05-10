"""Request body size limiting middleware."""

from collections.abc import Iterable

from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestBodyTooLargeError(Exception):
    """Raised when an incoming request body exceeds the configured cap."""


class RequestBodyLimitMiddleware:
    """Reject HTTP request bodies over a configured byte limit."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int,
        paths: Iterable[str] | None = None,
    ) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.paths = frozenset(paths) if paths is not None else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self._applies_to_path(scope):
            await self.app(scope, receive, send)
            return

        if self._content_length_exceeds_limit(scope):
            await self._send_too_large(scope, send)
            return

        response_started = False

        async def send_with_tracking(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        receive_with_limit = self._limited_receive(receive)
        try:
            await self.app(scope, receive_with_limit, send_with_tracking)
        except RequestBodyTooLargeError:
            if response_started:
                raise
            await self._send_too_large(scope, send)

    def _applies_to_path(self, scope: Scope) -> bool:
        if self.paths is None:
            return True
        return str(scope.get("path", "")) in self.paths

    def _content_length_exceeds_limit(self, scope: Scope) -> bool:
        for name, value in scope["headers"]:
            if name.lower() != b"content-length":
                continue
            try:
                return int(value) > self.max_body_bytes
            except ValueError:
                return False
        return False

    def _limited_receive(self, receive: Receive) -> Receive:
        total_bytes = 0

        async def receive_with_limit() -> Message:
            nonlocal total_bytes
            message = await receive()
            if message["type"] == "http.request":
                total_bytes += len(message.get("body", b""))
                if total_bytes > self.max_body_bytes:
                    raise RequestBodyTooLargeError
            return message

        return receive_with_limit

    async def _send_too_large(self, scope: Scope, send: Send) -> None:
        response = PlainTextResponse("Request body too large", status_code=413)
        await response(scope, self._empty_receive, send)

    async def _empty_receive(self) -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}
