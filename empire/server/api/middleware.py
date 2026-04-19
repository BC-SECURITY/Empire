import typing

from starlette.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send


class EmpireCORSMiddleware(CORSMiddleware):
    """
    This is required to stop the middleware from breaking socket.io requests.
    """

    def __init__(
        self,
        app: ASGIApp,
        allow_origins: typing.Sequence[str] = (),
        allow_methods: typing.Sequence[str] = ("GET",),
        allow_headers: typing.Sequence[str] = (),
        allow_credentials: bool = False,
        allow_origin_regex: str | None = None,
        allow_private_network: bool = False,
        expose_headers: typing.Sequence[str] = (),
        max_age: int = 600,
    ) -> None:
        super().__init__(
            app,
            allow_origins=allow_origins,
            allow_methods=allow_methods,
            allow_headers=allow_headers,
            allow_credentials=allow_credentials,
            allow_origin_regex=allow_origin_regex,
            allow_private_network=allow_private_network,
            expose_headers=expose_headers,
            max_age=max_age,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not scope.get("path", "").startswith("/socket.io"):
            await super().__call__(scope, receive, send)
            return

        await self.app(scope, receive, send)
        return
