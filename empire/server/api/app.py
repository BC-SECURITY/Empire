import json
import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime
from json import JSONEncoder

import socketio
import urllib3
from fastapi import FastAPI
from fastapi.routing import APIRoute
from starlette.middleware.gzip import GZipMiddleware
from starlette.routing import WebSocketRoute

from empire.server.api.middleware import EmpireCORSMiddleware
from empire.server.api.v2.admin import admin_api
from empire.server.api.v2.agent import agent_api, agent_file_api, agent_task_api
from empire.server.api.v2.bypass import bypass_api
from empire.server.api.v2.credential import credential_api
from empire.server.api.v2.download import download_api
from empire.server.api.v2.health import health_api
from empire.server.api.v2.host import host_api, process_api
from empire.server.api.v2.ip import ip_api
from empire.server.api.v2.listener import listener_api, listener_template_api
from empire.server.api.v2.meta import meta_api
from empire.server.api.v2.module import module_api
from empire.server.api.v2.obfuscation import obfuscation_api
from empire.server.api.v2.plugin import plugin_api, plugin_registry_api, plugin_task_api
from empire.server.api.v2.profile import profile_api
from empire.server.api.v2.stager import stager_api, stager_template_api
from empire.server.api.v2.tag import tag_api
from empire.server.api.v2.user import user_api
from empire.server.api.v2.websocket.socketio import setup_socket_events
from empire.server.common import empire
from empire.server.core.config.config_manager import empire_config
from empire.server.core.config.data_manager import (
    resolve_starkiller_dist,
    starkiller_directory_problem,
    sync_starkiller,
)
from empire.server.core.db import base

log = logging.getLogger(__name__)


_NON_ALNUM = re.compile(r"[^a-zA-Z0-9]+")


def custom_generate_unique_id(route: APIRoute) -> str:
    """Name each operation `{tag}_{route name}` so generated clients read well.

    FastAPI's default appends the path and method, which yields names like
    `read_agent_api_v2_agents__uid__get`. A route name defaults to its endpoint
    function's name, so routers that mount a shared endpoint under one tag give
    it a distinct `name=` rather than an explicit operation id -- that keeps the
    `{tag}_` prefix true by construction.

    The one-tag-per-route convention that makes `tags[0]` lossless is enforced
    by test_openapi, not here.

    Hyphenated tags (`listener-templates`) are folded to underscores: client
    generators have to mangle anything that is not a valid identifier, and each
    one mangles differently. `string_util.slugify` is not reused for that --
    its character class does not cover every punctuation character, so a tag
    could slip through and produce an unusable id. The tag and the name are
    folded separately so that a tag ending in punctuation still leaves a
    literal `{tag}_` prefix rather than collapsing the separator into it.

    FastAPI hands this an internal per-route object, not the `APIRoute` the
    annotation claims; it carries the route's resolved state, so `path` is
    prefixed and `tags` are merged with the router's.
    """
    if not route.tags:
        # Ids are built lazily: when the schema is served, and when a request
        # walks the route table far enough to reach this route. So an untagged
        # route registers fine and then breaks the schema plus every route
        # registered after it, and every 404. That blast radius is the same
        # without this guard -- `tags[0]` raises there instead -- but as a bare
        # `IndexError: list index out of range` naming neither the route that
        # is at fault nor the reason, while the request that surfaces it is
        # usually for some other route entirely.
        raise ValueError(
            f"{route.path} declares no tag, so it cannot be given an operation id"
        )
    tag = _NON_ALNUM.sub("_", str(route.tags[0]))
    return f"{tag}_{_NON_ALNUM.sub('_', route.name)}"


class MyJsonWrapper:
    @staticmethod
    def dumps(*args, **kwargs):
        if "cls" not in kwargs:
            kwargs["cls"] = MyJsonEncoder
        return json.dumps(*args, **kwargs)

    @staticmethod
    def loads(*args, **kwargs):
        return json.loads(*args, **kwargs)


class MyJsonEncoder(JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, bytes):
            return o.decode("latin-1")
        if hasattr(o, "json") and callable(o.json):
            return o.json()

        return JSONEncoder.default(self, o)


def load_starkiller(app, port):
    try:
        starkiller_dir = sync_starkiller(empire_config.starkiller)
    except Exception as e:
        log.warning("Failed to load Starkiller: %s", e, exc_info=True)
        if not empire_config.starkiller.directory:
            # Only the clone path can fail on credentials; under a directory
            # override nothing was fetched, so this advice would misdirect.
            log.warning(
                "If you are trying to pull Starkiller from a private repository ("
                "such as Starkiller-Sponsors), make sure you have the proper ssh "
                "credentials set in your Empire config. See "
                "https://docs.github.com/en/github/authenticating-to-github"
                "/connecting-to-github-with-ssh"
            )
        return

    dist_dir = resolve_starkiller_dist(starkiller_dir)
    if dist_dir is None:
        hint = "Run a Starkiller build first."
        if empire_config.starkiller.directory:
            hint = starkiller_directory_problem(starkiller_dir) or hint
        log.warning(
            "No Starkiller build found under '%s'. The UI will not be available. %s",
            starkiller_dir,
            hint,
        )
        return

    app.frontend("/", directory=dist_dir)

    log.info("Starkiller served at the same ip and port as Empire Server")
    log.info(f"Starkiller served at http://localhost:{port}/")


def create_app() -> FastAPI:  # noqa: PLR0915
    """Build the FastAPI app without running the server.

    The ASGI entrypoint (empire/server/asgi.py) calls this; see it for how to run.
    """
    cors_origins = empire_config.api.cors_origins

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup: module import stays cheap; DB + MainMenu init happens here,
        # not at import time, so the ASGI app can be imported before DB startup.
        if empire_config.suppress_self_cert_warning:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Startup runs inside the try so a failure partway through (e.g. after
        # MainMenu is built but before serving) still hits the finally and
        # tears down whatever was started, rather than leaking listeners.
        try:
            base.startup_db()

            # A fresh app is built per create_app() and its lifespan runs once,
            # so this startup work always runs against clean state — no re-entry
            # guards.
            app.state.main = empire.MainMenu()

            if app.state.sio:
                setup_socket_events(app.state.sio, app.state.main)

            if empire_config.starkiller.enabled:
                log.info("Starkiller enabled. Loading.")
                load_starkiller(app, empire_config.api.port)
            else:
                log.info("Starkiller disabled. Not loading.")

            yield
        finally:
            # Shutdown — guard each step so one failure doesn't skip the rest
            if app.state.main:
                try:
                    app.state.main.shutdown()
                except Exception:
                    # A failed MainMenu shutdown can leave listeners/plugins and
                    # their bound ports orphaned, so surface it at error level.
                    log.error("Error during Empire shutdown", exc_info=True)

            if app.state.sio:
                try:
                    log.info("Shutting down SocketIO...")
                    await app.state.sio.shutdown()
                except Exception:
                    log.warning("Error during SocketIO shutdown", exc_info=True)

    app = FastAPI(
        lifespan=lifespan, generate_unique_id_function=custom_generate_unique_id
    )

    app.include_router(admin_api.router)
    app.include_router(agent_file_api.router)
    app.include_router(agent_task_api.router)
    app.include_router(agent_api.router)
    app.include_router(bypass_api.router)
    app.include_router(credential_api.router)
    app.include_router(download_api.router)
    app.include_router(health_api.router)
    app.include_router(host_api.router)
    app.include_router(ip_api.router)
    app.include_router(listener_api.router)
    app.include_router(listener_template_api.router)
    app.include_router(meta_api.router)
    app.include_router(module_api.router)
    app.include_router(obfuscation_api.router)
    app.include_router(plugin_registry_api.router)
    app.include_router(plugin_task_api.router)
    app.include_router(plugin_api.router)
    app.include_router(process_api.router)
    app.include_router(profile_api.router)
    app.include_router(stager_api.router)
    app.include_router(stager_template_api.router)
    app.include_router(tag_api.router)
    app.include_router(user_api.router)

    app.add_middleware(
        EmpireCORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["content-disposition"],
    )

    app.add_middleware(GZipMiddleware, minimum_size=500)

    sio = None
    if empire_config.server.socketio:
        sio = socketio.AsyncServer(
            async_mode="asgi",
            cors_allowed_origins=cors_origins,
            json=MyJsonWrapper,
        )
        sio_app = socketio.ASGIApp(
            socketio_server=sio, other_asgi_app=app, socketio_path="/socket.io/"
        )

        app.add_route("/socket.io/", route=sio_app, methods=["GET", "POST"])
        app.router.routes.append(WebSocketRoute("/socket.io/", sio_app))
    else:
        log.info("Socket.IO disabled via server.socketio config.")

    # Initialize state up front so the lifespan and request dependencies can use
    # plain attribute access. main stays None until the lifespan populates it,
    # which is the window get_main() guards with a 503.
    app.state.sio = sio
    app.state.main = None

    return app
