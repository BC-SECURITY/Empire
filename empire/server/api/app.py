import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from json import JSONEncoder

import socketio
import uvicorn
from fastapi import FastAPI
from starlette.middleware.gzip import GZipMiddleware
from starlette.staticfiles import StaticFiles

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
from empire.server.core.config.config_manager import empire_config
from empire.server.core.config.data_manager import sync_starkiller

log = logging.getLogger(__name__)


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
        log.warning(
            "If you are trying to pull Starkiller from a private repository ("
            "such as Starkiller-Sponsors), make sure you have the proper ssh "
            "credentials set in your Empire config. See "
            "https://docs.github.com/en/github/authenticating-to-github"
            "/connecting-to-github-with-ssh"
        )
        return

    app.mount(
        "/",
        StaticFiles(directory=f"{starkiller_dir!s}/dist", html=True),
        name="static",
    )

    log.info("Starkiller served at the same ip and port as Empire Server")
    log.info(f"Starkiller served at http://localhost:{port}/")


def initialize(run: bool = True, cert_path=None):  # noqa: PLR0915
    ip = empire_config.api.ip
    port = empire_config.api.port
    secure = empire_config.api.secure

    from empire.server.server import main

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        if main:
            main.shutdown()

        if sio:
            log.info("Shutting down SocketIO...")
            await sio.shutdown()

    app = FastAPI(lifespan=lifespan)

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
        allow_origins=[
            "*",
            "http://localhost",
            "http://localhost:8080",
            "http://localhost:8081",
        ],
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
            cors_allowed_origins="*",
            json=MyJsonWrapper,
        )
        sio_app = socketio.ASGIApp(
            socketio_server=sio, other_asgi_app=app, socketio_path="/socket.io/"
        )

        app.add_route("/socket.io/", route=sio_app, methods=["GET", "POST"])
        app.add_websocket_route("/socket.io/", sio_app)

        setup_socket_events(sio, main)
    else:
        log.info("Socket.IO disabled via server.socketio config.")

    if empire_config.starkiller.enabled:
        log.info("Starkiller enabled. Loading.")
        load_starkiller(app, port)
    else:
        log.info("Starkiller disabled. Not loading.")

    if run:
        if secure and cert_path:
            uvicorn.run(
                app,
                host=ip,
                port=port,
                log_config=None,
                lifespan="on",
                ssl_keyfile=f"{cert_path}/empire-priv.key",
                ssl_certfile=f"{cert_path}/empire-chain.pem",
            )
        else:
            uvicorn.run(
                app,
                host=ip,
                port=port,
                log_config=None,
                lifespan="on",
            )

    return app
