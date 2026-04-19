"""Tests for async hook DB session handling.

Async hooks dispatched via loop.create_task() run after the caller's
`with SessionLocal.begin() as db:` block has already exited. Any db.execute()
call inside the hook triggers SQLAlchemy autobegin, re-acquiring a pool
connection with nothing to release it — exhausting the pool under load.
"""

import asyncio
import contextlib
import logging

import pytest
import sqlalchemy.exc
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

import empire.server.core.hooks as hooks_module
from empire.server.core.db.base import engine as original_engine
from empire.server.core.hooks import _run_async_hook
from empire.server.core.hooks import hooks as hooks_instance

HOOK_NAME = "test_async_hook_db_session"


@contextlib.contextmanager
def _registered_hook(event, hook):
    hooks_instance.register_hook(event, HOOK_NAME, hook)
    try:
        yield
    finally:
        hooks_instance.unregister_hook(HOOK_NAME, event)


@pytest.fixture
def constrained_engine():
    connect_args = (
        {"check_same_thread": False} if "sqlite" in str(original_engine.url) else {}
    )
    engine = create_engine(
        original_engine.url,
        pool_size=1,
        max_overflow=0,
        pool_timeout=1,
        connect_args=connect_args,
    )
    yield engine
    engine.dispose()


def test_stale_session_holds_connection_during_slow_hook(
    models, agent, session_local, constrained_engine
):
    """Direct invocation: a stale session holds its pool connection for the
    full duration of a slow await — the production failure mode.

    When an async hook calls db.execute() on a stale (post-commit) session,
    SQLAlchemy autobegin re-acquires a connection that nothing will release.
    Any concurrent caller trying to get a connection times out.
    """
    CS = sessionmaker(bind=constrained_engine)

    with CS.begin() as db:
        agent_obj = db.query(models.Agent).filter_by(session_id=agent).first()
        assert agent_obj is not None
        db.expunge(agent_obj)

    stale_db = CS()
    pool_exhausted = False

    async def slow_operation():
        nonlocal pool_exhausted
        try:
            with CS.begin() as probe:
                probe.execute(text("SELECT 1"))
        except sqlalchemy.exc.TimeoutError:
            pool_exhausted = True

    async def hook_with_slow_io(db, agent):
        db.execute(text("SELECT 1"))  # autobegin → connection held
        await slow_operation()  # probe fires while connection is still held

    try:
        asyncio.run(hook_with_slow_io(stale_db, agent_obj))
    finally:
        stale_db.close()

    assert pool_exhausted, (
        "Pool should be exhausted while the hook is suspended — stale_db "
        "holds the connection via autobegin during the slow await."
    )


def test_create_task_path_hook_receives_fresh_session(
    models, agent, session_local, constrained_engine, monkeypatch
):
    """Via run_hooks with a running event loop: the hook receives a fresh
    session, not the caller's stale session.

    _run_async_hook must open its own SessionLocal session so the hook never
    uses the caller's (potentially stale) session, which would re-acquire a
    pool connection with no scoped cleanup.
    """
    CS = sessionmaker(bind=constrained_engine)
    monkeypatch.setattr(hooks_module, "SessionLocal", CS)

    with CS.begin() as db:
        agent_obj = db.query(models.Agent).filter_by(session_id=agent).first()
        assert agent_obj is not None
        db.expunge(agent_obj)

    hook_session_id = None
    caller_session_id = None

    async def _run():
        nonlocal hook_session_id, caller_session_id

        async def _hook(db, agent):
            nonlocal hook_session_id
            hook_session_id = id(db)

        with _registered_hook(hooks_instance.AFTER_AGENT_CHECKIN_HOOK, _hook):
            caller_db = CS()
            nonlocal caller_session_id
            caller_session_id = id(caller_db)
            try:
                hooks_instance.run_hooks(
                    hooks_instance.AFTER_AGENT_CHECKIN_HOOK, caller_db, agent_obj
                )
            finally:
                caller_db.close()
            await asyncio.sleep(0)
            await asyncio.sleep(0)

    asyncio.run(_run())

    assert hook_session_id is not None, "Hook did not run"
    assert hook_session_id != caller_session_id, (
        "Hook must receive a fresh session, not the caller's session"
    )


def test_asyncio_run_path_releases_connection(
    models, agent, session_local, constrained_engine, monkeypatch
):
    """Sync context (no running event loop): asyncio.run() path uses a fresh
    session and releases its connection before returning.

    When run_hooks is called from a synchronous context, it falls back to
    asyncio.run(). The fresh session must be closed before asyncio.run()
    returns so the pool is available for subsequent callers.
    """
    CS = sessionmaker(bind=constrained_engine)
    monkeypatch.setattr(hooks_module, "SessionLocal", CS)

    with CS.begin() as db:
        agent_obj = db.query(models.Agent).filter_by(session_id=agent).first()
        assert agent_obj is not None
        db.expunge(agent_obj)

    async def _async_hook(db, agent):
        db.execute(text("SELECT 1"))

    with _registered_hook(hooks_instance.AFTER_AGENT_CHECKIN_HOOK, _async_hook):
        caller_db = CS()
        try:
            hooks_instance.run_hooks(
                hooks_instance.AFTER_AGENT_CHECKIN_HOOK, caller_db, agent_obj
            )
        finally:
            caller_db.close()

        # asyncio.run() blocks until complete — pool should be free now
        probe_succeeded = False
        try:
            with CS.begin() as probe:
                probe.execute(text("SELECT 1"))
                probe_succeeded = True
        except sqlalchemy.exc.TimeoutError:
            pass

    assert probe_succeeded, (
        "Pool should be free after asyncio.run() path completes — "
        "_run_async_hook must close the fresh session before returning."
    )


def test_run_async_hook_without_session_passes_args_unchanged(session_local):
    """When args[0] is not a Session, all args are forwarded to the hook unchanged."""
    received = []

    async def _run():
        async def _hook(x, y):
            received.extend([x, y])

        await _run_async_hook(_hook, "string-arg", 42)

    asyncio.run(_run())
    assert received == ["string-arg", 42]


def test_async_hook_exception_is_logged_via_done_callback(
    models, agent, session_local, constrained_engine, monkeypatch, caplog
):
    """Via create_task path: exceptions from hooks are logged by _log_task_exception.

    Exceptions raised inside loop.create_task() do not propagate to run_hooks'
    try/except. The done callback must catch and log them so failures are visible.
    """
    CS = sessionmaker(bind=constrained_engine)
    monkeypatch.setattr(hooks_module, "SessionLocal", CS)

    with CS.begin() as db:
        agent_obj = db.query(models.Agent).filter_by(session_id=agent).first()
        assert agent_obj is not None
        db.expunge(agent_obj)

    async def _run():
        async def _failing_hook(db, agent):
            raise ValueError("hook boom")

        with _registered_hook(hooks_instance.AFTER_AGENT_CHECKIN_HOOK, _failing_hook):
            caller_db = CS()
            try:
                hooks_instance.run_hooks(
                    hooks_instance.AFTER_AGENT_CHECKIN_HOOK, caller_db, agent_obj
                )
                await asyncio.sleep(0)  # let the create_task task complete
            finally:
                caller_db.close()

    with caplog.at_level(logging.ERROR, logger="empire.server.core.hooks"):
        asyncio.run(_run())

    assert any("hook boom" in r.message for r in caplog.records), (
        "Exception message from the async hook should appear in error logs "
        "via the _log_task_exception done callback."
    )
