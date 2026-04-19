import asyncio
import logging
from collections.abc import Callable

from sqlalchemy.orm import Session

from empire.server.core.db.base import SessionLocal

log = logging.getLogger(__name__)


def _log_task_exception(task: asyncio.Task, hook: Callable, event: str) -> None:
    """Log exceptions from fire-and-forget async hook tasks.

    Exceptions raised inside loop.create_task() are not caught by the
    try/except in run_hooks because the task runs after run_hooks returns.
    This callback ensures they are logged immediately when the task finishes.
    """
    try:
        task.result()
    except asyncio.CancelledError:
        log.debug("Async hook %s for event '%s' was cancelled", hook, event)
    except Exception as exc:
        log.error(
            "Async hook %s failed for event '%s': %s",
            hook,
            event,
            exc,
            exc_info=True,
        )


async def _run_async_hook(hook: Callable, *args) -> None:
    """Run an async hook with a fresh, properly scoped DB session.

    Async hooks are dispatched via loop.create_task(), which means they run
    after the caller's `with SessionLocal.begin() as db:` block has already
    exited. Passing the caller's session directly is unsafe: any db.query()
    call inside the hook triggers SQLAlchemy autobegin, re-acquiring a pool
    connection with no code to release it — exhausting the pool under load.

    Opens a fresh SessionLocal session, merges any ORM objects from the
    caller's args into it, and calls the hook. The session commits and closes
    when the hook returns.

    Uses load=False on merge to skip the SELECT lookup. Without load=False,
    merge issues a SELECT for each ORM object; if the outer transaction has
    flushed but not yet committed the row, the SELECT finds nothing and marks
    the object as pending (new). On commit, SQLAlchemy tries to INSERT the
    row, hitting a 50-second MySQL lock wait on the uncommitted PK.

    If args[0] is not a Session, args are forwarded unchanged.
    """
    if args and isinstance(args[0], Session):
        rest = args[1:]
        with SessionLocal.begin() as db:
            merged = [
                db.merge(arg, load=False) if hasattr(arg, "__mapper__") else arg
                for arg in rest
            ]
            await hook(db, *merged)
    else:
        await hook(*args)


class Hooks:
    """
    Hooks are currently a *Beta feature*. The methods, event names, and callback arguments are subject to change until
    it is not a beta feature.

    Add a hook to an event to do some task when an event happens.
    Potential future addition: Filters. Add a filter to an event to do some synchronous modification to the data.
    """

    # This event is triggered after the creation of a listener.
    # Its arguments are (db: Session, listener: models.Listener)
    AFTER_LISTENER_CREATED_HOOK = "after_listener_created_hook"

    # This event is triggered after the tasking is written to the database.
    # Its arguments are (db: Session, tasking: models.Tasking)
    AFTER_TASKING_HOOK = "after_tasking_hook"

    # This event is triggered after the tasking results are received but before they are written to the database.
    # Its arguments are (db: Session, tasking: models.Tasking) where tasking is the db record.
    BEFORE_TASKING_RESULT_HOOK = "before_tasking_result_hook"

    BEFORE_TASKING_RESULT_FILTER = "before_tasking_result_filter"

    # This event is triggered after the tasking results are received and after they are written to the database.
    # Its arguments are (db: Session, tasking: models.Tasking) where tasking is the db record.
    AFTER_TASKING_RESULT_HOOK = "after_tasking_result_hook"

    # This event is triggered after the agent has completed the stage2 of the checkin process,
    # and the sysinfo has been written to the database.
    # Its arguments are (db: Session, agent: models.Agent)
    AFTER_AGENT_CHECKIN_HOOK = "after_agent_checkin_hook"

    # This event is triggered each time an agent calls back to the server.
    # Its arguments are (db: Session, agent_id: str)
    AFTER_AGENT_CALLBACK_HOOK = "after_agent_callback_hook"

    # This event is triggered after a tag is created.
    # Its arguments are (db: Session, tag: models.Tag, taggable: Union[models.Agent, models.Listener, etc])
    AFTER_TAG_CREATED_HOOK = "after_tag_created_hook"

    # This event is triggered after a tag is updated.
    # Its arguments are (db: Session, tag: models.Tag, taggable: Union[models.Agent, models.Listener, etc])
    AFTER_TAG_UPDATED_HOOK = "after_tag_updated_hook"

    def __init__(self):
        self.hooks: dict[str, dict[str, Callable]] = {}
        self.filters: dict[str, dict[str, Callable]] = {}

    def register_hook(self, event: str, name: str, hook: Callable):
        """
        Register a hook for a hook type.
        """
        if event not in self.hooks:
            self.hooks[event] = {}
        self.hooks[event][name] = hook

    def register_filter(self, event: str, name: str, filter: Callable):
        """
        Register a filter for a hook type.
        """
        if event not in self.filters:
            self.filters[event] = {}
        self.filters[event][name] = filter

    def unregister_hook(self, name: str, event: str | None = None):
        """
        Unregister a hook.
        """
        if event is None:
            for ev in self.hooks:
                self.hooks[ev].pop(name)
            return
        if name in self.hooks.get(event, {}):
            self.hooks[event].pop(name)

    def unregister_filter(self, name: str, event: str | None = None):
        """
        Unregister a filter.
        """
        if event is None:
            for ev in self.filters:
                self.filters[ev].pop(name)
            return
        if name in self.filters.get(event, {}):
            self.filters[event].pop(name)

    def run_hooks(self, event: str, *args):
        """
        Run all hooks for a hook type.
        This could be updated to run each hook async.
        """
        if event not in self.hooks:
            return
        for hook in self.hooks.get(event, {}).values():
            try:
                if asyncio.iscoroutinefunction(hook):
                    try:  # https://stackoverflow.com/a/61331974/
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        loop = None

                    if loop and loop.is_running():
                        # Exceptions from the scheduled task are NOT caught by
                        # the surrounding try/except — they run after run_hooks
                        # returns. The done callback handles error logging.
                        task = loop.create_task(_run_async_hook(hook, *args))
                        task.add_done_callback(
                            lambda t, h=hook, e=event: _log_task_exception(t, h, e)
                        )
                    else:
                        asyncio.run(_run_async_hook(hook, *args))
                else:
                    hook(*args)
            except Exception as e:
                log.error(f"Hook {hook} failed for event '{event}': {e}", exc_info=True)

    def run_filters(self, event: str, *args):
        """
        Run all the filters for a hook in sequence.
        The output of each filter is passed into the next filter.
        """
        if event not in self.filters:
            return None
        for filter in self.filters.get(event, {}).values():
            if not isinstance(args, tuple):
                args = (args,)
            try:
                args = filter(*args)
            except Exception as e:
                log.error(f"Filter {filter} failed: {e}", exc_info=True)
        return args


hooks = Hooks()
