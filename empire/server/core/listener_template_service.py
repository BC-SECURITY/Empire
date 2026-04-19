import fnmatch
import importlib.util
import logging
import typing

from sqlalchemy.orm import Session

from empire.server.core.db.base import SessionLocal
from empire.server.utils.string_util import slugify

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu

log = logging.getLogger(__name__)


class ListenerTemplateService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu

        # loaded listener format:
        #     {"listenerModuleName": moduleInstance, ...}
        self._loaded_listener_templates = {}

        with SessionLocal.begin() as db:
            self._load_listener_templates(db)

    def new_instance(self, template: str):
        instance = type(self._loaded_listener_templates[template])(self.main_menu)
        for value in instance.options.values():
            value.setdefault("SuggestedValues", [])
            value.setdefault("Strict", False)

        return instance

    def get_listener_template(self, name: str) -> object | None:
        return self._loaded_listener_templates.get(name)

    def get_listener_templates(self):
        return self._loaded_listener_templates

    def _load_listener_templates(self, db: Session):
        """
        Load listeners from the install + "/listeners/*" path
        """

        root_path = self.main_menu.install_path / "listeners"
        log.info(f"v2: Loading listener templates from: {root_path}")

        for file_path in root_path.rglob("*.py"):
            filename = file_path.name

            # don't load up any of the templates
            if fnmatch.fnmatch(filename, "*template.py"):
                continue

            # instantiate the listener module and save it to the internal cache
            listener_name = file_path.relative_to(root_path).with_suffix("").as_posix()
            spec = importlib.util.spec_from_file_location(listener_name, file_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            listener = mod.Listener(self.main_menu)

            for value in listener.options.values():
                value.setdefault("SuggestedValues", [])
                value.setdefault("Strict", False)
                value.setdefault("Internal", False)
                value.setdefault("Depends_on", [])

            self._loaded_listener_templates[slugify(listener_name)] = listener
