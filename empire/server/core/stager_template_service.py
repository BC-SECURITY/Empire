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


class StagerTemplateService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu

        # loaded stager format:
        #     {"stagerModuleName": moduleInstance, ...}
        self._loaded_stager_templates = {}

        with SessionLocal.begin() as db:
            self._load_stagers(db)

    def new_instance(self, template: str):
        instance = type(self._loaded_stager_templates[template])(self.main_menu)
        for value in instance.options.values():
            if value.get("SuggestedValues") is None:
                value["SuggestedValues"] = []
            if value.get("Strict") is None:
                value["Strict"] = False
            if value.get("Internal") is None:
                value["Internal"] = False
            if value.get("Depends_on") is None:
                value["Depends_on"] = []

        return instance

    def get_stager_template(
        self, name: str
    ) -> object | None:  # would be nice to have a BaseListener object.
        return self._loaded_stager_templates.get(name)

    def get_stager_templates(self):
        return self._loaded_stager_templates

    def _load_stagers(self, db: Session):
        """
        Load stagers from the install + "/stagers/*" path
        """
        root_path = self.main_menu.install_path / "stagers"
        log.info(f"v2: Loading stager templates from: {root_path}")

        for file_path in root_path.rglob("*.py"):
            filename = file_path.name

            # don't load up any of the templates
            if fnmatch.fnmatch(filename, "*template.py"):
                continue

            # instantiate the module and save it to the internal cache
            stager_name = file_path.relative_to(root_path).with_suffix("").as_posix()
            spec = importlib.util.spec_from_file_location(stager_name, file_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            stager = mod.Stager(self.main_menu)
            for value in stager.options.values():
                if value.get("SuggestedValues") is None:
                    value["SuggestedValues"] = []
                if value.get("Strict") is None:
                    value["Strict"] = False
                if value.get("Internal") is None:
                    value["Internal"] = False
                if value.get("Depends_on") is None:
                    value["Depends_on"] = []

            self._loaded_stager_templates[slugify(stager_name)] = stager
