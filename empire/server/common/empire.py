import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

from empire.server.core import hooks_internal
from empire.server.core.agent_communication_service import AgentCommunicationService
from empire.server.core.agent_file_service import AgentFileService
from empire.server.core.agent_service import AgentService
from empire.server.core.agent_socks_service import AgentSocksService
from empire.server.core.agent_task_service import AgentTaskService
from empire.server.core.bypass_service import BypassService
from empire.server.core.credential_service import CredentialService
from empire.server.core.dotnet import DotnetCompiler
from empire.server.core.download_service import DownloadService
from empire.server.core.go import GoCompiler
from empire.server.core.host_process_service import HostProcessService
from empire.server.core.host_service import HostService
from empire.server.core.ip_service import IpService
from empire.server.core.listener_service import ListenerService
from empire.server.core.listener_template_service import ListenerTemplateService
from empire.server.core.module_service import ModuleService
from empire.server.core.obfuscation_service import ObfuscationService
from empire.server.core.plugin_registry_service import PluginRegistryService
from empire.server.core.plugin_service import PluginService
from empire.server.core.plugin_task_service import PluginTaskService
from empire.server.core.profile_service import ProfileService
from empire.server.core.stager_generation_service import StagerGenerationService
from empire.server.core.stager_service import StagerService
from empire.server.core.stager_template_service import StagerTemplateService
from empire.server.core.tag_service import TagService
from empire.server.core.user_service import UserService

if TYPE_CHECKING:
    from socket import SocketIO

VERSION = "6.4.1 BC Security Fork"

log = logging.getLogger(__name__)


class MainMenu:
    def __init__(self, args=None):
        log.info("Empire starting up...")

        self.install_path = Path(os.path.realpath(__file__)).parent.parent
        # installPath is deprecated, use install_path
        self.installPath = str(self.install_path)

        self.args = args

        self.socketio: SocketIO | None = None

        self.dotnet_compiler = DotnetCompiler(self.install_path)
        self.go_compiler = GoCompiler(self.install_path)
        self.listenertemplatesv2 = ListenerTemplateService(self)
        self.stagertemplatesv2 = StagerTemplateService(self)
        self.bypassesv2 = BypassService(self)
        self.obfuscationv2 = ObfuscationService(self)
        self.profilesv2 = ProfileService(self)
        self.credentialsv2 = CredentialService(self)
        self.hostsv2 = HostService(self)
        self.processesv2 = HostProcessService(self)
        self.tagsv2 = TagService(self)
        self.downloadsv2 = DownloadService(self)
        self.usersv2 = UserService(self)
        self.listenersv2 = ListenerService(self)
        self.stagersv2 = StagerService(self)
        self.modulesv2 = ModuleService(self)
        self.agentsv2 = AgentService(self)
        self.agentsocksv2 = AgentSocksService(self)
        self.agenttasksv2 = AgentTaskService(self)
        self.ipsv2 = IpService(self)
        self.agentcommsv2 = AgentCommunicationService(self)
        self.agentfilesv2 = AgentFileService(self)
        self.pluginsv2 = PluginService(self)
        self.stagergenv2 = StagerGenerationService(self)
        self.pluginregistriesv2 = PluginRegistryService(self)
        self.plugintasksv2 = PluginTaskService(self)

        self.pluginsv2.startup()
        hooks_internal.initialize()

        self.listenersv2.start_existing_listeners()

    def shutdown(self):
        """
        Perform any shutdown actions.
        """
        log.info("Empire shutting down...")

        log.info("Shutting down listeners...")
        self.listenersv2.shutdown_listeners()

        log.info("Shutting down plugins...")
        self.pluginsv2.shutdown()
