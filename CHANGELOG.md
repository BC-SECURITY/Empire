# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

-   **Added** for new features.
-   **Changed** for changes in existing functionality.
-   **Deprecated** for soon-to-be removed features.
-   **Removed** for now removed features.
-   **Fixed** for any bug fixes.
-   **Security** in case of vulnerabilities.

## [Unreleased]

### Added

-   Added Debian 13 support
-   Added error message if running `ps-empire server` under root without `-f`
-   Added Get-ClipboardHistory PowerShell module to enumerate Windows clipboard history (Windows 10/11) via WinRT APIs
-   Added local ticket support to Invoke-PSRemoting module

## [6.3.0] - 2025-12-11
-   Updated Starkiller to v3.2.0

### Added

-   Exposed all agent language options in PSexec so that C#, Ironpython, and Go can be selected for the Empire payload in addition to PowerShell
-   Add support for overriding all config values with environment variables
-   Updated Empire Compiler to v0.4.1
-   Add customizable C# obfuscation to EmpireCompiler through confuser xml
-   Added mTLS support to agents and listeners
-   Added mono to install script for confuser obfuscation support on Linux

### Changed

-   Upgrade all dependencies to latest
-   https `host` can be used on http and malleable listeners without a cert path
-   Upgraded routing packets from RC4 to use ChaCha20-Poly1305 for encryption and authentication
-   Changed key exchange for Powershell agent from RSA to Diffie-Hellman
-   Updated server to use AESCipher class for encryption/decryption
-   Updated multi-launcher launcher to use EntryPoint.Invoke for Powershell
-   Moved default bypasses from stager and modules to config

### Fixed

-   Fix typo in variable name `suppress_self_cert_warning`
-   Fixed all the new ruff linting issues after the upgrade
-   URL encode database credentials in case they have special characters
-   Fixed EmpireCompiler not obfuscating C# code properly
-   Fixed issue where some C# modules would not run in Go agent
-   Fixed SharpSploit/ShellCmd not running due to additional yaml argument
-   Fixed install script failing on a subsequent run
-   Fixed cookie naming for HTTP, foreign, and hop listeners
-   Fixed port appending issues with listeners when not needed

### Changed

-   Install script invokes `setup` command to download starkiller, empire-compiler, and plugin registries

### Removed

-   Removed Ubuntu 20.04 from install tests
-   Removed RC4 being used to deliver to agents

## [6.2.1] - 2025-09-05

-   Fix bug where websocket connection would fail because the jwt_auth method arguments changed

## [6.2.0] - 2025-09-02

-   Updated Starkiller to v3.1.0
-   Added clean and reset options to the server
-   Added other agent language support to fodhelper
-   Added go support to spawn and spawnas
-   Fixed launcher_bat when go agent is used
-   Fixed issue where gopire doesn't detect high integrity agents
-   Fixed C# execution in iron python agent to use ordered arguements
-   Removed redundant C# function from iron python agent
-   Cleaned up Rubeus and RunCoff yamls
-   Fixed port normalization to allow host port and bind port to be different
-   Allow 'X-Empire-Token' as an alternative header to 'Authorization'
-   Remove abandoned passlib library and use bcrypt directly

## [6.1.3] - 2025-07-11

-   Updated Starkiller to v3.0.1
-   Fixed PowerShell agent having base64 encoded Cookie name for HTTP listener

## [6.1.2] - 2025-05-21

### Added

-   Added support for Ubuntu 24.04 in the install script

### Fixed

-   Fixed issue launching powershell on some distros by installing libicu

## [6.1.1] - 2025-05-21

### Fixed

-   Fix issue caused by ordering of API routers

## [6.1.0] - 2025-05-20

### Changed

-   Use pyyaml's C extension for loading/dumping module yamls to make startup and tests faster
-   Simplified Dockerfile by using TARGETARCH variable
-   Cleanup API code
-   Use a new version of donut that supports arm64
-   Update all deps

### Removed

-   Remove unused files

## [6.0.3] - 2025-04-24

-   Fixed SMB listener not sending start task
-   Fixed ironpython shell commands running as cmd instead of powershell
-   Added literal interpretation for shell commands to ironpython agent
-   Fixed multi_launcher not being able to build smb agent
-   Removed linux as go agent option as its not implemented yet

## [6.0.2] - 2025-04-07

-   Fixed issue where C# modules on powershell agent would be improperly formatted
-   Fixed SharpWMI argument errors when using escaped quotes
-   Updated result parser on SharpWMI to not use StreamWriter due to messing up results

## [6.0.1] - 2025-04-03

### Fixed

-   Fixed issue generating Sharpire exes

## [6.0.0] - 2025-03-25
-   Updated Starkiller to v3.0.0

### Highlights

-   Plugin Marketplace
-   Go agents
-   Empire Compiler for C#
-   Command line client removed

### Added

-   Added support for plugin registries and installing plugins via the API
    -   See the Plugin Marketplace in Starkiller 3.0!
-   New allow/deny list implementation that properly supports IPv4, IPv6, Ranges, and CIDRs
-   Added API endpoints for managing autorun commands on agent checkin
-   Added `api.ip` and `api.secure` as server config options
-   Added Go agents
    -   Added Go to install script
    -   Added new stager type `multi_go_exe`
    -   Added Go is an option for `multi_launcher`
    -   Added new compiler class `GoCompiler`
-   Added `-f` flag for install script to force install as root
-   Added dynamic options to modules
-   Added module `code_execution/invoke-script` for remote ps1 script execution
-   Added module `python/code_execution/invoke-script` for remote py script execution
-   Added sharphound ingestor for CE and tagged bloodhound with legacy
-   Added check that module can be ran on the agent based on language

### Changed

-   Changed minimum Python version to 3.13
-   Updated module_service logic for tasking types
-   Swapped C# module RunOF for COFFLoader
-   Updated parsing for bof formatting to use bof_pack
-   Moved bash and pyinstaller stagers to linux folder
-   Change formatter to ruff to consolidate developer tooling
-   Revised the staging process for agents. Session IDs are provided by the server and all packets are wrapped in routing packets.
    -   Updated stageless agents to work with python, ironpython, and powershell with the new staging process.
-   Updated tactics and techniques on all modules
-   Added a yaml formatter and run pre-commit across all files
-   Combined config with config_manager
-   Converted many parts of codebase to be compliant with flake8-use-pathlib
-   Csharp and bof tasks attach the executable as a 'download' with a tag 'task:input'
-   Pass output path to dotnet compiler, only compile the requested version
-   Limited staging key space to letters and numbers to avoid invalid combinations

#### Breaking

-   Many improvements to plugins - see the `plugin-development` wiki page
-   Moved `Agents` class to `AgentCommunicationService`
    -   Refactored many of the functions and parameter names
-   Moved `Stagers` class to `StagerGenerationService`
    -   Refactored many of the funtions and parameter names
-   Moved Plugin Task handling from `PluginService` to `PluginTaskService`
-   Moved socks management to `AgentSocksService`
    -   Renamed socks properties on `AgentSocksService` to use plural naming
-   Removed `update_lastseen` parameter from `handle_agent_request`
-   Renamed all config properties in client and server configs to use snake_case
-   Starkiller is now accessed at `{api_url}/` instead of `{api_url}/index.html`
-   `ip_whitelist` and `ip_blacklist` are now `ip_allow_list` and `ip_deny_list` and are lists instead of comma separated strings
-   Using a new and improved [Empire-Compiler] for C# compilation
    -   Downloads pre-compiled Empire-Compiler to eliminate `dotnet` as an OS dependency
    -   Updated shortened task results to show the C# command ran and full input to show directory of the file
    -   Updated C# tasks into folders and split yaml configs to be one per module and match Empire yaml format
    -   All C# module code has been moved as submodules of Empire-Compiler
    -   Moved EmpireCompiler compression from application to the server
    -   Moved EmpireCompiler from install script to startup with autoupdate functionality
    -   Replaced csharpserver plugin with `DotnetCompiler` class in `empire.server.common`
-   module_service.execute_module returns a pydantic model
-   agent_task_service functions take a user model instead of user id
-   All writeable data moved out of the install path into `~/.local/share/empire`

### Deprecated

### Removed

-   Removed autorun config options which haven't been used since Empire 3
-   Removed install support for Debian 10
-   Removed `nim` stager from Empire and install script
-   Removed slack notifications from listeners
-   Removed the following stagers
    -   osx/pkg
    -   windows/backdoorlnkmacro
    -   windows/launcher_lnk
    -   windows/launcher_sct
    -   windows/ms16-051
    -   windows/reverseshell
-   Removed the following listeners
    -   HTTP COM only supports powershell agent and uses an older COM object that isn't used often
    -   OneDrive has new APIs and Microsoft hs made registration harder. May return in the future with revisions.
    -   Dropbox has new APIs and may return in the future with revisions.
-   Removed empire_config.directories.module_source and empire_config.directories.obfuscated_module_source
-   Removed BLANK and RANDOM options for staging_keys (wasn't documented anyway)

#### Breaking

-   Removed the command line client. Use Starkiller instead.
-   Removed `Listeners` class
-   Removed `Credentials` class
-   Removed functions from `Agents` class that were marked as deprecated in 5.x
-   Removed `--restip` and `--restport` options from the command line. Use the config file instead.
-   Removed `socketport` config option on the client which was no longer being used
-   Removed script and module upload to memory in favor of modules with same functionality
-   Removed reverseshellserver plugin

### Fixed

-   Fixed Powershell agent overwritting results for C# taskings
-   Simplify option_util.validate_options, fixes a bug where an optional file option was treated as required
-   Fixed issue loading a plugin that has multiple files
-   Fixed issue with permissions caused by git operations being done with de-elevated permissions
-   Fixed go agent using a preshared session id

### Security

## [5.12.2] - 2025-01-12

### Fixed

-   Fixed issue with C# exe and shellcode not compiling PowerShell stagers
-   Fix delay/jitter adjustment in python agent (@janit0rjoe)

## [5.12.1] - 2025-01-08

### Fixed

-   Fixed issue with install script caused by Poetry 2.0

## [5.12.0] - 2024-12-14

-   Reduce the check-in tests that were adding an unncessary amount of time to the CI
-   Allow Python 3.13 to be used
-   Fix python install
-   Support Empire for system-wide deployment (@D3vil0p3r)
-   Paths specified in config.yaml where user does not have write permission will be fallback to ~/.empire directory and config.yaml updated as well (@D3vil0p3r)
-   Invoke-Obfuscation is no longer copied to /usr/local/share

## [5.11.7] - 2024-11-11

-   Fix arm installs by installing dotnet and powershell manually
-   Fix issue initializing some databases by removing the unused Reporting table

## [5.11.6] - 2024-11-08

-   Fixed extra character in nanodump.x64.o
-   Fixed bof tasking for IronPython agent

## [5.11.5] - 2024-09-22

-   Updated Starkiller to v2.8.2
-   Fixed various Python 3.12 SyntaxWarning

## [5.11.4] - 2024-09-04

### Added

-   Added nameserver check for linux hosts (@0x636f646f)

## [5.11.3] - 2024-09-04

### Changed

-   Updated Rubeus to v2.3.2 (@Cx01N)

### Fixed

-   Fixed Rubeus error where only first arg was being used (@Cx01N)
-   Fixed background jobs checking in continuously (@Cx01N)
-   Fixed Rubeus killing agent when certain options were given that use System.Environment.Exit (@Cx01N)
-   Fixed option parsing error in credential/tokens module (@Cx01N)
-   Removed requirement for credid for mimikatz/pth (@Cx01N)

## [5.11.2] - 2024-08-08

### Added

-   Added Route4Me to sponsor page on Empire (@Cx01N)

### Fixed

-   Fixed global obfuscation bug in listener staging (@Cx01N)

## [5.11.1] - 2024-07-23

### Changed

-   Updated Ruff to 0.5.3 and added additional Ruff rules (@Vinnybod)

### Fixed

-   Removed duplicate code for ironpython agent for loading path resetting (@Cx01N)
-   Fixed issue of Sharpire taskings not getting assigned correct id (@Cx01N)

## [5.11.0] - 2024-07-14

### Added

-   Added threaded jobs for powershell tasks using Appdomains (@Cx01N)
-   Added job tracking for all tasks in Sharpire (@Cx01N)
-   Updated agents to track all tasks and removed only tracking jobs (@Cx01N)
-   Added Invoke-BSOD modules (@Cx01N)
-   Added ticketdumper ironpython module (@Hubbl3)
-   Added ThreadlessInject module (@Cx01N)

### Fixed

-   Fixed issue in python agents where background jobs were failed due to a missing character (@Cx01N)
-   Fixed task bundling for the c# server plugin (@Cx01N)
-   Fixed missing New-GPOImmediateTask in powerview (@Cx01N)
-   Fixed NET45 missing folder causing a compilation error (@Cx01N)
-   Fixed NET45 files not being removed on server reset (@Cx01N)

### Changed

-   Converted C# server plugin to use plugin taskings (@Cx01N)
-   Upgraded Ruff to 0.5.0 and Black to 24.4.2 (@Vinnybod)
-   Added pylint-convention (PLC), pylint-error (PLE), pylint-warning (PLW), and pylint-refactor (PLR) to ruff config (@Vinnybod)

## [5.10.3] - 2024-05-23

### Changed

-   Updated the default value for Sharpup to audit (@Cx01N)
-   Updated the default value for Seatbelt to AntiVirus (@Cx01N)
-   Updated the default value for SharpWMI to action=query (@Cx01N)
-   Updated the default value for SharpSC to action=query service= (@Cx01N)
-   Updated GetSystem to require admin (@Cx01N)
-   Updated the default value for Moriarty to --debug (@Cx01N)

### Fixed

-   Fixed issue with generate_agent having a mismatched function name for stageless (@Cx01N)
-   Fixed parsing issue for C# portscan with commas (@Cx01N)
-   Fixed error for PrivExchange with missing System.XML.dll (@Cx01N)

### Removed

-   Removed BypassUACGrunt due to compatibility with only Covenant (@Cx01N)
-   Removed BypassUACCommand due to compatibility with only Covenant (@Cx01N)

## [5.10.2] - 2024-05-05
-   Updated Starkiller to v2.8.1

## [5.10.1] - 2024-04-26
-   Updated Starkiller to v2.8.0

### Added

-   Added removal of starkiller directory to server reset (@Cx01N)

### Fixed

-   Fixed missing .NET 4.5 DLLs (@Cx01N)
-   Fixed run_as_user issue when dealing with directories (@Cx01N)
-   Fixed missing clr package for IronPython standard library (@Cx01N)

## [5.10.0] - 2024-04-08

### Added

-   Added dependabot for github actions dependencies (@Vinnybod)
-   Added install option to ./ps-empire file (@Cx01N)
-   Added auto pull options for submodules on startup (@Cx01N)
-   Added hook and socket message to receive callback messages for individual agents (@AaronVigal)
-   Added sacrificial Spawn Process bof (@Cx01N)
-   Added suggested values to most modules (@Cx01N)
-   Added continuous, error, and completed tasking statuses (@Cx01N)
-   Added continuous and error plugin statuses (@Cx01N)
-   Added Moriary module (@C01N)
-   Added .NET 4.5 compile option (@C01N)

### Changed

-   Updated all dependencies (@Vinnybod)
-   Updated Dockerfile and install script to Python 3.12.2 (@Vinnybod)
-   Updated starkiller snyc to no longer require root (@Cx01N)
-   Change file permissions for empire and listener logs to be non-root (@Cx01N)

### Fixed

-   Fixed issue loading `openapi.json` (@Vinnybod)
-   Fixed issue when False is given for options and option is appended with 'False' (@Cx01N)
-   Fixed module generation error in ComputerDetails (@Cx01N)

## [5.9.5] - 2024-02-22
-   Updated Starkiller to v2.7.3

## [5.9.4] - 2024-02-17

### Fixed

-   Fixed downloads for C# agent (@Cx01N)

## [5.9.3] - 2024-02-09

### Added

-   Added option to windows_macro stager to select Excel or Word and AutoOpen or AutoClose (@Cx01N)

### Fixed

-   Fixed obfuscation issue in Malleable HTTP listeners and added tests (@Cx01N)
-   Fixed issue that invalid session IDs were accepted by the server (@Cx01N)
-   Fixed skywalker exploit (again) and added tests (@Cx01N)

## [5.9.2] - 2024-01-31
-   Updated Starkiller to v2.7.2

### Fixed

-   Fixed the ForeignKeyConstraint error when refreshing a directory that contains a file with a linked Download (@Vinnybod)
-   Downgraded bcrypt to version 4.0.1 to resolve issue in passlib (@Cx01N)

## [5.9.1] - 2024-01-25

### Changed

-   Convert agent task output to string before the BEFORE_TASKING_RESULT_HOOK (@Vinnybod)
-   Updated tasklist for powershell code to not throw error when GetOwner fails (@Cx01N)

### Fixed

-   Updated Uvicorn to fix issue where an open browser would cause the shutdown to hang (<https://github.com/encode/uvicorn/pull/2145>) (@Vinnybod)
-   Fixed the fastapi app lifecycle not being properly called on shutdown (@Vinnybod)
-   Converted listener threads to daemons so they don't hang the shutdown in Python 3.12 and report `RuntimeError: can't create new thread at interpreter shutdown` (@Vinnybod)
-   Log warning about ps/ls hooks and filters not being able to parse the JSON output (@Vinnybod)

## [5.9.0] - 2024-01-20

### Added

-   Added validation and execution exceptions for modules to raise (@Vinnybod)
-   Added decorators for module generate functions to automatically get the module_source and call finalize_module (@Vinnybod)
-   Added execution exception to plugins (@Vinnybod)
-   Added RUF rules to ruff config (@Vinnybod)
-   Added SIM rules to ruff config (@Vinnybod)
-   Added BOF modules to Empire as yamls (@Cx01N)
    -   Added ClipBoardWindow-Inject module
    -   Added nanodump module
    -   Added secinject module
    -   Added tgtdelegation module
    -   Added TrustedSec's SA modules
-   Added custom certificate path to server config.yaml (@AaronVigal)

### Deprecated

-   Returning tuples from module generate functions is deprecated
    -   To return a 400, raise a `ModuleValidationException`
    -   To return a 500, raise a `ModuleExecutionException`
    -   Stop using `handle_error_message`
-   Returning tuples from plugin execution functions is deprecated
    -   To return a 400, raise a `PluginValidationException`
    -   To return a 500, raise a `PluginExecutionException`
-   Loading plugins from a `.plugin` file is deprecated
    -   Use a `.py` file with a `plugin.yaml` instead
-   Extending the `Plugin` class is deprecated
    -   Use the `BasePlugin` class instead

### Changed

-   Migrated some Pydantic and FastAPI usage away from deprecated features (@Vinnybod)
-   Updated the install script and Docker file from Python 3.12.0 to 3.12.1 (@Vinnybod)
-   Upgraded all dependencies with `poetry up` (@Vinnybod)
-   Plugin updates (@Vinnybod)
    -   Plugins have a `plugin.yaml`
    -   Base plugin class is now `BasePlugin`
    -   Updated plugin documentation
-   Upgraded Black to 23.12.0 (@Vinnybod)
-   Upgraded Ruff to 0.1.9 (@Vinnybod)
-   Upgraded Seatbelt to 1.2.1 (@Cx01N)

## [5.8.4] - 2023-12-22

### Fixed

-   Fixed `Path` variables in EmpireConfig not properly expanding `~` (@Vinnybod)

## [5.8.3] - 2023-12-15

### Fixed

-   Fixed error in Get-DomainComputer in Powerview when dnshostname property is missing (@Cx01N)

## [5.8.2] - 2023-12-09

### Fixed

-   Fixed error in generating stager for HTTP Hop listener (@Cx01N)
-   Fixed the publishing of docker images to go to the correct DockerHub coordinate (@Vinnybod)

## [5.8.1] - 2023-11-30
-   Updated Starkiller to v2.7.1

### Added

-   Add tags search to credentials endpoints (@Vinnybod)
-   Allow Starkiller to be disabled (@Vinnybod)
-   Allow API port to be configured from the config.yaml (@Vinnybod)
-   Add flake8-comprehensions rules to ruff config (@Vinnybod)

### Changed

-   Upgrade Pydantic to v2 (@Vinnybod)
-   Update common FastAPI Dependencies to use 'Annotated' types for simpler code (@Vinnybod)
-   Simplify TestClient setup (@Vinnybod)
-   Removed usages of deprecated `Credentials` and `Listeners` functions (@Vinnybod)
-   Remove usages of deprecated `Agents` functions (@Vinnybod)
-   Add typehinting for `MainMenu` object in modules (@Vinnybod)
-   Removed `name` property from listener start and shutdown functions (@Vinnybod)
-   Removed secretsocks as dependency for Python agents (@Cx01N)

### Removed

-   Remove unused migration scripts (@Vinnybod)

### Fixed

-   Fixed the database session management for websocket endpoints (@Vinnybod)

## [5.8.0] - 2023-11-06

-   Warning: You may run into errors installing things such as nim if you are running the install script on a machine that previously ran it. This is due to permissions changes with the install script. In this case it is recommended to use a fresh machine or manually remove the offending directories/files.

### Added

-   Added automatic tasking for sysinfo for stageless agents (@Cx01N)

### Changed

-   Modernized the Python and IronPython agents with new agent and staging code (@Cx01N)
-   Updated listeners to consistently use port 80 and 443 for HTTP traffic by default (@Cx01N)
-   Make the installation of donut conditional on architecture since it doesn't work on ARM (@Vinnybod)
    -   When donut is invoked but not installed, give a useful warning (@Vinnybod)
-   Allow a config to be loaded from an outside directory and the downloads/logs/etc to be stored in an outside directory (@Vinnybod)
-   Correct more deprecation warnings for SQLAlchemy and invalid escape sequences (@Vinnybod)
-   Updated the ruff minimum Python version to 3.10 and applied fixes to get codebase compliant (@Vinnybod)
-   Remove unneeded condition statement from all listeners (@Vinnybod)
-   Update Docker build (@Vinnybod)
    -   Use the official Poetry installer
    -   Fix Starkiller trying to auto-update inside the container
    -   Pre-install Starkiller as part of the docker build
    -   Use Python 3.12
    -   Don't use apt for powershell and dotnet
    -   DockerHub images now have linux/amd64 and linux/arm64 architectures
-   Dependency changes (@Vinnybod)
    -   Use BC-Security fork of md2pdf until upstream can support Python 3.12
    -   Use a patched version of pysecretsocks that packages asyncore for Python 3.12 support
    -   Use docopt-ng for Python 3.12 support
    -   Add packaging as a runtime dependency
-   Update install script (@Vinnybod)
    -   Use pyenv to install Python
    -   Use the official Poetry installer
    -   Don't run the entire script as root
    -   Rewrite the test containers and reuse a templated Dockerfile
    -   Add Debian12 support
    -   Bump all OS to use Python 3.12
    -   Refactor the script to be a bit more readable
    -   Condense the test_install_script job
    -   Added option to start MySQL service on boot (@Cx01N)

### Removed

-   Drop support for Python 3.8 and 3.9

## [5.7.3] - 2023-10-17

-   Updated Starkiller to v2.6.1
-   Fixed global obfuscation not working on modules (@Cx01N)
-   Added bypass module in PowerShell to run bypasses after agent is staged (@Cx01N)
-   Fixed IronPython and Python stagers not getting obfuscation applied (@Cx01N)

## [5.7.2] - 2023-09-28

-   Updated Dropbox C2 to use new API endpoints (@Cx01N)
-   Standardized Kill Date and Working Hours for PowerShell Agents (@Cx01N)
-   Apply fixes for future Python 3.12 compatibility (@Vinnybod)
-   Add additional rulesets to ruff linting (@Vinnybod)

## [5.7.1] - 2023-09-25

## [5.7.0] - 2023-09-17

-   Add avatars to users (@Vinnybod)
-   Update plugin documentation, update embedded plugins to not abuse notifications (@Vinnybod)
-   Add additional pre-commit hooks for code cleanup (@Vinnybod)
-   Report test coverage on pull requests (@Vinnybod)
-   Fixed issue with multiple parameters not executing in IronPython for C# tasks (@Cx01N)
-   Fix for spawnas not generating bat file (@wizquaza)
-   Fixed taskings for OneDrive listener (@Hubbl3)

## [5.6.4] - 2023-09-08

-   Added Stix2 to dependency list for Advanced Reports (@Cx01N)
-   Fixed C# module imports for IronPython agent (@Cx01N)
-   Updated Invoke-DllInjection.ps1 (@Signum21)
-   Fix nimble install error (@fukusuket)

## [5.6.3] - 2023-08-27

-   Updated Starkiller to v2.5.3
-   Added Advanced Reporting Plugin and dependencies (@Cx01N)
-   Pin linters in the workflow
-   Catch error when starting up database that was seeded by an older version of Empire (@Vinnybod)
-   Updated Windows BAT launcher to use Base64 for all payloads (@Cx01N)

## [5.6.2] - 2023-08-09

-   Update the github issue templates to use forms (@Vinnybod)
-   Fix issue with option validator throwing error for strict non-required options (@Vinnybod)
-   Allow Starkiller to load even if the git pull fails if the dir exists (@Vinnybod)
-   Update listener descriptions to not specify languages since Empire supports more languages now

## [5.6.1] - 2023-08-02

## [5.6.0] - 2023-07-25

-   Upgrade dependencies
-   Upgrade Dockerfile to bullseye and 3.11.4
-   Allow download_service to accept a pathlib.Path object to create a download (@Vinnybod)
-   Fix file option for listeners, stagers, plugins (@Vinnybod)
-   Add tags to Listeners, Agents, Agent Tasks, Plugin Tasks, Credentials, and Downloads (@Vinnybod)
    -   Add endpoints to add, edit, and delete tags for each resource type
    -   Add tag list endpoint
    -   Add tag filters to Agent Tasks, Plugin Tasks, and Downloads
    -   Add events for new and updated tags
-   Fix user filters for tasks to include tasks without any users (@Vinnybod)
-   Refactor stager and listener tests to work better in parallel (@Vinnybod)
-   Add a Invoke-PhishingLNK Module (@0xFFaraday)
-   Fix changelog link in README (@theguly)

## [5.5.4] - 2023-07-20
-   Updated Starkiller to v2.4.3

## [5.5.3] - 2023-07-20

-   Updated Starkiller to v2.4.2
-   Updated restip message to show IP address on server (@Cx01N)
-   Fixed onedrive taskings for powershell (@Cx01N)
-   Update pyyaml to 6.0.1 to avoid build issue from cython (@Vinnybod)
-   Use MariaDB in Debian (@Vinnybod)

## [5.5.2] - 2023-07-14

-   Fix TypeError and crash when using `main` command in client (@jellyjellyrobot)
-   Fix extraneous semi-colon breaking powershell 'literal' execution (@crittico)

## [5.5.1] - 2023-07-06

-   Fix basic_reporting plugin using the wrong agent checkin column

## [5.5.0] - 2023-06-21

-   Break out agent checkins to a new table (@Vinnybod)
    -   New checkins endpoint to get them as a list
    -   New checkins aggregate endpoint to get aggregated checkin data
    -   Aggregate endpoint not supported with SQLite
-   Add a warning message about using SQLite
-   Added LinPEAS to Python modules (@Cx01N)
-   Added python obfusscation using python-obfuscator (@Cx01N)
-   Added IronPython SMB Agents/Listener (@Cx01N)
-   Expand file options to plugins, stagers, and listeners (@Vinnybod)
-   Added Python agent support to hop listener (@Cx01N)
-   Added staging to hop listener (@Cx01N)
-   Added python module for Pwnkit (CVE-2021-4034) (@Cx01N)
-   Added python module for Polkit (CVE-2021-3560) (@Cx01N)
-   Fixed safecheck error for python module sudo spawn (@Cx01N)
-   Fixed file error in Invoke-Shellcode (@Cx01N)
-   Removed duplicate modules between languages (@Cx01N)
    -   Removed .NET Core modules due to errors
    -   Removed redundant C# lateral movement modules
    -   Removed Covenant Mimikatz in favor of Invoke-Mimikatz
    -   Removed Invoke-Assembly in favor of Covenant's execute assembly
    -   Removed Invoke-BOF in favor of RunOF
    -   Removed Invoke-Rubeus in favor of Covenant's Rubeus
    -   Removed Invoke-Seatbelt in favor of Covenant's Seatbelt
    -   Removed Bloodhound v1 module
-   Revamped malleable profiles and increased their generation reliability (@Cx01N)
-   Allow the server to start even when starkiller sync fails (@Vinnybod)
-   Remove libssl1.1 from the install script since it doesn't appear to be needed and causes install failures on some OS (@Vinnybod)
-   Fix the restip argument which wasn't being used (@Vinnybod)
-   Added reload endpoint to Malleable Profiles, Modules, Bypasses, and Plugins (@Cx01N)
-   Updated and fixed pyinstaller stager (@Cx01N)

## [5.4.2] - 2023-06-07

-   Updated Starkiller to v2.3.2
-   Fixed python modules not running properly (Cx01N)
-   Updated python multi_socks to run with Python 3 (Cx01N)

## [5.4.1] - 2023-06-02

-   Fix database reset issue with MySQL (@Vinnybod)
-   Add a message to the client recommending the use of the Starkiller (@Vinnybod)
-   Fixed issue with Invoke-wmi not returning a success message (@Cx01N)
-   Fixed dynamic function issue with Powerview (@Cx01N)
-   Pair down the amount of minutes needed to run pull request builds (@Vinnybod)

## [5.4.0] - 2023-05-22

-   Remove Starkiller as a submodule, treat it as a normal directory (@Vinnybod)
    -   Everything should 'just work', but if you have issues after pulling these latest changes, try deleting the Starkiller directory before running the server `rm -r empire/server/api/v2/starkiller`.
-   Some improvements to the release flow after starkiller submodule removal (@Vinnybod)

## [5.3.0] - 2023-05-17

-   Add the ability to specify a module option as a file (@Vinnybod)

## [5.2.2] - 2023-04-30

-   Updated Starkiller to v2.2.0
-   Dependency upgrades (@Vinnybod)

## [5.2.1] - 2023-04-30

-   Updated Donut to v1.0.2 (@Cx01N)
-   Fixed issue with install path not being used properly when switching empire location (@Vinnybod)
-   Lock nim version in the install script (@Vinnybod)
-   Fixed issue with Powerview modules not performing dynamic detect on overhead functions (@Cx01N)
-   Fixes for the onedrive listener that broke with 5.0 (@Vinnybod)

## [5.2.0] - 2023-03-31

-   Added new plugin functionality (@Vinnybod)
    -   Added plugin tasks
    -   Added plugin task endpoints
    -   Gave plugins kwargs to allow for more flexibility. Plugins are now receiving a database session and user object.
-   Tasks renamed to AgentTasks to avoid confusion with PluginTasks
-   Rename tasking to task in most places to standardize the naming. The hook names have not been changed yet.
-   Fix Starkiller error in Docker (@0x4xel)
-   Fixed launcher_bat to work with all listeners (@Cx01N)
-   Fixed issue with duplicate Server Header being added by Flask (@Cx01N)
-   Fixed malleable c2 not generating IronPython agents correctly (@Cx01N)

## [5.1.2] - 2023-03-29

-   Updated Starkiller to v2.1.1
-   Removed thread from IronPython agent (@Hubbl3)
-   Fixed foreign listener issue with cookies (@Hubbl3)
-   Fixed error message handling for port forward pivot (@Cx01N)
-   Fixed upload not reporting error in PowerShell agent (@Cx01N)
-   Fixed client not giving option to select upload directory (@Cx01N)
-   Fixed persistence/powerbreach/eventlog launcher generation (@Cx01N)

## [5.1.1] - 2023-03-17

-   Added D/Invoke option to Process Injection (@Cx01N)
-   Added IronPython and csharp to windows/launcher_bat (@Cx01N)
-   Added language option to spawn and spawnas modules (@Cx01N)
-   Fixed issue with powershell and ironpython agents not using public classes (@Cx01N)
-   Fixed issue where large shellcode files lock up server in Invoke_Shellcode (@Cx01N)
-   Increased the default time for base64 encoded ironpython payloads (@Cx01N)
-   Fix issue with large stacktrace on stale socketio connection (@Vinnybod)

## [5.1.0] - 2023-03-01

-   Added a 'modified_input' field to the 'execute module' task (@Vinnybod)
-   Added an endpoint to get the script for a module (@Vinnybod)

## [5.0.4] - 2023-02-25

-   Fix module error in PSRansom (@Cx01N)
-   Update the install script to set up a new db user instead of overwriting the root user (@Vinnybod)
-   Update the Starkiller syncer to skip updating if not in a git repo (@Vinnybod)
-   Update the Docker CI action to publish latest on 'main' branch (@Vinnybod)
-   Fix install of Poetry for Debian based systems (@Vinnybod)

## [5.0.3] - 2023-02-20

-   Updated Starkiller to v2.0.5
-   Fix Invoke-Kerberoast with etype 17 or 18 (@AdrianVollmer)
-   Add 3.11 support, bump Dockerfile to 3.11, bump Debian install to 3.8.16 (@Cx01N)
-   Update the GitHub actions to remove usages of deprecated ::set-output function (@Vinnybod)
-   Update plugin submodule references post 5.0 branch merges (@Vinnybod)

## [5.0.2] - 2023-02-14

-   Fix the test that detects errors loading modules (@Vinnybod)
-   Allow empty user id and username on the task API (@Vinnybod)
-   Rename module_slug to module_id for tasks for consistent naming on the api (@Vinnybod)
-   Add a shebang to the checkout-latest-tag.sh script (@xambroz)

## [5.0.1] - 2023-02-04

-   Fixed the uniqueness check for MariaDB (@Vinnybod)
-   Fixed redirector issue with parent listeners (@Cx01N)
-   Added exception for agent task when server is initializing (@Cx01N)
-   Fixed listener menu displaying error when viewing options (@Cx01N)
-   Starkiller sync process now attempts to pull the ref from the remote (@Vinnybod)
-   Auto-merge `private-main` to downstream `main` branches using a label (@Vinnybod)
-   Fixed error in IronPython agent when running PowerShell tasks (@Cx01N)
-   Fixed issue adding comms twice to stageless python agents (@Cx01N)
-   Updated Redirector to Port Forward Pivot (@Cx01N)
-   Updated to Mimikatz 2.2.0-20220919 (@Cx01N)
-   Add Ruff linter and pre-commit hook (@Vinnybod)

## [5.0.0] - 2023-01-15

-   Added Starkiller as an integrated web app (@Vinnybod)
-   Added full MySQL support (@Vinnybod)
    -   MySQL is the new default
    -   Database type can be changed by setting `database.use` in `config.yaml` or environment variable `DATABASE_USE`
    -   SQLite is still supported
    -   The Docker image still defaults to SQLite, but can be changed to MySQL by modifying the `config.yaml` or setting the environment variable `DATABASE_USE=mysql`.
-   Added v2 API (@Vinnybod)
-   Added autogenerated docs for v2 API (@Vinnybod)
-   Added stageless options for agents (@Cx01N)
-   Added clear window command to client (@Cx01N)
-   Added mouse_support to client (@Cx01N)
-   Added RunOF module to support COFF/BOF execution (@Cx01N)
-   Added new database table for files (@Vinnybod)
-   Added server-side storage of stagers (@Vinnybod)
-   Added new listener object is created for each listener instead of using a shared state (@Vinnybod)
-   Added listener, agent, and task hooks (@Vinnybod)
-   Added db session to hooks (@Vinnybod)
-   Added global obfuscation config and removed from config table (@Vinnybod)
-   Added authors to bypass endpoints (@Vinnybod)
-   Added a help command to the client to print the full doc string of a function. such as `help shell` or `help script_import` (@Vinnybod)
-   Added `--literal` flag that can be used on shell commands that forces the agent to execute the command literally, ignoring any built-in aliases that exist such as for whoami or ps (@Vinnybod)
-   Updated plugins endpoints and options (@Vinnybod)
-   Updated authentication to use JWT auth instead of basic auth (@Vinnybod)
-   Updated to MITRE ATT&CK v11 for sub-technique and tactic support (@Cx01N)
-   Updated SOCKS & Chisel plugins for 5.0 (@Cx01N)
-   Updated socketio emit to be async (@Vinnybod)
-   Updated hooks to handle sync or async functions (@Vinnybod)
-   Updated authors to have name, handle, and link for modules, listeners, stagers, and plugins (@Vinnybod)
-   Updated Dockerfile for better caching (@Vinnybod)
-   Updated agent.py to extract logic for sleep duration and lazily calculate file sizes (@lavafroth)
-   Moved keyword_obfuscation config property under database defaults (@Vinnybod)
-   Moved obfuscate and obfuscateCommand defaults under `database.defaults.obfuscation` (@Vinnybod)
-   Restructured all the 'common' code (@Vinnybod)
-   Converted reports to a plugin (@Cx01N)
-   Converted generate_agent module to stager (@Cx01N)
-   Removed malleable.Profile from listener options (@Cx01N)
-   Removed old REST API (@Vinnybod)
-   Removed old WebSocket API (@Vinnybod)
-   Removed socketport since socketio runs on the same port as the API (@Vinnybod)
-   Removed AFTER_AGENT_STAGE2_HOOK and replaced with AFTER_AGENT_CHECKIN_HOOK (@Vinnybod)
-   Removed last seen time for users since it could cause db locking issues (@Vinnybod)
-   Removed pydispatcher (@Vinnybod)
-   Removed prompt line from server (@Vinnybod)

## [4.10.0] - 2023-01-03

-   Updated agent model for consumer methods to use the info property (@lavafroth)
-   Debian 11, Ubuntu 2204, and ParrotOS Support (@Vinnybod)
-   Add a "-y" option to the install script and fixed a bunch of formatting (@ajanvrin)
-   Fixed issues with stripping comments from Python code and executing certain Python modules (@Jackrin)
-   Added C# Crypto Miner module (@Cx01N)
-   Added PSRansom module (@Cx01N)

## [4.9.0] - 2022-11-29

-   New CI/CD Process (@Vinnybod)

## [4.8.4] - 2022-11-26

-   Fixed #540 PydanticModule object has no attribute 'info' in API module search (@lavafroth)
-   Fixed agent/server module version check (@Jackrin)

## [4.8.3] - 2022-11-11

## [4.8.2] - 2022-11-11

-   Updated crontab method to work with python3 (@Cx01N)
-   Updated linux_privesc_check to work with python3 (@Cx01N)
-   Fixed mistakes in README.md (@Cx01N)
-   Removed unused class in python agents (@Cx01N)

## [4.8.1] - 2022-10-30

-   Added container structure test to CI (@Vinnybod)
-   Added a fallback checkout that doesn't use a token (@Vinnybod)
-   Revamped README.md (@Cx01N)
-   Simplified Dockerfile install process (@lavafroth)
-   Fixed crashing issue with IronPython agent (@Cx01N)
-   Fixed infinite loop output stream for csharpserver plugin (@dwilson5)
-   Fixed querying stale and active agents (@lavafroth)

## [4.8.0] - 2022-08-30

-   Updated compiler to .NET SDK 6.0 (@Hubbl3)

## [4.7.3] - 2022-08-20

-   Added SANS 565 to README (@Cx01N)
-   Fixed error when entering empty line into client (@Cx01N)
-   Fixed Dropbox listener staging issue (@Cx01N)
-   Fixed OneDrive listener staging issue (@Cx01N)

## [4.7.2] - 2022-08-20

## [4.7.1] - 2022-07-29

-   Fix write_dllhijacker.yaml script_path reference (@kevNii)

## [4.7.0] - 2022-06-25

-   Update Python version on Dockerfile (@Vinnybod)
-   Add Python 3.10 to CI tests  (@Vinnybod)
-   Add a resource file command to the client (@Vinnybod)
-   Add PowerShell and C# to IronPython modules (@Cx01N)
-   Add ChiselServer, SocksProxyServer plugin as a submodule (@Cx01N)
-   Fixed Sharpire download function (@Cx01N)
-   Fixed spawnas to work with new bat file format (@Cx01N)
-   Fixed tasking error for IronPython launcher executable (@Cx01N)
-   Remove some python dependencies (@Vinnybod)
-   Make tkinter import failure a warning instead of a fatal error (@Vinnybod)

## [4.6.1] - 2022-06-10

-   Use a BC-Security fork of Donut to resolve a python 3.10 issue (@Cx01N)
-   Update reflective pick dlls (@Hubbl3)

## [4.6.0] - 2022-05-24

-   Added Certify C# module (@Cx01N)
-   Added embedded VNC client and launcher (@Cx01N)
-   Added obfuscate option to C# payloads (@Hubbl3)
-   Added global obfuscation to C# modules (@Cx01N)
-   Added -BasicParsing to .bat launcher (@X0RW3LL)
-   Added obfuscation to bat launcher for HTTP and HTTP COM (@Cx01N)
-   Added option to enable/disable JA3 evasion (@Cx01N)
-   Added JA3 evasion technique to Malleable HTTP (@Cx01N)
-   Added option to client config to remove borders on tables (@Cx01N)
-   Updated staging for agents (@Cx01N)
-   Updated confuser to confuserex 2 (@Cx01N)
-   Fixed nim install on Ubuntu by using choosenim installer (@vinnybod)
-   Converted reset.sh script to Python and add tests (@Vinnybod)
-   Add a `--reset` flag to the client (@Vinnybod)

## [4.5.5] - 2022-05-07

-   Fixed http bug in malleable, http-com, and onedrive listeners (@Cx01N)
-   Updated jq to 1.2.2 to avoid install errors (@Cx01N)

## [4.5.4] - 2022-04-26

-   Fixed typo from 4.5.3 with the bypass database model (@Vinnybod)

## [4.5.3] - 2022-04-24

-   Fixed issue where default_response is needed for external/generate_agent (@Cx01N)
-   Added check if bypass language is compatible (@Cx01N)
-   Added error message formatting for listeners and stagers (@Cx01N)
-   Added `zip` to the Dockerfile which is necessary to create ms files such as docx (@junquera)

## [4.5.2] - 2022-04-12

-   Fix string format errors in dbx listener (@awsmhacks)
-   Fix script_end error in schtasks.py (@harry-cmdzero)
-   Add workflows for doing the public releases (@Vinnybod)
-   Pull out common code from listeners to a listener_utils module (@Cx01N)
-   Fix missing script_path and fix variable references in service_stager and service_exe_stager (@harry-cmdzero)

## [4.5.1] - 2022-03-27

-   Fixed empire_config `yaml` property to include fields that don't exist on the config object (@Vinnybod)

## [4.5.0] - 2022-03-27

-   Updated changelog to use [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) (@Vinnybod).
-   Added tests for listener launchers (@Vinnybod).
-   Add a step to run the test suite on the Docker image itself (@Vinnybod)
-   Removed .plugin from the black configuration (@Vinnybod)
-   Removed random caps from backdoorlnk (@Cx01N)
-   Added html files for listener responses (@Cx01N)
-   Converted server config to a typed class (@Vinnybod)
-   Add keyword obfuscation to the config.yaml (@Vinnybod)
-   Fix proxy_creds variable name in bypassuac (@Cx01N)
-   Updated launcher_bat to use web request for launcher (@Cx01N)
-   updated malleable profiles with banzarloader (@Cx01N)
-   Added C# execution modules (@Cx01N)
-   Add tests for launcher code (@Vinnybod)
-   Split ls/dir command line to get the first element for ls/dir command (@CyrilleFranchet)
-   Updated lastwritetime on ls/dir command (@CyrilleFranchet)
-   Fix script_end variable on privesc/ask module (@CyrilleFranchet)
-   script_import will upload a file from the client's machine (@Cx01N)

## [4.4.1] - 2022-03-06

-   Fixed agent generation with custom headers (@Hubbl3)
-   Fixed missing quote in get_users.yaml (@Cx01N)
-   Fixed displaying info for plugins (@Cx01N)
-   Fixed legacy plugin loading to ignore folders (@Cx01N)
-   Removed http_mapi.ps1
-   Removed comment that global obfuscation and keyword obfuscation cannot be combined (@Cx01N)

## [4.4.0] - 2022-02-14

-   Added auto copy to clipboard feature (@Cx01N)
-   Added directory settings to yaml for downloads/stagers/obfuscated_modules (@Cx01N)
-   Added C# process injection module (Cx01N)
-   Added bypass yamls for PowerShell (@Hubbl3)
-   Added Black and Isort integration (@Vinnybod)
-   Added tests for loading and generating scripts with defaults (@Vinnybod)
-   Updated Psinject to use updated version of reflective pick and bypasses (@Hubbl3)
-   Fixed check for preobfuscation of files (Cx01N)
-   Fixed issue with plugins using tuple (@Vinnybod)
-   Removed random capitialization function for listeners (@Cx01N)
-   Removed meterpreter and mapi listeners (@Cx01N)
-   Powerview - added functions for group managed service accounts and fine grained pw pol (@jfmaes)

## [4.3.3] - 2022-01-24

-   Added a hook for when an agent is fully checked in (stage2) (@Vinnybod)

## [4.3.2] - 2022-01-14

-   Fixed issues with variables names in Mimikatz & Privesc modules (@sbrun)
-   Fixed issue with Invoke-Obfuscation not being properly called (@Cx01N)
-   Add dotnet install to dockerfile (@Vinnybod)

## [4.3.1] - 2022-01-08

-   Fixed issue with module variables referenced before assignment or undefined (@Vinnybod)
-   Fixed bug with Invoke-Seatbelt caused by variable name mismatch (@Vinnybod)
-   Fixed IronPython exit/shutdown issue (@Cx01N)
-   Fixed ToLower() bug in PowerShell agent when using route (@CyrilleFranchet)
-   Fixed multiline shell output bug (#491) (@CyrilleFranchet)
-   Added dir command to the file browser hook (@CyrilleFranchet)
-   Generate test account with secure rng (@moloch--)
-   Add Invoke-FodhelperProgIDs module (@m1m1k4tz)
-   Add Invoke-VeeamGetCreds module (@sadshade)

## [4.3.0] - 2021-12-23

-   Updated Invoke-Seatbelt, Invoke-Rubeus, & Invoke-WinPeas (@Cx01N)
-   Updated C# modules: Seatbelt, SharpSploit (@Cx01N)
-   Updated profiles to include APT29 (@Cx01N)
-   Updated Mimikatz to 20210810-2 (@Cx01N)
-   Updated reset script to remove c# tasks and generated-stagers (@Cx01N)
-   Added obfuscation options into Empire CLI (@Cx01N)
-   Added Invoke-BOF module (@Cx01N)
-   Added C# server plugin to run on startup (@Cx01N)
-   Added autostart plugin with options to config file (@Cx01N)
-   Added upload & download options for Empire CLI (@Cx01N)
-   Added Plugin folders and extensions (@Cx01N)
-   Added C# redirector (@Cx01N)
-   Added Invoke-DownloadFile (@Cx01N)
-   Added error message in client for file downloads >1MB (@Cx01N)
-   Moved NVNC and Sharpire as C# submodules (@Cx01N)
-   Fixed Invoke-Assembley (@Cx01N)
-   Fixed osx/clipboard & pilliageuser modules (@Cx01N)
-   Removed unused wiki workflows (@Cx01N)

## [4.2.0] - 2021-11-01

-   Added revershell & cmd launchers with reversehell (@Cx01N)
-   Added ironpython to compile through empire with embedded std lib (@Cx01N)
-   Added proxy (SOCKS/TOR/HTTP) pivots to python agents (@Cx01N)
-   Added notifications in bottom toolbar for plugins and agents (@Cx01N)
-   Added C# VNC server (@Cx01N)
-   Added extended rights for certificate templates (@daem0nc0re)
-   Added donut for shellcode generation (@Cx01N)
-   Updated WMI persistence and bug fixes (@janit0rjoe)
-   Updated covenant compiler (@Hubbl3)
-   Updated csharp powershell launcher to compile through empire (@Hubbl3)
-   Fixed formatting error in enable_rdp (@jamarir)
-   Fixed nim launcher to run internal to exe (@Cx01N)
-   Fixed misc python module errors (@Cx01N)
-   Fixed outfile message displaying wrong directory (@Cx01N)
-   Removed sRDI for shellcode (@Cx01N)

## [4.1.3] - 2021-09-28

-   Fixed output from files throwing a error for the client (@Cx01N)

## [4.1.2] - 2021-09-21

-   Removed pyminifier as a dependency to prevent install errors (@Cx01N)

## [4.1.1] - 2021-09-20

-   Add OutputFunction to dcsync_hashdump (@jamarir)
-   Convert file operations to use with syntax (@jamarir)
-   Added Invoke-IronPython3 and some OffensiveDLR fixes (@Cx01N)
-   Fix for (#476) - String indices error  ms16-032 & ms16-135 (@Cx01N)
-   Fix help menu text on the interact menu (@archcloudlabs)
-   Rework agent taskings in the client to not poll for a result (@Cx01N)
-   Added Python agents to the external/generate_agent module (@Cx01N)
-   Update add_sid_history module command (@ilanisme)

## [4.1.0] - 2021-08-29

-   Correct issue where install script would break depending on the current working directory (@Vinnybod)
-   Empire client now currently refreshes listener list after killing a listener (@Vinnybod)
-   Removed the wiki and added a link to the new docs (@Vinnybod)
-   Added the initial filtering/hooking feature (@Vinnybod)
-   Fix an issue where the docker builds would not run because it was deleting the database (@Vinnybod)
-   Added autocomplete for taskings in the Empire Client and added a command to view a specific task (@Cx01N)
-   Updated the OutputFunction feature to allow for arbitrary values (@Vinnybod)
-   Added an IronPython3 agent (@Cx01N)

## [4.0.2] - 2021-08-16

-   Added socketio messages to screenshot/download/upload (@Cx01N)
-   Added help message when no input is given to empire.py (@Cx01N)
-   Fixed missing slash for module directories (@Cx01N)
-   Fixed modules Get-SQLServerLoginDefaultPw and PortScan (@jamarir)
-   Fixed formatting bug in the options table on the listener menu (@Vinnybod)
-   Fixed querying retain-last-value config parameters (@ilanisme)
-   Fixed invalid concat on keylogs (@Cx01N)
-   Fixed mimikatz command and added suggested values (@Cx01N)
-   Fixed misc bugs (@Vinnybod)
-   Updated suggested values for stagers and reformatted code (@Cx01N)
-   Updated editlistener menu (@Vinnybod)
-   Removed client suppression for job started taskings (@Cx01N)

## [4.0.1] - 2021-07-19

-   Added API endpoints for sleep/jitter to agents (@Cx01N)
-   Added sleep command to CLI (@Cx01N)
-   Added sleep/jitter option to C# agents (@Hubbl3)
-   Fix for Invoke-Obfuscation installation
-   Added PrintNightmare module (@Cx01N)

## [4.0.0] - 2021-06-28

### Breaking Changes

-   Removed old Empire CLI and cmdloop from server (@Cx01N)
-   The credential create endpoint now accepts a single credential instead of a list
-   Some endpoints which were previously throwing 500s when not found, now properly return a 404
-   Plugin endpoints and socketio channels renamed to plural (plugin -> plugins) to match naming convention of other resources (@Vinnybod)

### New Features

-   Integrated server and client into Empire (@Cx01N, @Vinnybod)
-   Introduced C# agents (@Hubbl3)
-   Integrated Covenant Roslyn compiler for task compilation (@Hubbl3)
-   Covenant Task compatibility (@Hubbl3, @Vinnybod)
-   Added support for 'suggested values' on the server and auto completing the suggested values in the CLI (@Vinnybod)
-   Added new launch parameters for starting server/client (@Cx01N, @Vinnybod)
-   Added Offensive DLR Modules: IronPython, ClearScript, & Boolang (@Cx01N)
-   Added MS16-051 stager (@Cx01N)
-   Added Start-ProcessAsUser module (@Cx01N)
-   Added NTLM-Extract module (@Cx01N)
-   Added Invoke-SharpSecDump module (@Cx01N)
-   Added sriptimport and scriptcommand to API (@Cx01N)
-   Added auto generate certificate function to startup script (@Cx01N)
-   Added Invoke-SpoolSample (@Cx01N)
-   Added redirector chaining and proper tunneling (@Cx01N)
-   Updated pycrypto to pycryptodome (@Cx01N)
-   Updated PowerDump with AES NTLM hashes (@Cx01N)
-   Updated cert/install/reset script with new directories (@Cx01N)
-   Updated all modules to new YAML format (@Vinnybod, @Cx01N)
-   Updated to Mimikatz 2.2.0 20210531 X11 RDP Clients (@Cx01N)
-   Removed M2Crypto dependency (@Cx01N)
-   Simplified kill/remove commands and added 'all' and 'stale' options (@Cx01N)
-   Removed the need for manual database timestamp updates, merge taskings and results table to a single table (@Vinnybod)
-   Added a socketio event for when tasking results come back (@Vinnybod)
-   Readded rastamouse's bypass (@Cx01N)
-   Added a 'since' query parameter to the tasks endpoint for more efficient querying (@Vinnybod)
-   Added socketio tasking event handler to CLI for displaying task results in the interact menu (@Vinnybod)
-   Install script prompts for xar, bomutils, openjdk, and dotnet for a more streamlined install (@Vinnybod)
-   Install script now includes dotnet (@Vinnybod)
-   Dockerfile size decreased by ~1GB by only installing the essentials. There is a note in the README (@Vinnybod)
-   Made powershell bypasses dynamic. Now set with a single field `Bypasses` and they will be applied in the order provided (@Vinnybod)
-   Added API endpoints for managing bypasses (@Vinnybod)
-   Add processor architecture to powershell, csharp, and python agents (@Vinnybod)
-   Add a display command to interact menu (@Vinnybod)
-   Add additional endpoints for credential for get, update, and delete (@Vinnybod)
-   Add create, update, remove credential functionality to the CLI (@Cx01N)
-   Add an "output function" option on several modules (@jamarir)
-   Updated shellcoderdi to newest version (@Cx01N)
-   Added a Nim launcher (@Hubbl3)

[Unreleased]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v6.3.0...HEAD

[6.3.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v6.2.1...v6.3.0

[6.2.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v6.2.0...v6.2.1

[6.2.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v6.1.4...v6.2.0

[6.1.4]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v6.1.3...v6.1.4

[6.1.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v6.1.2...v6.1.3

[6.1.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v6.1.1...v6.1.2

[6.1.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v6.1.0...v6.1.1

[6.1.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v6.0.3...v6.1.0

[6.0.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v6.0.2...v6.0.3

[6.0.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v6.0.1...v6.0.2

[6.0.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v6.0.0...v6.0.1

[6.0.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.12.2...v6.0.0

[5.12.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.12.1...v5.12.2

[5.12.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.12.0...v5.12.1

[5.12.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.11.7...v5.12.0

[5.11.7]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.11.6...v5.11.7

[5.11.6]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.11.5...v5.11.6

[5.11.5]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.11.4...v5.11.5

[5.11.4]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.11.3...v5.11.4

[5.11.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.11.2...v5.11.3

[5.11.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.11.1...v5.11.2

[5.11.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.11.0...v5.11.1

[5.11.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.10.3...v5.11.0

[5.10.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.10.2...v5.10.3

[5.10.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.10.1...v5.10.2

[5.10.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.10.0...v5.10.1

[5.10.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.9.5...v5.10.0

[5.9.5]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.9.4...v5.9.5

[5.9.4]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.9.3...v5.9.4

[5.9.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.9.2...v5.9.3

[5.9.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.9.1...v5.9.2

[5.9.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.9.0...v5.9.1

[5.9.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.8.4...v5.9.0

[5.8.4]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.8.3...v5.8.4

[5.8.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.8.2...v5.8.3

[5.8.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.8.1...v5.8.2

[5.8.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.8.0...v5.8.1

[5.8.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.7.3...v5.8.0

[5.7.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.7.2...v5.7.3

[5.7.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.7.1...v5.7.2

[5.7.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.7.0...v5.7.1

[5.7.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.6.4...v5.7.0

[5.6.4]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.6.3...v5.6.4

[5.6.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.6.2...v5.6.3

[5.6.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.6.1...v5.6.2

[5.6.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.6.0...v5.6.1

[5.6.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.5.4...v5.6.0

[5.5.4]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.5.3...v5.5.4

[5.5.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.5.2...v5.5.3

[5.5.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.5.1...v5.5.2

[5.5.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.5.0...v5.5.1

[5.5.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.4.2...v5.5.0

[5.4.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.4.1...v5.4.2

[5.4.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.4.0...v5.4.1

[5.4.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.3.0...v5.4.0

[5.3.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.2.2...v5.3.0

[5.2.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.2.1...v5.2.2

[5.2.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.2.0...v5.2.1

[5.2.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.1.2...v5.2.0

[5.1.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.1.1...v5.1.2

[5.1.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.1.0...v5.1.1

[5.1.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.0.4...v5.1.0

[5.0.4]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.0.3...v5.0.4

[5.0.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.0.2...v5.0.3

[5.0.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.0.1...v5.0.2

[5.0.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v5.0.0...v5.0.1

[5.0.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.10.0...v5.0.0

[4.10.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.9.0...v4.10.0

[4.9.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.8.4...v4.9.0

[4.8.4]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.8.3...v4.8.4

[4.8.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.8.2...v4.8.3

[4.8.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.8.1...v4.8.2

[4.8.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.8.0...v4.8.1

[4.8.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.7.3...v4.8.0

[4.7.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.7.2...v4.7.3

[4.7.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.7.1...v4.7.2

[4.7.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.7.0...v4.7.1

[4.7.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.6.1...v4.7.0

[4.6.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.6.0...v4.6.1

[4.6.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.5.5...v4.6.0

[4.5.5]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.5.4...v4.5.5

[4.5.4]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.5.3...v4.5.4

[4.5.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.5.2...v4.5.3

[4.5.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.5.1...v4.5.2

[4.5.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.5.0...v4.5.1

[4.5.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.4.1...v4.5.0

[4.4.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.4.0...v4.4.1

[4.4.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.3.3...v4.4.0

[4.3.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.3.2...v4.3.3

[4.3.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.3.1...v4.3.2

[4.3.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.3.0...v4.3.1

[4.3.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.2.0...v4.3.0

[4.2.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.1.3...v4.2.0

[4.1.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.1.2...v4.1.3

[4.1.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.1.1...v4.1.2

[4.1.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.1.0...v4.1.1

[4.1.0]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.0.3...v4.1.0

[4.0.3]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.0.2...v4.0.3

[4.0.2]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.0.1...v4.0.2

[4.0.1]: https://github.com/BC-SECURITY/Empire-Sponsors/compare/v4.0.0...v4.0.1

[4.0.0]: https://github.com/BC-SECURITY/Empire-Sponsors/releases/tag/v4.0.0
