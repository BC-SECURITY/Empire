# Table of contents

* [Empire](README.md)
* [Quickstart](quickstart/README.md)
  * [Installation](quickstart/installation/README.md)
    * [Common Issues](quickstart/installation/common-issues.md)
  * [Server](quickstart/server.md)
  * [Resetting](quickstart/resetting.md)
* [Starkiller](starkiller/README.md)
  * [Introduction](starkiller/introduction.md)
  * [Agent Tasks](starkiller/agent-tasks.md)
* [Listeners](listeners/README.md)
  * [Dropbox](listeners/dropbox.md)
  * [OneDrive](listeners/onedrive.md)
  * [HTTP](listeners/http.md)
  * [Malleable C2](listeners/malleable-c2.md)
* [Stagers](stagers/README.md)
  * [multi\_generate\_agent](stagers/multi_generate_agent.md)
* [Plugins](plugins/README.md)
  * [Development](plugins/development/README.md)
    * [Imports](plugins/development/imports.md)
    * [Lifecycle Hooks](plugins/development/lifecycle-hooks.md)
    * [Execution](plugins/development/execution.md)
    * [Hooks and Filters](plugins/development/hooks-and-filters.md)
    * [Plugin Tasks](plugins/development/plugin-tasks.md)
    * [Notifications](plugins/development/notifications.md)
    * [Database Usage](plugins/development/database-usage.md)
    * [Settings](plugins/development/settings.md)
    * [Migration](plugins/development/migration.md)
* [Modules](modules/README.md)
  * [Module Configuration](modules/module-configuration.md)
  * [Autorun Modules](modules/autorun_modules.md)
  * [Module Development](modules/module-development/README.md)
    * [PowerShell Modules](modules/module-development/powershell-modules.md)
    * [Python Modules](modules/module-development/python-modules.md)
    * [C# Modules](modules/module-development/c-modules.md)
    * [BOF Modules](modules/module-development/bof-modules.md)
* [Agents](agents/README.md)
  * [Python](agents/python/README.md)
    * [Main Agent Class](agents/python/mainagentclass.md)
    * [Stage Class](agents/python/stageclass.md)
    * [Packet Handler Class](agents/python/packethandlerclass.md)
    * [Extended Packet Handler Class](agents/python/extendedpackethandlerclass.md)
  * [Go](agents/go/README.md)
    * [Main Agent Class](agents/go/mainagentclass.md)
    * [Packet Handler Class](agents/go/packethandlerclass.md)
    * [Main.go Template](agents/go/template.md)
  * [Staging](agents/staging.md)
* [RESTful API](restful-api/README.md)
  * ```yaml
    type: builtin:openapi
    props:
      models: true
      downloadLink: true
    dependencies:
      spec:
        ref:
          kind: openapi
          spec: bc-security-api
    ```
* [Settings](settings/README.md)
  * [Logging](settings/logging.md)
  * [Bypasses](settings/bypasses.md)
  * [IP Filtering](settings/ip-filtering.md)
