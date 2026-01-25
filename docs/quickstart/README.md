# Quickstart

## Run Commands

Empire uses a server/client architecture which is handled automatically by the startup script. The server will continue running from the terminal that it is launched from and Starkiller will be started on the configured port

### Server

```bash
# Start Server
./ps-empire server

# Help
./ps-empire server -h
```

The server can be reset by passing a `--reset` flag. This will delete the database and any files that were created at runtime. It is recommended to run a `--reset` after any upgrades.

```
./ps-empire server --reset
```

Default credentials are set in the config.yaml and are:

```
Username: empireadmin
Password: password123
```

It is strongly recommended that these be changed if Empire is being used for any kind of operational engagement.

## Listeners 101

The first thing you need to do is set up a local listener. The **listeners** tab will display any active listeners, and active listeners can be disabled or modified from this tab. The `create` button in the top right will prompt you to select a listener type to build. The dropdown supports fuzzy search and tab completion. Each listener will have its own set of required and optional parameters.

![](../.gitbook/assets/listeners_tab.png)

HTTP is the most commonly used lsitener and supports both HTTP and HTTPS. For HTTPS, you must first set the CertPath to be a local .pem file. The provided **./setup/cert.sh** script will generate a self-signed cert and place it in **\~/.local/share/empire/cert/empire.pem**.

Set any optional paramaters such as WorkingHours, KillDate, DefaultDelay, and DefaultJitter for the listener, as well as whatever name you want it to be referred to as. You can then hit **submit** to start the listener. If the name is already taken, a nameX variant will be used, and Empire will alert you if the port is already in use.

## Stagers 101

The staging process is described \[\[here|Staging]].

Empire implements various stagers in a modular format in **./empire/server/stagers/** . These include dlls, macros, one-liners, and more. To use a stager, select the stagers tab and click **create**, and you'll be taken to the individual stager's menu. The stagers tab will display any previously created stagers, along with key information about it them such as the agent lanuague it will use and what listener it is keyed to.

![](../.gitbook/assets/stagers.png)

For UserAgent and proxy options, default uses the system defaults, none clears that option from being used in the stager, and anything else is assumed to be a custom setting (note, this last bit isn't properly implemented for proxy settings yet).

## Agents 101

When an agent checks in you will get a notification both on the server and in Starkiller.

![](../.gitbook/assets/server_check_in.png) ![](../.gitbook/assets/starkiller_checkin.png)

Once you have recieved a check in notification you can go to the agents tab and see all checked in agents. If an agent has turned red it means that the agent has failed to checkin and the server can not currently communicate with it. These are reffered to as stale agents

![](../.gitbook/assets/agents_tab.png)

From here you can click on any agent where you will be presented with a number of tabs including the interact tab for running modules, tasks, and view. The view tab will provide you informaiton that has been collected about the host along with other key informaiton like delay and jitter intervals.

For each registered agent, a `downloads/AGENT_NAME/` folder is created. An `agent.log` is created here with timestamped commands/results for agent communication. Downloads/module outputs are broken out into relevant folders here as well.

When you're finished with an agent, you can either kill it from its interaction page or from the Agents tab.

## Modules 101

To see available modules, use the modules tab under agents. This will provide a list of all available modules within Empire. These modules can be searched with the search bar on the lift or filiterd based on a number of criteria.

![](../.gitbook/assets/modules.png)

Clicking on a module will take you to module overview where can read more information and configure settings. You can also select agents to task the module to and can deploy a module to multiple agents simultaneously

![](../.gitbook/assets/multi_agent_tasking.png)
