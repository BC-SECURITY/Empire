# RESTful API

## Introduction
The Empire v2 API is a RESTful API that provides access to the data in Empire. It was introduced in Empire 5.0 and replaced the old v1 API.
The API is powered by [FastAPI](https://fastapi.tiangolo.com/) and is available at [http://localhost:1337/api/v2/](http://localhost:1337/api/v2/).
The Swagger UI is available at [http://localhost:1337/docs/](http://localhost:1337/docs/).
The docs here are to be used as a reference for the API and to explain nuances for interacting with it. For actual endpoint definitions, use the OpenAPI Spec. For explanations of what the heck a listener, stager, etc is, see the associated non-API documentation.

The server can be launched by running `./ps-empire server` and can be connected to with the built-in client or [Starkiller](https://github.com/BC-SECURITY/Starkiller). By default, the RESTful API is started on port 1337, over HTTP without a certificate. This is because self-signed certs are blocked by most web browsers and Starkiller is used via a web browser.

If launched with `--secure-api`, https will be used using the certificate located at `empire/server/data/empire.pem`, which is generated at startup.

The port can be configured in the server `config.yaml` file by the `api.port` property.
It can also be set by supplying `--restport <PORT_NUM>` on launch, which will take precedence over the config file.

## API Authentication
API Authentication is handled via JSON Web Tokens (JWT).
The default username for the API is `empireadmin` and the default password is `password123`.

To login, POST to the http://localhost:1337/token endpoint with the username and password. The response will contain a field called `access_token`. This token is the JWT that should be sent on subsequent requests as an Authorization header. (ie `Authorization: Bearer {access_token}`).

## Endpoints

### Listener Templates
*/api/v2/listener-templates/*
Listener templates are the "types" of templates that can be used to create listeners.
A listener template defines the options that can be used when creating a listener.
Listener templates are read-only via the API.

The options that are listed are derived from the associated listener objects. The `value` field will always be a string,
for a consistent API object, but the `type` field will tell the client how to interpret the value.

### Listeners
*/api/v2/listeners/*
Listeners are created by using a listener template. The create endpoint expects the
options dictionary to contain the options that are required for associated listener template
and will be validated against the template. The options can be sent as strings, but Empire will
still validate that they can be parsed to the correct type and raise an exception if it isn't correct.

They can be created, updated, enabled/disabled, and deleted via the API. To update a listener,
it must be disabled first.

### Stager Templates
*/api/v2/stager-templates/*
Stager templates are the "types" of templates that can be used to create stagers.
A stager template defines the options that can be used when creating a stagers.
Stager templates are read-only via the API.

The options that are listed are derived from the associated stager objects. The `value` field will always be a string,
for a consistent API object, but the `type` field will tell the client how to interpret the value.

### Stagers
*/api/v2/stagers/*
Stagers are created by using a stager template. The create endpoint expects the
options dictionary to contain the options that are required for associated stager template
and will be validated against the template. The options can be sent as strings, but Empire will
still validate that they can be parsed to the correct type and raise an exception if it isn't correct.

They can be created, updated, and deleted via the API.
When creating a stager, there is an option to only "generate" instead of save.
If `save=false`, then the stager will not be saved to the database, but will be returned in the response. If the stager is a file, then the response will contain a reference to the download uri for that file.

### Agents
*/api/v2/agents/*
The agent endpoints allow for updating specific fields and deleting (aka killing or archiving).
The agent endpoints also have sub-resources for tasks and files.

#### Agent Checkins
*/api/v2/agents/{agent_id}/checkins/*
The agent checkins endpoints are for viewing the checkins for an agent. Checkins are created every time an agent checks in with the server. The checkins are read-only via the API.

*/api/v2/agents/checkins/aggregate/*
The aggregate endpoint is a read-only view of the checkins for an agent. It is a summary of the checkins for agents over time.

#### Agent Tasks
*/api/v2/agents/{agent_id}/tasks/*
The agent tasks endpoints are for tasking an agent to do something.
While there are a variety of `POST` endpoints for specific types of tasks, the resulting
objects are the same and can be viewed together via the `GET` endpoints. Tasks also support deletion as long as they are still only queued to run (the agent hasn't seen it yet).

Some tasks have the ability to join in a `Download`, if this is the case, the downloads will appear as a property on the task response with a reference to the uri.

#### Agent Files
*/api/v2/agents/{agent_id}/files/*
The agent files endpoints are a read only view of the the files on an agent's machine.
To populate agent files, a task must be run to get a list of files. At the moment running an `ls`
will populate this resource because of a [hook](../plugins/development/hooks-and-filters.md) that is built in to Empire. There is also a `DirectoryList` task that also populates these, which is what the File Browser in Starkiller uses.

If a file is downloaded, then the associated AgentFile record will have a joined `Download` record. Just like Stagers and Agent Tasks, if a download is associated with a file, it will be returned along with the file with a reference to the uri to download it.

### Modules
*/api/v2/modules/*
The modules endpoints provide a way to view the currently loaded modules in Empire.
At the moment, there is no way to create modules via the API, they must exist on the server
at the time that the server is ran. There is an update endpoint that allows for enabling and disabling a module. Disabling a module will block it from being allowed to execute.

### Hosts
*/api/v2/hosts/*
Hosts are read-only via the API. Hosts represent the machines that agents are running on.
Multiple agents can run on a single host. The resources are generated when an agent connects and
is based on its internal IP address and name.

### Host Processes
*/api/v2/hosts/{host_id}/host-processes/*
Host processes are the processes that are scraped via the `ps` command on an agent. They are read-only via the API.

### Downloads
*/api/v2/downloads*
The downloads API allows for downloading of files from the Empire server.
Downloads are linked to the following sources (and can be expanded in the future):
* Saved stagers
* Downloaded agent files, such as via the file browser or a task
* Agent tasks

A user can also upload a file to the server via the `POST` endpoint. That file can then
be referenced to be used in certain modules.

### Credentials
*/api/v2/credentials*
Credentials support basic CRUD operations via the API.
They can also be generated by agent tasks.

### Obfuscation
#### Keywords
*/api/v2/obfuscation/keywords*
Keyword obfuscation supports basic CRUD operations via the API.
These are used for the `keyword replacement` feature within Empire.

#### Global Obfuscation
*/api/v2/obfuscation/global*
The global obfuscation endpoint allows for getting and modifying the global obfuscation configuration
for a language. Modules can be pre-obfuscated by using the `/preobfuscate` endpoint after configuring the obfuscation.

### Bypasses
*/api/v2/bypasses*
Bypasses support basic CRUD operations via the API.
Once created, these can be passed into the `Bypasses` field of a stager.

The `/api/v2/bypasses/default` endpoint returns the default bypasses configured in `config.yaml` under `database.defaults.bypasses`. These default bypasses are automatically applied to stagers and modules when they are generated.

### Malleable Profiles
*/api/v2/malleable-profiles*
Malleable Profiles support basic CRUD operations via the API.
They are initially loaded via .profile files on Empire startup, and then can be change via the API. Once created, they can be passed as an option to the malleable listener.

### Plugins
*/api/v2/plugins*
The plugin endpoints allow for the management of plugins. There is an endpoint for getting a single plugin, as well as a list of all plugins.
The `execute` endpoint allows for the execution of a plugin's code. Like a listener, stager, or module, the plugin defines its options in code, and the options can be sent as strings, but Empire will still validate that they can be parsed to the correct type and raise an exception if it isn't correct.

### Meta
*/api/v2/meta*
The meta endpoints are for getting information about the server itself.
At the moment, there is only an endpoint for getting the version of the server.

### Users
*/api/v2/users*
Users support basic CRUD operations via the API.
There is also an endpoint for updating a user's password. Only an admin user can create and
update other users.
