# Server

The Server configuration is managed via [empire/server/config.yaml](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/config.yaml).

Once launched, Empire checks for user write permissions on paths specified in `config.yaml`. If the current user does not have write permissions on these paths, `~/.empire` will be set as fallback parent directory and the configuration file will be updated as well. If `empire-priv.key` and `empire-chain.pem` are not found in the data directory (`~/.local/share/empire` by default; see [data & config locations](#data--config-locations)), self-signed certs will be generated.


## User Config Overrides

To customize settings without modifying `config.yaml`, create a `config.user.yaml` file in the same directory as the base config (e.g. `~/.config/empire/config.user.yaml`). This file only needs to contain the settings you want to override — everything else falls through to the base config.

For example, to override the API port and database type:

```yaml
api:
  port: 8443
database:
  use: mysql
  mysql:
    password: my_secret_password
```

The config priority order (first wins):
1. Environment variables (`EMPIRE_*`, e.g. `EMPIRE_API__PORT=8443`)
2. `.env` file
3. `config.user.yaml` (user overrides)
4. `config.yaml` (base defaults)

Nested settings are deep-merged: overriding `database.mysql.password` in `config.user.yaml` does not affect sibling fields like `database.mysql.username`. Lists are replaced entirely rather than appended.

If using `--config /path/to/config.yaml`, Empire looks for `config.user.yaml` in the same directory as the specified config file.

## Data & config locations

Empire uses [platformdirs](https://pypi.org/project/platformdirs/) for its base
directories, so paths are XDG-compliant:

| Purpose | Default |
|---------|---------|
| Config (`config.yaml`, `config.user.yaml`) | `~/.config/empire` |
| Data (DB, certs, logs, downloads, backups, clones) | `~/.local/share/empire` |
| Cache (Go build cache) | `~/.cache/empire` |

These honor `$XDG_CONFIG_HOME` / `$XDG_DATA_HOME` / `$XDG_CACHE_HOME` when set.
The examples elsewhere in the docs use the defaults above.

* **suppress-self-cert-warning** - Suppress the http warnings when launching an Empire instance that uses a self-signed cert.
* **obfuscation** - Settings for the obfuscation subsystem.

  * **timeout** - Maximum time in seconds allowed for a single PowerShell obfuscation subprocess. Large modules like PowerView (~4000 lines) and Invoke-Mimikatz (~12000 lines) may exceed the default on resource-constrained environments (e.g. single-CPU containers). Set to `0` to disable the timeout entirely. Also settable via the `EMPIRE_OBFUSCATION__TIMEOUT` environment variable.

```yaml
obfuscation:
  # Default: 300
  timeout: 600
```

* **api** - Configure the RESTful API.

ip - The IP address to bind the API and Starkiller to. port - The port to bind the API and Starkiller to. secure - Enable HTTPS for the API and Starkiller. Browsers will not work with self-signed certs. Uses .key and .pem file from empire/server/data

```yaml
api:
  ip: 0.0.0.0
  port: 1337
  secure: false
```

* **database** - Configure Empire's database. Empire utilizes MySQL by default for high performance database operations. It can be configured to use sqlite for more lightweight implementations if required For more info on the database, see the [Database](../database/README.md) section.

MySQL supports customizing the default url, username, password, database name, and connection pool settings. By default these are set to

```yaml
database:
  use: mysql
  mysql:
    url: localhost:3306
    username: empire_user
    password: empire_password
    database_name: empire
    pool_size: 10        # base connections kept open
    max_overflow: 15     # extra connections allowed under load
    pool_pre_ping: true  # detect stale connections before use
    pool_recycle: 3600   # recycle connections after N seconds
```

The connection pool defaults (25 total connections) handle typical deployments. For heavier workloads with many concurrent agents, increase `pool_size` and `max_overflow`.

If using SQLite the database location is customizable with the default setting:

```yaml
database:
  use: sqlite
  sqlite:
    location: empire/server/data/empire.db
```

The defaults block defines the properties that are initially loaded into the database when it is first created. These include the staging key, default user and password, obfuscation settings, and default bypasses.

```yaml
database:
  defaults:
    # staging key will first look at OS environment variables, then here.
    # If empty, will be prompted (like Empire <3.7).
    staging-key: RANDOM
    username: empireadmin
    password: password123
    # The default configuration for global obfuscation.
    obfuscation:
      - language: powershell
        enabled: false
        command: "Token\\All\\1"
        module: "invoke-obfuscation"
        preobfuscatable: true
      - language: csharp
        enabled: false
        command: ""
        module: "confuser"
        preobfuscatable: false
    keyword_obfuscation:
      - Invoke-Empire
      - Invoke-Mimikatz
    bypasses:
      - mattifestation
      - etw
    ip_allow_list: []
    ip_deny_list: []
```

* **empire\_compiler** - Configure the Empire Compiler module. This block manages settings for the Empire Compiler, which is responsible for handling C# compilation tasks.

repo: The GitHub repository in `owner/name` format (e.g. `BC-SECURITY/Empire-Compiler`).
ref: The release tag to download (e.g. `v0.4.4`). Empire queries the GitHub Releases API to find the matching platform asset.
directory: (optional) Path to a local compiler directory. When set, Empire uses this directory directly instead of downloading from GitHub. Useful for testing local builds.

```yaml
empire_compiler:
  repo: BC-SECURITY/Empire-Compiler
  ref: v0.4.4
  # Uncomment to use a local compiler build instead of downloading:
  # directory: /path/to/local/EmpireCompiler
```

* **starkiller** - Configure the Starkiller web UI that Empire serves at its own IP and port.

enabled: Whether to serve Starkiller at all.
repo: The git repository to clone Starkiller from.
ref: A branch, tag, or commit hash.
directory: (optional) Path to an already-built Starkiller. When set, Empire serves that build directly and never clones from GitHub — this is what makes air-gapped and distro-packaged installs possible. `./ps-empire update` reports the override and never writes to it, so an externally managed or read-only directory is left alone.

`directory` accepts either a directory containing a `dist/index.html` build (a git checkout that has been built) or the build output itself (an `index.html` beside its assets, which is what a packaged build like the nixpkgs derivation produces). When both match, `dist/` wins. A source checkout that has not been built is rejected rather than served — its root `index.html` is a build-time template, so serving it would render a blank page. A `dist/` with no `index.html` in it is rejected too: an interrupted build leaves one behind, and so does any unrelated project.

When set and the path is missing or holds no build, the server logs the problem, starts without a UI, and does **not** fall back to cloning — a typo would otherwise serve upstream Starkiller in place of your build. `./ps-empire setup` and `./ps-empire update` check the same conditions and exit non-zero when any fails, so a bad override is caught at install or upgrade time rather than at the next boot. Both skip the check when `enabled` is false — a UI you have switched off will not fail your install.

Use an **absolute** path. A relative value is kept verbatim and resolved against the process's working directory, so `setup` (run from the repo root) and the server (launched by a systemd unit, console script, or container) can end up resolving the same value to different directories; `setup` warns when it sees one.

Put `directory` in `config.user.yaml`, not in the base `config.yaml`. `./ps-empire update` overwrites the base config with the shipped template on every run, which would drop the override and let the next boot clone from GitHub.

```yaml
# ~/.config/empire/config.user.yaml
starkiller:
  directory: /opt/starkiller   # a dist/ parent, or the build output itself
```

* **plugins** - Config related to plugins auto\_start - boolean, whether the plugin should start automatically. If this is not set, Empire will defer to the plugin's own configuration. auto\_execute - run an execute command on the plugin at startup. If this is not set, Empire will defer to the plugin's own configuration.

```yaml
plugins:
  # Auto-execute plugin with defined settings
  basic_reporting:
    auto_start: true
    auto_execute:
      enabled: true
      options:
        report: all
```

* **plugin\_marketplace** - This points the server to where Empire should look for additional available plugins to install. This defaults to the BC Security plugin marketplace but can point to a private marketplace as well. name - the display name for the marketplace in Empire git\_url - git project to pull plugins from

```yaml
plugin_marketplace:
  registries:
    - name: BC-SECURITY
      git_url: git@github.com:BC-SECURITY/Empire-Plugin-Registry-Sponsors.git
      ref: '7.x'
      file: registry.yaml
```

`ref` is pinned per Empire major line: every 7.x release reads the registry's
`7.x` branch, and `main` stays pinned to the already-shipped 6.x installs.
Repointing it at `main` on a 7.x server resolves plugin refs from the 6.x line.

* **directories** - Control where Empire should read and write specific data.

```yaml
directories:
  downloads: downloads
```

* **logging** - See [Logging](../settings/logging.md) for more information on logging configuration.
