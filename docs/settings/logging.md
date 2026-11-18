Logging
----

The logging for the server is logged to the file `<data-dir>/logs/empire_server.log` (`~/.local/share/empire/logs/empire_server.log` by default; see [data & config locations](../quickstart/server.md#data--config-locations)) and to the console (file output is skipped when `logging.file_logging` is `false`).
By default, the logging level is set to `INFO`.


## Listener Logging
Listeners have their own logging configuration. Unless `logging.file_logging` is `false`, all logs `debug` and above are written to
the file `<data-dir>/logs/listener_<listener_name>.log` (Linux default `~/.local/share/empire/logs/listener_<listener_name>.log`), and all logs `warning` and above will go to the console.
If `logging.file_logging` is `false`, only the `warning` and above console output remains; see
[Docker / console-only logging](#docker--console-only-logging).

If there is a log message that you also want sent to the server log and console,
also log it to the module logger with `log.info()`.

To use the listener logger for the `http` listener, you can use the following command:
`self.instance_log.info()`.


## Formatters
The default formatter for the console is the "simple format" that just contains the log level and message.
The expanded logging format contains extra info such as a timestamp and the line of code that triggered the log.
The expanded format is used in the server log file and can be enabled for the console logger using
`logging.simple_console`

## Configuration
```yaml
logging:
  level: INFO
  simple_console: true
  file_logging: true
  max_bytes: 10485760
  backup_count: 5
debug:
  last_task:
    enabled: false
    file: debug/last_task.txt
```

Log level for the root server log defaults to `INFO`.
It can be changed by passing the `--log-level` flag to the server,
which expects a string of one of the following values: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`.
If no command line flag is passed, the config file is used.

Log files live under `<data-dir>/logs`.

`simple_console` changes the console logging format to just the log level and message,
instead of the extended format.

`file_logging` controls whether Empire writes log files at all. It defaults to `true`.
See [Docker / console-only logging](#docker--console-only-logging) below.

`max_bytes` and `backup_count` control rotation of `empire_server.log` and every
`listener_<name>.log`. When a file reaches `max_bytes` it is renamed to `.1`, `.1` becomes
`.2`, and so on up to `backup_count`; the oldest rotated file is deleted. With the defaults
(10 MB, 5 backups) each log is capped at about 60 MB on disk. Rotated-out data is gone,
so on a busy engagement where you need the full listener record, raise the limits or set
`max_bytes: 0` (or `backup_count: 0`) to disable rotation and keep a single unbounded file,
which was the behavior before these options existed.

`debug.last_task` will cause Empire to save the input of the last task that was run to a file.

### Docker / console-only logging
Empire's console output goes to stderr, which container runtimes capture along with stdout
(`docker logs`, Kubernetes, Cloud Run). To log only to the console, set:

```yaml
logging:
  file_logging: false
```

or, without touching the config file:

```bash
EMPIRE_LOGGING__FILE_LOGGING=false
```

With file logging off, no `logs/` directory is created and the server and listener log files
are not written. Per-agent `agent.log` files under the downloads directory are unaffected.
Listener loggers still send `warning` and above to the console, but their `info` and `debug`
records are dropped. Those include a line per agent check-in with the raw session cookie,
which would otherwise flood the console and land in the container's log collector.

The runtime, not Empire, then decides how much of that output is kept. Docker's default
`json-file` log driver does not rotate on its own; cap it with
`--log-opt max-size=10m --log-opt max-file=5` (or the `logging:` block in Compose).

## Command Line Flags
`--log-level <level>`
    Sets the log level for the server.

`--debug`
    Sets the log level for the server to `DEBUG`.

## Development
In Empire 5 and beyond, if you want to print something to the console, you should
almost always be using the `logging` module instead of a print statement.

Not all print statements have been removed from the code yet, simply because there was just a lot of code to convert.
If you find a print statement that should be removed: either replace it with logging, remove it, or see if it should be returned via the api (such as in stager generation).

## Possible future features

### JSON Logging
Add support for logging in JSON format to make it easier to parse the logs and integrate with other tools, such as with [structlog](https://www.structlog.org/en/stable/) or [python-json-logger](https://github.com/madzak/python-json-logger).

### Plugin logging
Give each plugin their own log file. With this, we could add endpoints to pull or tail the
logs for a specific plugin. This could be useful for debugging and for the plugin executions
that produce many lines of response for a single action to be viewed in Starkiller.
