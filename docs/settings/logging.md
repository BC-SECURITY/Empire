# Logging

### Logging

The logging for the server is logged to the file `~/.local/share/empire/logs/empire_server.log` and to the console. By default, the logging level is set to `INFO`.

### Listener Logging

Listeners have their own logging configuration. All logs `debug` and above are written to the file `~/.local/share/empire/logs/listener_<listener_name>.log`, and all logs `warning` and obove will go to the console.

If there is a log message that you also want sent to the server log and console, also log it to the module logger with `log.info()`.

To use the listener logger for the `http` listener, you can use the following command: `self.instance_log.info()`.

### Formatters

The default formatter for the console is the "simple format" that just contains the log level and message. The expanded logging format contains extra info such as a timestamp and the line of code that triggered the log. The expanded format is used in the server log file and can be enabled for the console logger using `logging.simple_console`

### Configuration

```yaml
logging:
  level: INFO
  directory: empire/server/downloads/logs/
  simple_console: true
debug:
  last_task:
    enabled: false
    file: empire/server/data/last_task.txt
```

Log level for the root server log defaults to `INFO`. It can be changed by passing the `--log-level` flag to the server, which expects a string of one of the following values: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. If no command line flag is passed, the config file is used.

The log directory can be changed by setting the `logging.directory` property in the config file.

`simple_console` changes the console logging format to just the log level and message, instead of the extended format.

`debug.last_task` will cause Empire to save the input of the last task that was run to a file.

### Command Line Flags

`--log-level <level>` Sets the log level for the server.

`--debug` Sets the log level for the server to `DEBUG`.

### Development

In Empire 5 and beyond, if you want to print something to the console, you should almost always be using the `logging` module instead of a print statement.

Not all print statements have been removed from the code yet, simply because there was just a lot of code to convert. If you find a print statement that should be removed: either replace it with logging, remove it, or see if it should be returned via the api (such as in stager generation).

### Possible future features

#### JSON Logging

Add support for logging in JSON format to make it easier to parse the logs and integrate with other tools, such as with [structlog](https://www.structlog.org/en/stable/) or [python-json-logger](https://github.com/madzak/python-json-logger).

#### Plugin logging

Give each plugin their own log file. With this, we could add endpoints to pull or tail the logs for a specific plugin. This could be useful for debugging and for the plugin executions that produce many lines of response for a single action to be viewed in Starkiller.
