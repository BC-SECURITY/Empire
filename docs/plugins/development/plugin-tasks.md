# Plugin Tasks

Plugins can store tasks. The data model looks pretty close to Agent tasks. This is for agent executions that:

1. Want to attach a file result
2. Need to display a lot of output, where notifications don't quite work
3. Has output you'll want to look back at later

```python
from empire.server.core.db import models

def execute(self, command, **kwargs):
    user = kwargs.get('user', None)
    db = kwargs.get('db', None)
    plugin_options = kwargs.get('plugin_options', None)

    input = 'Example plugin execution.'

    plugin_task = models.PluginTask(
      plugin_id=self.info["Name"],
      input=input,
      input_full=input,
      user_id=user.id,
      status=models.PluginTaskStatus.completed,
      plugin_options=plugin_options,
    )

    db.add(plugin_task)
```

For an example of using plugin tasks and attaching files, see the [basic\_reporting plugin](https://github.com/BC-SECURITY/Empire/blob/main/server/plugins/basic_reporting/basic_reporting.plugin).

## Statuses

Plugin tasks in Empire follow a similar lifecycle to agent tasks, with status updates providing key insights into the progress and outcomes of various plugin operations. Below are the possible statuses for plugin taskings along with descriptions and representative icons.

### Queued

* **Description**: The task is queued for the plugin. This status indicates that the task has been created and is waiting to be pulled by the server.
* **Icon**:&#x20;

### Started

* **Description**: The plugin has successfully pulled and started the tasking. This status signifies that the server has received the task and is either processing it or about to start processing.
* **Icon**:&#x20;

### Completed

* **Description**: The task has returned data successfully. This indicates that the plugin has finished executing the task and has returned the output.
* **Icon**:&#x20;

### Error

* **Description**: If an plugin reports an error for a task, it will return an ERROR status. This status allows users to identify tasks that did not execute as expected.
* **Icon**: )

### Continuous

* **Description**: A special class for modules like keylogging since they are handled differently on the server due to their continuous nature. These tasks do not have a definite end and run continuously until stopped.
* **Icon**:&#x20;
