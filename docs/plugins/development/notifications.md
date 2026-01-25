# Notifications

Notifications are meant for time sensitive information that the user should be aware of. In Starkiller, these get displayed immediately, so it is important not to spam them.

To send a notification, use the `send_socketio_message` from the `BasePlugin`.

```python
def execute(self, command, **kwargs):
    self.send_socketio_message("Helo World!")
```
