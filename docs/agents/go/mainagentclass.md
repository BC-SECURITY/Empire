# Main Agent Class

The `MainAgent` class manages the core functionality of the agent after the staging process. It handles communication with the Empire server, tasking execution, and results reporting.

## Attributes

* **packet\_handler**: The `PacketHandler` instance responsible for encrypting/decrypting messages to/from the server.
* **server**: The base URL of the command and control (C2) server.
* **session\_id**: A unique identifier for the current session.
* **kill\_date**: The date when the agent will terminate itself.
* **working\_hours**: The agent's allowed operation window.

## Methods

### `run()`

Continuously checks in with the Empire server for new tasking, executes the commands, and sends back results. This method will run until the `kill_date` is reached or the agent is otherwise terminated.

### `check_in()`

Communicates with the server to check for new tasks.

### `execute_command(command)`

Executes a command on the host system and returns the result.

## Usage Example

```go
agent := MainAgent{...}
agent.run()
```
