# Main Agent Class

The `MainAgent` class represents the core functionality of the agent after the initial staging process. It handles tasking, command execution, results posting, and overall agent lifecycle management.

## Attributes

* **packet\_handler**: An instance of a packet handler class, such as `ExtendedPacketHandler`, which facilitates communication with the command and control server.
* **profile**: The communication profile string, inherited from the staging process, that determines the agent's network signatures.
* **server**: The base URL of the command and control server.
* **session\_id**: A unique identifier for the agent's session.
* **kill\_date**: The date upon which the agent will automatically cease operations.
* **working\_hours**: A window of time during which the agent is allowed to operate.

## Methods

### `check_in()`

Communicates with the command and control server to check for any new tasking or commands that should be executed.

### `process_packet(packet_type, data, result_id)`

Processes an individual packet of data, potentially executing a command, and then returning the result. The specific behavior is determined by the `packet_type`.

### `execute_command(command)`

Executes a given command on the host system, capturing any output or errors, and then returning the result.

### `send_results(result)`

Packages up the result of a command and sends it to the command and control server using the `packet_handler`.

### `run()`

The main loop of the agent, which continually checks in with the server for new commands, executes them, and returns results. This loop will typically continue until the `kill_date` is reached or another termination condition is met.

## Usage Example

To use the `MainAgent` class, it's typically instantiated within the `Stage` class after the initial staging process:

```python
agent = MainAgent(packet_handler=packetHandlerInstance, profile=profile, server=server, session_id=session_id, kill_date=kill_date, working_hours=working_hours)
agent.run()
```
