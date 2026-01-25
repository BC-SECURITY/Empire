# Extended Packet Handler Class

`ExtendedPacketHandler` is a subclass of `PacketHandler`. While `PacketHandler` focuses on managing packet structure and encryption, `ExtendedPacketHandler` extends this functionality by introducing specific methods to interact with the command and control server using HTTP requests. It integrates communication profiles to make these interactions customizable.

## Attributes

The attributes for `ExtendedPacketHandler` depend on the agent's communication profile, but can look similar to below for an HTTP listener.

* **headers**: The HTTP headers to use in requests. Derived from the agent's communication profile.
* **taskURIs**: The list of potential URI endpoints for tasking. Randomly sampled to vary the request patterns.
* **server**: The base URL of the command and control server.

## Methods

### `post_message(uri, data)`

Sends a POST request to the specified `uri` with the provided `data`, using the communication profile's headers. Returns the server's response.

### `send_results_for_child(received_data)`

Forwards tasking results to the control server for SMB agents. It uses a random taskURI and sets a session cookie in the headers based on `received_data`.

### `send_get_tasking_for_child(received_data)`

Forwards the get-tasking request to the control server for SMB agents, with data decoded from `received_data`.

### `send_staging_for_child(received_data, hop_name)`

Forwards the staging request to the control server using a specific URI (`/login/process.php`) for SMB agents. Additionally, it sets the 'Hop-Name' in the headers.

### `send_message(packets=None)`

If `packets` is not provided, it constructs a GET request to fetch tasking from the control server. If `packets` is provided, it constructs a POST request to send data to the server. It chooses a random taskURI for the request and manages error handling for server communication issues.

## Usage Example

To use `ExtendedPacketHandler`, you need to instantiate it with the right parameters, including the agent instance, staging key, session ID, and the communication profile details (headers, taskURIs, server).

```python
handler = ExtendedPacketHandler(agent_instance, "sample_staging_key", "sample_session_id", headers, server, taskURIs)
response = handler.post_message("/some/endpoint", "some_data")
```
