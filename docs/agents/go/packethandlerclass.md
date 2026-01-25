# Packet Handler Class

The `PacketHandler` class manages packet creation, encryption, decryption, and communication between the agent and the Empire server. It handles network communication and ensures the secure transmission of tasking and results.

### Attributes

* **server**: The base URL of the Empire server.
* **staging\_key**: Key used during the staging process for initial secure communication.
* **aeskey**: The key used to encrypt/decrypt tasking.
* **sessionID**: Unique session identifier for the agent.

### Methods

#### `buildRoutingPacket()`

Constructs a packet for secure communication with the Empire server, including encryption.

#### `send_message()`

Sends data to the Empire server, either for tasking or result submission.

#### `process_tasking(data)`

Processes a tasking packet received from the server, decrypting it, and executing the task on the agent's system.

### Usage Example

```go
packetHandler := PacketHandler{...}
packetHandler.send_message([]byte("tasking data"))
```
