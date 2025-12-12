# PacketHandler Class

The `PacketHandler` class is responsible for creating, parsing, and processing packets for agent-server communication. This includes encrypting/decrypting packets, extracting metadata, and routing tasking.

## Attributes

- **agent**: An instance of the main agent.
- **key**: Encryption key for the current session.
- **staging_key**: Key used during the staging process.
- **session_id**: Unique identifier for the current session.
- **missedCheckins**: Counter for failed check-ins.
- **language_list**: Dictionary linking programming languages to unique IDs.
- **meta**: Defines metadata types for packets.
- **additional**: Empty dictionary, can be populated with additional metadata.

## Methods


### `ChaCha20Poly1305`

ChaCha20Poly1305 class that seals/unseals the input `data` with the given `key` and `nonce`.

### `parse_routing_packet(staging_key, data)`

Parses the encrypted agent data from a routing packet, which includes session ID, language, metadata type, and the encrypted data. The function returns a dictionary with session IDs as keys and tuples (language, metadata, additional data, encrypted data) as values.

### `build_routing_packet(staging_key, session_id, meta, additional, enc_data)`

Builds a packet for agent communication, including a unique session ID, metadata, and encrypted data.

### `decode_routing_packet(data)`

Parses all routing packets and processes packets specific to the agent's session ID.

### `build_response_packet(tasking_id, packet_data, result_id)`

Constructs a task packet for the agent, which includes packet type, task ID, and the actual data.

### `parse_task_packet(packet, offset)`

Parses a packet to extract various details such as packet type, task ID, and data. Returns a tuple with all the extracted details.

### `process_tasking(data)`

Processes an encrypted packet by decrypting it, extracting the packets, and directing the agent to execute them.

### `process_job_tasking(result)`

Processes job data packets, mainly sending results back to the Command & Control server.
