# Python & IronPython Agents

The agents are built in Python and IronPython to provide flexibility and extensibility for a variety of scenarios and environments.

## Prerequisites

- Python 3.x (for the Python agent)
- IronPython 3.4+ (for the IronPython agent)

## Dependencies

The agent incorporates multiple external Python functionalities, sourced via Jinja2 templates:

```python
{% include 'common/aes.py' %}
{% include 'common/chacha.py' %}
{% include 'common/diffiehellman.py' %}
{% include 'common/get_sysinfo.py' %}
{% include 'http/comms.py' %}
```

These functionalities provide:
- AES & ChaCha20 Encryption: For encrypted communications.
- Diffie-Hellman Key Exchange: Secure establishment of a shared secret key.
- System Information: Gather details about the host system.
- HTTP Communication Methods: Communication methods tailored for HTTP. (Can be customized with other listener options)

### IronPython Dependencies
The IronPython agent will also use custom libraries that are added to lib.zip which include:
- [SecretSocks](https://github.com/BC-SECURITY/PySecretSOCKS)

## Staging Process
Staging is the agent's initial phase, where it communicates with the server and prepares for secure interactions. During the staging process initial staging information is provided and used to create a secure communication channel.

```
+------------+             +------------+             +----------------+            +------------+
|   Client   |             |    C2      |             |    Stager      |            |   Agent    |
+------------+             +------------+             +----------------+            +------------+
       |                          |                          |                            |
       |                          |                          |                            |
       |      Request Staging     |                          |                            |
       |------------------------->|                          |                            |
       |                          |                          |                            |
       |                          | Generate Staging Key     |                            |
       |                          |   & Profile (AES/HMAC)   |                            |
       |                          |------------------------->|                            |
       |                          |                          |                            |
       |   Send Staging Key &    |                          |                             |
       |        Profile           |                          |                            |
       |<-------------------------|                          |                            |
       |                          |                          |                            |
       |                          |                          |   Decrypt Staging Profile  |
       |                          |                          |<---------------------------|
       |                          |                          |                            |
       |                          |                          | Generate Diffie-Hellman    |
       |                          |                          |    (AES Session Key)       |
       |                          |                          |<---------------------------|
       |                          |                          |                            |
       |                          |                          |                            |
       |                          |                          |                            | Decrypt
       |                          |                          |                            | Tasking
       |                          |                          |                            | using AES
       |                          |                          |                            | Session Key
       |                          |                          |                            |<-------|
       |                          |                          |                            |
       |                          |                          |                            | Execute
       |                          |                          |                            |  Tasks
       |                          |                          |                            |<-------|
```

1. Client → C2: The client requests the staging code.
2. C2: The Command and Control (C2) server generates a staging key and a profile for the client. This staging key is usually encrypted using symmetric encryption like AES and is HMAC protected.
3. C2 → Client: The server sends the encrypted staging key and profile to the client.
4. Stager: The stager decrypts the staging profile and initiates a Diffie-Hellman key exchange process. This results in the creation of an AES session key that will be used for future communications.
5. Agent: When the stager receives tasking, it decrypts the tasking using the AES session key. Then the agent executes the decrypted tasks.

In this process, multiple encryption schemes are at play:
- AES/HMAC: Used to encrypt the staging key and ensure its integrity.
- Diffie-Hellman: Used to securely negotiate an AES session key for encrypted communications between the stager/agent and the C2 server.

## Components

- **[Stage](stageclass.md)**: Handles the initial communication with the C2 server and sets up the main agent for execution.

- **[MainAgent](mainagentclass.md)**: The core of the agent's functionality, it continuously communicates with the server, processes commands, and returns results.

- **[PacketHandler](packethandlerclass.md) & [ExtendedPacketHandler](extendedpackethandlerclass.md)**: Manages the encrypted communication between the agent and the server.
