# Python & IronPython Agents

The agents are built in Python and IronPython to provide flexibility and extensibility for a variety of scenarios and environments.

## Prerequisites

- Python 3.x (for the Python agent)
- IronPython 3.4+ (for the IronPython agent)

## Dependencies

The agent incorporates multiple external Python functionalities, sourced via Jinja2 templates:

```python
{% include 'common/aes.py' %}
{% include 'common/aesgcm.py' %}
{% include 'common/diffiehellman.py' %}
{% include 'common/get_sysinfo.py' %}
{% include 'http/comms.py' %}
```

These functionalities provide:
- AES-CBC & AES-256-GCM Encryption: For encrypted communications (FIPS-compliant).
- Diffie-Hellman Key Exchange + HKDF-SHA256: Secure establishment of a shared session key via DH with HKDF key derivation (FIPS SP 800-56C).
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
       |                          |  & Profile (AES-GCM)     |                            |
       |                          |------------------------->|                            |
       |                          |                          |                            |
       |   Send Staging Key &    |                          |                             |
       |        Profile           |                          |                            |
       |<-------------------------|                          |                            |
       |                          |                          |                            |
       |                          |                          |   Decrypt Staging Profile  |
       |                          |                          |<---------------------------|
       |                          |                          |                            |
       |                          |                          | DH Key Exchange + HKDF     |
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
2. C2: The Command and Control (C2) server generates a staging key and a profile for the client. Routing packets are encrypted with AES-256-GCM using the staging key.
3. C2 → Client: The server sends the encrypted staging key and profile to the client.
4. Stager: The stager decrypts the staging profile and initiates a Diffie-Hellman key exchange. The shared secret is derived into a 256-bit AES session key via HKDF-SHA256 (FIPS SP 800-56C).
5. Agent: When the stager receives tasking, it decrypts the tasking using the AES session key. Then the agent executes the decrypted tasks.

In this process, multiple encryption schemes are at play:
- AES-256-GCM: AEAD encryption for routing packets (staging key).
- AES-CBC + HMAC-SHA256: Encrypt-then-MAC for payload data. Independent cipher and MAC keys are derived from the session key via HKDF-SHA256 (`empire-enc` / `empire-mac`); the HMAC is truncated to 16 bytes per FIPS SP 800-107.
- Diffie-Hellman + HKDF-SHA256: Securely negotiates an AES-256 session key via DH key exchange with HKDF key derivation (FIPS SP 800-56C).

## Components

- **[Stage](stageclass.md)**: Handles the initial communication with the C2 server and sets up the main agent for execution.

- **[MainAgent](mainagentclass.md)**: The core of the agent's functionality, it continuously communicates with the server, processes commands, and returns results.

- **[PacketHandler](packethandlerclass.md) & [ExtendedPacketHandler](extendedpackethandlerclass.md)**: Manages the encrypted communication between the agent and the server.
