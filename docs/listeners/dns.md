# DNS

The DNS listener in Empire enables agent communication **entirely over DNS queries**, using **A** and **TXT** records. This is particularly useful in restricted environments where only DNS traffic is allowed to leave the network.

By default, the DNS listener runs on **port 53 (UDP)**. It implements a custom UDP DNS server that handles agent staging, tasking, and result collection without relying on any external DNS infrastructure.

## How It Works

The DNS listener uses a chunked protocol to transmit data within DNS query names:

- **Upload (agent → server)**: Data is split into 60-byte Base64url chunks sent as **A record** queries. The last chunk is sent as a **TXT** query to receive the server's response.
- **Download (server → agent)**: For small responses (≤200 bytes), the data is returned directly in a single **TXT** record. For larger payloads, the server returns a `JOB:<id>` reference, and the agent downloads the full response in chunks via sequential **TXT** queries.

### Query Format

| Direction             | Format                                | Record Type |
| --------------------- | ------------------------------------- | ----------- |
| Upload (intermediate) | `r[TID]c[chunk]t[total].[base64].xyz` | A           |
| Upload (last chunk)   | `r[TID]c[chunk]t[total].[base64].xyz` | TXT         |
| Download chunk        | `s[JobID]c[index].xyz`                | TXT         |

Where `TID` is a random transaction ID, `chunk` is the chunk index, and `total` is the total number of chunks.

## Staging Process

The DNS listener follows the same multi-stage negotiation as the HTTP listener:

1. **STAGE0** – The launcher sends a routing packet to announce itself. The server generates the stager (stage 1) and buffers it for chunked download.
2. **STAGE1** – The agent downloads the stager via TXT chunks, executes it, then performs a Diffie-Hellman key exchange with Ed25519 certificate validation. A shared session key is derived.
3. **STAGE2** – The agent sends encrypted sysinfo. The server responds with the full agent code (`agent.ps1`), encrypted with the session key and delivered via JOB-based chunked download.

After staging, the agent uses **TASKING_REQUEST** (Meta 4) and **RESULT_POST** (Meta 5) for runtime communication.

## Key Configuration Options

### **Host**

The IP address or hostname that the agent will use as the DNS server for all queries. This must point to the Empire server (e.g., `127.0.0.1` for local testing, or a public IP / NS delegation in production).

### **BindIP**

The local IP address the DNS server binds to. Defaults to `0.0.0.0` (all interfaces).

### **Port**

The UDP port for the DNS server. Defaults to `53`.

### **Staging Key**

The staging key used to negotiate the session key between the agent and the server during the STAGE0–STAGE2 handshake.

### **Delay & Jitter**

- **DefaultDelay** – The interval (in seconds) at which the agent checks back with the server for new tasks.
- **DefaultJitter** – A randomness factor (between **0** and **1**) that modifies the delay to avoid detection through predictable timing patterns.

### **DefaultLostLimit**

The number of missed check-ins before the agent assumes it has lost communication and exits.

### **DefaultProfile**

The default communication profile for the agent, structured the same way as the HTTP listener profile.

### Optional Fields

- **KillDate** – The expiration date when the agent will automatically exit (MM/DD/YYYY). Leave empty for no expiration.
- **WorkingHours** – Defines when the agent will operate (e.g., `09:00-17:00`). Leave empty for 24/7 operation.

## Cryptographic Stack

The DNS listener uses the same cryptographic stack as the HTTP listener:

- **ChaCha20-Poly1305** – Used for routing packet encryption/authentication between the agent and server.
- **AES-256-CBC + HMAC-SHA256** – Used for encrypting the payload body (encrypt-then-MAC).
- **Ed25519** – Used for certificate-based identity validation of the server.
- **Diffie-Hellman** – Used during STAGE1 to derive a shared session key.

## Deployment Considerations

### Local Testing

For local testing, set `Host` to `127.0.0.1` and ensure nothing else is bound to port 53.

### Production Deployment

In a real engagement, the DNS listener requires that target machines send their DNS queries to the Empire server. This is typically achieved through:

- **NS delegation** – Register a domain and point the NS records to the Empire server's IP.
- **Direct specification** – If you control the target's DNS configuration, point it at the Empire server directly.

### Performance

DNS has inherent bandwidth limitations compared to HTTP. Each query carries ~60 bytes of payload data, and each TXT response carries ~200 bytes. Large payloads (like the full agent code at ~50KB) require hundreds of DNS round-trips. As a result:

- Staging takes longer than HTTP (~10–20 seconds depending on network latency).
- Task results are slower to return for large outputs.
- The listener is best suited for **low-bandwidth, high-stealth** scenarios where DNS is the only available egress channel.
