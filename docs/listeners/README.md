# Listeners

Listeners in Empire are responsible for handling agent connections. They serve as the communication channels between compromised hosts and the Empire server, relaying commands and responses. Listeners can operate over various transport mechanisms such as HTTP, HTTPS, and SMB.

Empire supports multiple listener types, providing flexibility in how agents communicate based on the environment and operational needs.

## Listener Tips

* **Host binding**: Ensure `Host` matches how your target can reach the server (public IP, domain, or redirector).
* **Ports**: Keep firewall rules in mind for both inbound and outbound traffic.

## Listener Types

Empire offers several listener types designed for different network conditions and evasion techniques:

* **HTTP/HTTPS**: A standard HTTP listener for internet-facing operations supports both standard HTTP and encrypted HTTPS.
* **HTTP Malleable**: A customizable HTTP listener that allows beacons to match specific threat profiles.
* **SMB**: A peer-to-peer listener that works over SMB pipes (**currently only supports IronPython**).
* **HTTP Hop**: A listener that adds an intermediate hop or redirection server using PHP.
* **Port Forward**: Enables chaining agents through port forwarding.
* **HTTP Foreign**: Allows one server to generate stagers and agents for another Empire server.
