# IP Filtering

IP filtering allows you to restrict agent communication to a specific set of IP addresses.

## Configuration

The default configuration is located in the server's `config.yaml` file in the database defaults section. The `ip_allow_list` and `ip_deny_list` properties are lists of IP addresses, CIDR ranges, or dash-separated ranges.

The defaults from the `config.yaml` file are loaded into the database when Empire starts up if the ip lists are empty in the database. After the initial load, IPs can be added to both lists via the API or Starkiller.

IP Filtering can be turned on/off by an admin user via the API. The default behavior has both lists empty and the feature enabled.

An IP Filtering interface is available in the [Sponsors](https://github.com/sponsors/BC-SECURITY) version of Starkiller.

### Example Configuration formatting

```yaml
database:
    defaults:
      ip_allow_list:
        - 10.0.0.0-10.0.0.10
      ip_deny_list:
        - 10.0.0.0/32
        - 10.0.0.1
```

## How it works

When an agent checks in, the server checks the agent's IP address against the lists and will immediately kill the agent if the IP is not allowed. Individual listeners can also use IP filtering via `ip_service` to implement custom behavior or stop the agent from even reaching the check in stage. The `http` listener does this and serves a different http response code if the IP is not allowed.

The IP filtering logic is as follows:

* If no allow list or deny list is set, then all IPs are allowed.
* If only an allow list is set, then only IPs in the allow list are allowed.
* If only a deny list is set, then only IPs not in the deny list are allowed.
* If both an allow list and a deny list are set, the IPs are first filtered through the allow list, and then the deny list.

For example filtering logic see the [tests](https://github.com/BC-SECURITY/Empire/blob/main/empire/test/test_ip_service.py).
