# zyxel-router-mcp

An [MCP](https://modelcontextprotocol.io) server (stdio) for **Zyxel EX5601 / EX5600 series** broadband routers. It talks to the router's own encrypted "DAL" web API (the one its web configurator uses), so an AI assistant can read the router's state and make a small set of confirmed changes.

## Which routers

The EX5601-T0 / T1 and EX5600 are Wi-Fi 6 routers that Zyxel sells mainly to internet providers, who hand them out to customers (sometimes under their own name). They're used by, among others:

| Provider | Country | Notes |
|---|---|---|
| Odido | Netherlands | Supplied as the Odido-branded "T-56" (an EX5601-T1) |
| Hyperoptic | United Kingdom | ISP-branded EX5601-T1 |
| Digiweb | Ireland | EX5601-T0 |
| CETIN | Czech Republic | EX5601-T1 (wholesale network) |

It's also sold unbranded. Tested on an **EX5601-T1** (firmware V5.70). Other Zyxel broadband routers with the same web configurator likely use the same API but are untested.

## Tools

**Read**

- `router_status`: model, firmware, uptime, WAN status
- `list_devices`: LAN hosts with IP, MAC and connection type
- `get_wifi`: SSIDs, bands, security (secrets redacted unless asked)
- `list_port_forwards`, `list_dhcp_reservations` (with device names), `list_firewall_rules`
- `read_setting`: any DAL settings object, read-only

**Write** (each one is a dry run that shows what it would send, unless called with `confirm: true`)

- `set_wifi_enabled`: turn one SSID on or off (e.g. the guest network)
- `add_port_forward` / `delete_port_forward`
- `add_dhcp_reservation` / `delete_dhcp_reservation`
- `set_device_name`: the custom name the router shows for a device
- `block_device_internet` / `delete_firewall_rule`: block a LAN device from the internet with a firewall rule (LAN traffic keeps working, so local control of smart-home devices still works)
- `reboot_router`

## Setup

Requires Node.js 18+ and macOS (the password is read from the Keychain; set `ZYXEL_PASSWORD` instead on other systems).

```bash
npm install
security add-generic-password -s zyxel-router-mcp -a admin -w   # prompts for the router's admin password
claude mcp add -s user zyxel-router -e ZYXEL_HOST=192.168.1.1 -e ZYXEL_USER=admin -- node "$PWD/server.js"
```

| Variable | Default | Meaning |
|---|---|---|
| `ZYXEL_HOST` | `192.168.2.1` | Router address (many ISP builds use `192.168.1.1` or `192.168.2.1`) |
| `ZYXEL_USER` | `admin` | Web configurator user |
| `ZYXEL_PASSWORD` | — | Password; overrides the Keychain lookup |
| `ZYXEL_KEYCHAIN_SERVICE` | `zyxel-router-mcp` | Keychain service name |

## How it works

The web configurator encrypts its API traffic: the client fetches the router's RSA public key, sends an AES-256-CBC encrypted login, and gets a session key that doubles as the CSRF token for writes. Settings are read and written through `/cgi-bin/DAL?oid=<object>`. Field names for the write tools follow Zyxel's published GPL source for its DAL layer (`libzcfg_fe_dal`).

Some router quirks the client handles: an edit must send only the fields that change (echoing back the whole object is rejected), and every write returns a new session key.

## Disclaimer

Unofficial, not affiliated with Zyxel or any provider. It changes live network settings; writes are opt-in per call, but use it at your own risk. Your ISP may push firmware updates that change the API.

## License

Copyright (C) 2026 76r75r6qbh-sys

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. It is distributed WITHOUT ANY WARRANTY; see [LICENSE](LICENSE) for the full text.
