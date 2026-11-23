# zyxel-router-mcp

MCP server (stdio) for a Zyxel router with the KPN Box web GUI (e.g. the EX5601-T1), talking to the router's encrypted DAL web API.

- **Reads:** status, LAN devices, Wi-Fi, port forwards, DHCP reservations, any DAL settings object.
- **Writes:** Wi-Fi on/off, port forwards, DHCP reservations, reboot. Every write is a dry run unless called with `confirm: true`.

## Setup

```bash
npm install
security add-generic-password -s zyxel-router-mcp -a admin -w   # router password, prompted
claude mcp add -s user zyxel-router -e ZYXEL_HOST=192.168.2.1 -e ZYXEL_USER=admin -- node "$PWD/server.js"
```

`ZYXEL_PASSWORD` overrides the Keychain lookup; `ZYXEL_KEYCHAIN_SERVICE` changes the Keychain service name.
