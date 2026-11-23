#!/usr/bin/env node
// MCP server for a Zyxel broadband router (EX5601 family). Read tools plus a small set of confirmed writes.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { ZyxelClient } from "./zyxel.js";

let client;
const getClient = () => (client ??= ZyxelClient.fromEnv());

// Serialise router calls: the GUI API is session-based and dislikes concurrent logins.
let queue = Promise.resolve();
const run = (fn) => {
  const p = queue.then(() => fn(getClient()));
  queue = p.catch(() => {});
  return p;
};

const SECRET_KEY = /(psk|passphrase|password|passwd|wepkey|secret|presharedkey|keypassphrase)/i;
function redact(v, show) {
  if (show) return v;
  if (Array.isArray(v)) return v.map((x) => redact(x, show));
  if (v && typeof v === "object") {
    const o = {};
    for (const [k, val] of Object.entries(v)) {
      o[k] = SECRET_KEY.test(k) && typeof val === "string" && val !== "" ? "***redacted***" : redact(val, show);
    }
    return o;
  }
  return v;
}

const ok = (data) => ({ content: [{ type: "text", text: typeof data === "string" ? data : JSON.stringify(data, null, 2) }] });
const fail = (e) => ({ isError: true, content: [{ type: "text", text: String(e?.message || e) }] });
const tool = (fn) => async (args) => {
  try {
    return ok(await fn(args));
  } catch (e) {
    return fail(e);
  }
};
const needConfirm = (action, payload) => ({
  dry_run: true,
  message: `Not applied. Re-run with confirm: true to ${action}.`,
  would_send: payload,
});
const confirmArg = z.boolean().default(false).describe("Must be true to actually apply the change; otherwise a dry-run preview is returned");

const pick = (o, keys) => Object.fromEntries(keys.filter((k) => o[k] !== undefined).map((k) => [k, o[k]]));

const server = new McpServer({ name: "zyxel-router", version: "0.1.0" });

// ---------- Read tools ----------

server.registerTool(
  "router_status",
  {
    description: "Router model, firmware, uptime and WAN status summary (full: true for everything).",
    inputSchema: { full: z.boolean().default(false) },
  },
  tool(({ full }) =>
    run(async (c) => {
      const basic = await c.request("GET", "/cgi-bin/getBasicInformation").catch((e) => ({ error: e.message }));
      const s = (await c.dal("status")).Object?.[0] ?? {};
      if (full) return redact({ basic, status: s }, false);
      const wans = (s.WanLanInfo ?? [])
        .filter((w) => /WAN/i.test(w.X_ZYXEL_Type ?? w.Type ?? "") || w.X_ZYXEL_DefaultGatewayIface)
        .map((w) => pick(w, ["Name", "X_ZYXEL_SrvName", "Status", "X_ZYXEL_DefaultGatewayIface", "X_ZYXEL_IPv4Address", "IPv4Address", "X_ZYXEL_IPv6Address", "LinkType"]));
      return redact(
        {
          model: basic.ModelName,
          firmware: basic.SoftwareVersion,
          device: pick(s.DeviceInfo ?? {}, ["Manufacturer", "ModelName", "SerialNumber", "SoftwareVersion", "UpTime"]),
          system: pick(s.SystemInfo ?? {}, ["HostName", "DomainName", "CPUUsage", "MemoryStatus"]),
          wan_type: s.WanType,
          wan_rate_rx: s.WanRate_RX,
          wan_rate_tx: s.WanRate_TX,
          wan_uptime: s.X_ZYXEL_InterfaceUpTime,
          wan_interfaces: wans,
        },
        false
      );
    })
  )
);

server.registerTool(
  "list_devices",
  {
    description: "Devices known to the router (LAN hosts): name, IP, MAC, active state, connection type.",
    inputSchema: { active_only: z.boolean().default(false), raw: z.boolean().default(false).describe("Return every field") },
  },
  tool(({ active_only, raw }) =>
    run(async (c) => {
      const j = await c.dal("lanhosts");
      let hosts = j.Object?.[0]?.lanhosts ?? [];
      if (active_only) hosts = hosts.filter((h) => h.Active === true || h.Active === 1);
      if (raw) return hosts;
      return hosts.map((h) => ({
        name: h.curHostName || h.DeviceName || h.HostName || "",
        ...pick(h, ["IPAddress", "PhysAddress", "Active", "AddressSource", "X_ZYXEL_ConnectionType", "WiFiname", "X_ZYXEL_ConnectedAP", "X_ZYXEL_RSSI", "dhcp4StaticAddrExist"]),
      }));
    })
  )
);

server.registerTool(
  "get_wifi",
  {
    description: "Wi-Fi networks (SSIDs) with Index, band, enabled state and security. Compact unless full; secrets redacted unless show_secrets.",
    inputSchema: { full: z.boolean().default(false).describe("Return every field"), show_secrets: z.boolean().default(false) },
  },
  tool(({ full, show_secrets }) =>
    run(async (c) => {
      const list = (await c.dal("wlan")).Object ?? [];
      if (full || show_secrets) return redact(list, show_secrets);
      return list.map((w) =>
        pick(w, ["Index", "SSID", "band", "wlEnable", "MainSSID", "radioenable", "channel", "bandwidth", "SecurityMode", "wlHide", "IsolationEnable"])
      );
    })
  )
);

server.registerTool(
  "list_port_forwards",
  { description: "Port forwarding (NAT) rules with their Index." },
  tool(() => run(async (c) => (await c.dal("nat")).Object))
);

server.registerTool(
  "list_dhcp_reservations",
  { description: "Static DHCP reservations (MAC -> IP) with their Index and the device's name (custom name if set)." },
  tool(() =>
    run(async (c) => {
      const norm = (m) => (m || "").toLowerCase().replace(/-/g, ":");
      const custom = new Map(((await c.dal("change_icon_name")).Object ?? []).map((e) => [norm(e.MacAddress), e.HostName]));
      const hosts = new Map(((await c.dal("lanhosts")).Object?.[0]?.lanhosts ?? []).map((h) => [norm(h.PhysAddress), h.HostName]));
      return ((await c.dal("static_dhcp")).Object ?? []).map((r) => ({
        ...r,
        Name: custom.get(norm(r.MACAddr)) || hosts.get(norm(r.MACAddr)) || "",
      }));
    })
  )
);

const READ_OIDS = [
  "lanhosts", "status", "wlan", "wan", "lan", "static_dhcp", "nat", "nat_trigger", "nat_addr_map", "dns", "dns_route",
  "static_route", "firewall_acl", "firewall_proto", "paren_ctl", "content_filter", "wps", "wlan_scheduler", "wifi_easy_mesh",
  "wifi_mlo", "qos", "qos_class", "qos_queue", "scheduler", "user_account", "usb_info", "ethctl", "speedCtl", "pwr_saving",
  "MultiWan", "wanbackup", "vpnclient", "IPSecVPN", "vlan_group", "intf_group", "policy_route", "trust_domain", "email_ntfy",
];
server.registerTool(
  "read_setting",
  {
    description: `Read any router settings object (DAL OID). Read-only. Known OIDs: ${READ_OIDS.join(", ")}.`,
    inputSchema: { oid: z.string().describe("DAL object id, e.g. 'dns' or 'firewall_acl'"), show_secrets: z.boolean().default(false) },
  },
  tool(({ oid, show_secrets }) => run(async (c) => redact((await c.dal(oid)).Object, show_secrets)))
);

// ---------- Write tools (all require confirm: true) ----------

server.registerTool(
  "set_wifi_enabled",
  {
    description: "Enable or disable one Wi-Fi network (e.g. the guest SSID). Use get_wifi to find its Index.",
    inputSchema: { index: z.number().int(), enabled: z.boolean(), confirm: confirmArg },
  },
  tool(({ index, enabled, confirm }) =>
    run(async (c) => {
      const list = (await c.dal("wlan")).Object ?? [];
      const cur = list.find((w) => w.Index === index);
      if (!cur) throw new Error(`No Wi-Fi network with Index ${index}. Known: ${list.map((w) => `${w.Index}=${w.SSID}`).join(", ")}`);
      const field = "wlEnable" in cur ? "wlEnable" : "Enable" in cur ? "Enable" : null;
      if (!field) throw new Error(`Can't find the enable field on this SSID object; keys: ${Object.keys(cur).join(", ")}`);
      // The router rejects a full object echoed back (ZCFG_INVALID_PARAM_VALUE); send only the change.
      const body = { Index: index, [field]: enabled };
      const summary = { Index: index, SSID: cur.SSID, [field]: `${cur[field]} -> ${enabled}` };
      if (!confirm) return needConfirm(`${enabled ? "enable" : "disable"} Wi-Fi '${cur.SSID}'`, summary);
      const r = await c.dal("wlan", "PUT", { body });
      return { applied: true, ...summary, result: r.result };
    })
  )
);

server.registerTool(
  "add_port_forward",
  {
    description: "Add a port forwarding rule to a LAN device.",
    inputSchema: {
      description: z.string().max(64),
      protocol: z.enum(["TCP", "UDP", "ALL"]).default("TCP"),
      external_port_start: z.number().int().min(1).max(65535),
      external_port_end: z.number().int().min(1).max(65535).optional(),
      internal_port_start: z.number().int().min(1).max(65535).optional(),
      internal_port_end: z.number().int().min(1).max(65535).optional(),
      internal_client: z.string().regex(/^\d+\.\d+\.\d+\.\d+$/).describe("LAN IP of the target device"),
      wan_interface: z.string().optional().describe("WAN IpIfacePath; omit to auto-detect the WAN (what existing rules use)"),
      enabled: z.boolean().default(true),
      confirm: confirmArg,
    },
  },
  tool((a) =>
    run(async (c) => {
      const existing = (await c.dal("nat")).Object ?? [];
      const iface = a.wan_interface || "";
      const ext0 = a.external_port_start;
      const ext1 = a.external_port_end ?? ext0;
      const int0 = a.internal_port_start ?? ext0;
      const int1 = a.internal_port_end ?? int0 + (ext1 - ext0);
      const body = {
        Index: 0, referenceIndex: -1, Enable: a.enabled, Protocol: a.protocol, DefaultPort: "", Description: a.description,
        Interface: iface, ExternalPortStart: ext0, ExternalPortEnd: ext1, InternalPortStart: int0, InternalPortEnd: int1,
        InternalClient: a.internal_client, SetRemoteIP: false, RemoteHost: "", RemoteHostEndRange: "", WANIP: "",
        X_ZYXEL_AutoDetectWanStatus: !iface,
      };
      const clash = existing.find(
        (r) => (r.Protocol === a.protocol || r.Protocol === "ALL" || a.protocol === "ALL") && r.ExternalPortStart <= ext1 && ext0 <= r.ExternalPortEnd
      );
      if (clash) throw new Error(`External ports overlap existing rule Index ${clash.Index} (${clash.Description})`);
      if (!a.confirm) return needConfirm("add this port forward", body);
      const r = await c.dal("nat", "POST", { body });
      return { applied: true, result: r.result, rule: body };
    })
  )
);

server.registerTool(
  "delete_port_forward",
  {
    description: "Delete a port forwarding rule by Index (from list_port_forwards).",
    inputSchema: { index: z.number().int(), confirm: confirmArg },
  },
  tool(({ index, confirm }) =>
    run(async (c) => {
      const rule = ((await c.dal("nat")).Object ?? []).find((r) => r.Index === index);
      if (!rule) throw new Error(`No port forward with Index ${index}`);
      const summary = pick(rule, ["Index", "Description", "Protocol", "ExternalPortStart", "ExternalPortEnd", "InternalClient"]);
      if (!confirm) return needConfirm("delete this port forward", summary);
      const r = await c.dal("nat", "DELETE", { query: { Index: index } });
      return { applied: true, deleted: summary, result: r.result };
    })
  )
);

const MAC = z.string().regex(/^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/);
server.registerTool(
  "add_dhcp_reservation",
  {
    description: "Reserve a fixed LAN IP for a device MAC address.",
    inputSchema: { mac: MAC, ip: z.string().regex(/^\d+\.\d+\.\d+\.\d+$/), confirm: confirmArg },
  },
  tool(({ mac, ip, confirm }) =>
    run(async (c) => {
      const list = (await c.dal("static_dhcp")).Object ?? [];
      const norm = (m) => (m || "").toLowerCase().replace(/-/g, ":");
      const clash = list.find((r) => norm(r.MACAddr) === norm(mac) || r.IPAddr === ip);
      if (clash) throw new Error(`Conflicts with existing reservation: ${JSON.stringify(clash)}`);
      const nextIndex = list.reduce((m, r) => Math.max(m, r.Index ?? 0), 0) + 1;
      const body = { Index: nextIndex, BrWan: "Default", Enable: true, MACAddr: norm(mac), IPAddr: ip };
      if (!confirm) return needConfirm("add this DHCP reservation", body);
      const r = await c.dal("static_dhcp", "POST", { body });
      return { applied: true, result: r.result, reservation: body };
    })
  )
);

server.registerTool(
  "delete_dhcp_reservation",
  {
    description: "Delete a static DHCP reservation by Index (from list_dhcp_reservations).",
    inputSchema: { index: z.number().int(), confirm: confirmArg },
  },
  tool(({ index, confirm }) =>
    run(async (c) => {
      const res = ((await c.dal("static_dhcp")).Object ?? []).find((r) => r.Index === index);
      if (!res) throw new Error(`No reservation with Index ${index}`);
      if (!confirm) return needConfirm("delete this DHCP reservation", res);
      const r = await c.dal("static_dhcp", "DELETE", { query: { Index: index } });
      return { applied: true, deleted: res, result: r.result };
    })
  )
);

// ---------- Device names (DAL "change_icon_name") ----------
// The router has no description field on DHCP reservations; the closest is the custom device
// name the GUI's "edit device" stores per MAC, which the device list and other pages show.

const normMac = (m) => (m || "").toLowerCase().replace(/-/g, ":");

server.registerTool(
  "set_device_name",
  {
    description: "Give a LAN device a custom name on the router (the GUI's 'edit device' name), keyed by MAC.",
    inputSchema: { mac: MAC, name: z.string().min(1).max(64), confirm: confirmArg },
  },
  tool(({ mac, name, confirm }) =>
    run(async (c) => {
      const entries = (await c.dal("change_icon_name")).Object ?? [];
      const existing = entries.find((e) => normMac(e.MacAddress) === normMac(mac));
      // A DAL PUT must carry only the changed fields, or the router rejects it.
      const [method, body] = existing
        ? ["PUT", { Index: existing.Index, HostName: name }]
        : ["POST", { MacAddress: normMac(mac), HostName: name }];
      if (!confirm) return needConfirm(`${existing ? "rename" : "name"} this device`, { method, ...body });
      const r = await c.dal("change_icon_name", method, { body });
      return { applied: true, result: r.result, method, ...body };
    })
  )
);

// ---------- Firewall ACL (per-device internet block) ----------
// Field names follow Zyxel's DAL "firewall_acl" handler (libzcfg_fe_dal): the router copies
// every key of the body into the rule, so only send fields it knows.

const IPV4 = z.string().regex(/^\d+\.\d+\.\d+\.\d+$/);
const aclSummary = (r) =>
  pick(r, ["Index", "Name", "Enable", "Order", "Target", "X_ZYXEL_Direction", "Direction", "Protocol", "IPVersion",
    "SourceIP", "SourceMask", "MACAddress", "DestIP", "DestMask"]);

server.registerTool(
  "list_firewall_rules",
  { description: "Firewall ACL rules (including per-device internet blocks) with their Index." },
  tool(() => run(async (c) => ((await c.dal("firewall_acl")).Object ?? []).map(aclSummary)))
);

server.registerTool(
  "block_device_internet",
  {
    description:
      "Block a LAN device from the internet with a firewall ACL rule (LAN to WAN, all protocols, IPv4, drop). " +
      "LAN traffic, e.g. Home Assistant, keeps working. Give the device's MAC, its IP, or both (both must then match); " +
      "with an IP, reserve it first (add_dhcp_reservation) so the block survives a new lease.",
    inputSchema: {
      name: z.string().min(1).max(64).describe("Rule name, e.g. 'Block smart plug'"),
      mac: MAC.optional(),
      ip: IPV4.optional(),
      confirm: confirmArg,
    },
  },
  tool(({ name, mac, ip, confirm }) =>
    run(async (c) => {
      if (!mac && !ip) throw new Error("Give mac, ip or both");
      const rules = (await c.dal("firewall_acl")).Object ?? [];
      if (rules.some((r) => r.Name === name)) throw new Error(`A firewall rule named "${name}" already exists`);
      const body = {
        Enable: true,
        Name: name,
        Order: rules.reduce((m, r) => Math.max(m, r.Order ?? 0), 0) + 1,
        Target: "Drop",
        Protocol: "ALL",
        IPVersion: "IPv4",
        Direction: "LAN_TO_WAN",
        SourceIPPrefix: ip ? `${ip}/32` : "AnyIP",
        DestIPPrefix: "AnyIP",
        ...(mac ? { MACAddress: mac.toLowerCase().replace(/:/g, "-") } : {}),
      };
      if (!confirm) return needConfirm("add this firewall block", body);
      const r = await c.dal("firewall_acl", "POST", { body });
      const added = ((await c.dal("firewall_acl")).Object ?? []).find((x) => x.Name === name);
      return { applied: true, result: r.result, rule: added ? aclSummary(added) : body };
    })
  )
);

server.registerTool(
  "delete_firewall_rule",
  {
    description: "Delete a firewall ACL rule by Index (from list_firewall_rules), e.g. to lift a device block.",
    inputSchema: { index: z.number().int(), confirm: confirmArg },
  },
  tool(({ index, confirm }) =>
    run(async (c) => {
      const rule = ((await c.dal("firewall_acl")).Object ?? []).find((r) => r.Index === index);
      if (!rule) throw new Error(`No firewall rule with Index ${index}`);
      const summary = aclSummary(rule);
      if (!confirm) return needConfirm("delete this firewall rule", summary);
      const r = await c.dal("firewall_acl", "DELETE", { query: { Index: index } });
      return { applied: true, deleted: summary, result: r.result };
    })
  )
);

server.registerTool(
  "reboot_router",
  {
    description: "Reboot the router. Internet and Wi-Fi drop for a few minutes, including this Mac's connection.",
    inputSchema: { confirm: confirmArg },
  },
  tool(({ confirm }) =>
    run(async (c) => {
      if (!confirm) return needConfirm("reboot the router (network down for a few minutes)", {});
      await c.request("POST", "/cgi-bin/Reboot");
      c.sessionKey = null;
      return { applied: true, message: "Reboot requested. The router will be unreachable for a few minutes." };
    })
  )
);

const shutdown = async () => {
  if (client) await client.logout();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
process.stdin.on("end", shutdown);

await server.connect(new StdioServerTransport());
