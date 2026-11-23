// Client for the Zyxel (KPN Box) web GUI "DAL" API.
// Protocol, as implemented by the router's own app.js:
//  - GET /getRSAPublickKey -> RSA public key
//  - POST /UserLogin with {content, key, iv}: content = AES-256-CBC(JSON), key = RSA-PKCS1v15(base64 AES key)
//  - responses under /cgi-bin and /UserLogin come back as {content, iv}, AES-encrypted with the same key
//  - POST/PUT/DELETE on /cgi-bin need header CSRFToken = sessionkey returned at login
//  - GET/DELETE parameters go in the query string; GET with params adds DalGetOneObject=y
import https from "node:https";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

export class ZyxelClient {
  constructor({ host, username, password }) {
    this.host = host;
    this.username = username;
    this.password = password;
    this.cookies = new Map();
    this.aesKey = null; // base64 string, as the GUI stores it
    this.sessionKey = null;
    this.agent = new https.Agent({ rejectUnauthorized: false, keepAlive: true });
  }

  static fromEnv() {
    const host = process.env.ZYXEL_HOST || "192.168.2.1";
    const username = process.env.ZYXEL_USER || "admin";
    let password = process.env.ZYXEL_PASSWORD;
    if (!password) {
      const service = process.env.ZYXEL_KEYCHAIN_SERVICE || "zyxel-router-mcp";
      try {
        password = execFileSync(
          "/usr/bin/security",
          ["find-generic-password", "-s", service, "-a", username, "-w"],
          { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }
        ).trim();
      } catch {
        throw new Error(
          `No router password: add it to the macOS Keychain with ` +
            `security add-generic-password -s ${service} -a ${username} -w`
        );
      }
    }
    return new ZyxelClient({ host, username, password });
  }

  _raw(method, path, body) {
    return new Promise((resolve, reject) => {
      const headers = { "If-Modified-Since": "Thu, 01 Jun 1970 00:00:00 GMT", Accept: "application/json" };
      if (this.cookies.size) headers.Cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
      if (this.sessionKey && method !== "GET" && path.startsWith("/cgi-bin")) headers.CSRFToken = String(this.sessionKey);
      let data;
      if (body !== undefined) {
        data = Buffer.from(body);
        headers["Content-Type"] = "application/json";
        headers["Content-Length"] = data.length;
      }
      const req = https.request(
        { host: this.host, port: 443, path, method, headers, agent: this.agent, timeout: 30000 },
        (res) => {
          for (const c of res.headers["set-cookie"] || []) {
            const [pair] = c.split(";");
            const i = pair.indexOf("=");
            this.cookies.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
          }
          const chunks = [];
          res.on("data", (d) => chunks.push(d));
          res.on("end", () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString("utf8") }));
        }
      );
      req.on("timeout", () => req.destroy(new Error(`timeout on ${method} ${path}`)));
      req.on("error", reject);
      if (data) req.write(data);
      req.end();
    });
  }

  _encrypt(plaintext, withKey) {
    const key = Buffer.from(this.aesKey, "base64");
    const ivB64 = crypto.randomBytes(32).toString("base64");
    const iv = Buffer.from(ivB64, "base64").subarray(0, 16); // CryptoJS uses the first 128 bits
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    const content = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]).toString("base64");
    const out = { content, iv: ivB64 };
    if (withKey) {
      out.key = crypto
        .publicEncrypt({ key: this.rsaKey, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(this.aesKey))
        .toString("base64");
    }
    return JSON.stringify(out);
  }

  _decode(text) {
    let j;
    try {
      j = JSON.parse(text);
    } catch {
      throw new Error(`Router returned non-JSON: ${text.slice(0, 200)}`);
    }
    if (j && j.iv && j.content && this.aesKey) {
      const key = Buffer.from(this.aesKey, "base64");
      const iv = Buffer.from(j.iv, "base64").subarray(0, 16);
      const d = crypto.createDecipheriv("aes-256-cbc", key, iv);
      j = JSON.parse(Buffer.concat([d.update(j.content, "base64"), d.final()]).toString("utf8"));
    }
    return j;
  }

  async login() {
    const pk = JSON.parse((await this._raw("GET", "/getRSAPublickKey")).text);
    this.rsaKey = pk.RSAPublicKey;
    this.aesKey = crypto.randomBytes(32).toString("base64");
    this.sessionKey = null;
    this.cookies.clear();
    const payload = JSON.stringify({
      Input_Account: this.username,
      Input_Passwd: Buffer.from(this.password, "utf8").toString("base64"),
      currLang: "en",
      RememberPassword: 0,
      SHA512_password: false,
    });
    const res = await this._raw("POST", "/UserLogin", this._encrypt(payload, true));
    const j = this._decode(res.text);
    if (res.status !== 200 || !j.sessionkey) {
      this.aesKey = null;
      throw new Error(`Login failed (HTTP ${res.status}): ${j.result || JSON.stringify(j).slice(0, 200)}`);
    }
    this.sessionKey = j.sessionkey;
    return j;
  }

  async logout() {
    if (!this.sessionKey) return;
    try {
      await this._raw("POST", "/cgi-bin/UserLogout");
    } catch {}
    this.sessionKey = null;
    this.aesKey = null;
  }

  async request(method, path, { query, body } = {}, retried = false) {
    if (!this.sessionKey) await this.login();
    let url = path;
    const params = [];
    if (query && Object.keys(query).length) {
      if (method === "GET") params.push("DalGetOneObject=y");
      params.push(
        Object.entries(query)
          .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
          .join("&")
      );
    }
    if (params.length) url += (url.includes("?") ? "&" : "?") + params.join("&");
    const payload = body !== undefined ? this._encrypt(JSON.stringify(body), false) : undefined;
    const res = await this._raw(method, url, payload);
    let j;
    try {
      j = this._decode(res.text);
    } catch (e) {
      if (!retried) return this._relogin(method, path, { query, body });
      throw e;
    }
    const authFail =
      res.status === 401 ||
      res.status === 403 ||
      (j && typeof j.result === "string" && /Invalid Username|No AesKey|session/i.test(j.result));
    if (authFail && !retried) return this._relogin(method, path, { query, body });
    // Writes rotate the CSRF session key; the GUI stores whatever new one comes back.
    if (j && j.sessionkey) this.sessionKey = j.sessionkey;
    if (res.status >= 400) throw new Error(`HTTP ${res.status} on ${method} ${path}: ${JSON.stringify(j).slice(0, 300)}`);
    return j;
  }

  async _relogin(method, path, opts) {
    this.sessionKey = null;
    await this.login();
    return this.request(method, path, opts, true);
  }

  async dal(oid, method = "GET", { query, body } = {}) {
    const j = await this.request(method, `/cgi-bin/DAL?oid=${encodeURIComponent(oid)}`, { query, body });
    if (j && j.result && j.result !== "ZCFG_SUCCESS") {
      throw new Error(`DAL ${method} ${oid} failed: ${j.result}${j.ReplyMsg ? ` (${j.ReplyMsg})` : ""}`);
    }
    return j;
  }
}
