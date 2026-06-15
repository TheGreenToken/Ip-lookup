"use strict";

const https = require("https");
const { getCorsHeaders } = require("./middleware");

const CTRL_RE = /[^\x20-\x7E]/g;
function s(str, max) { return String(str || "").replace(CTRL_RE, "").slice(0, max || 200); }

function fetchJson(url, headers = {}) {
  return new Promise((resolve) => {
    try {
      const u = new URL(url);
      const req = https.request({ hostname: u.hostname, path: u.pathname + u.search, method: "GET", timeout: 6000, headers: { "User-Agent": "AntiSec-IP-Tool/1.0", Accept: "application/json", ...headers } }, (res) => {
        let data = "";
        res.on("data", (c) => { data += c; if (data.length > 100000) req.destroy(); });
        res.on("end", () => { try { resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, data: JSON.parse(data) }); } catch { resolve({ ok: false, data: null }); } });
      });
      req.on("error", () => resolve({ ok: false, data: null }));
      req.on("timeout", () => { req.destroy(); resolve({ ok: false, data: null }); });
      req.end();
    } catch { resolve({ ok: false, data: null }); }
  });
}

const IP_RE     = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$/;
const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

module.exports = async function handler(req, res) {
  Object.entries(getCorsHeaders(req)).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader("Cache-Control", "no-store");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  let body;
  try {
    const chunks = []; for await (const c of req) chunks.push(c);
    const raw = Buffer.concat(chunks).toString();
    if (raw.length > 512) return res.status(400).json({ error: "Request too large" });
    body = JSON.parse(raw || "{}");
  } catch { return res.status(400).json({ error: "Invalid JSON" }); }

  let target = s(String(body.target || ""), 253).toLowerCase().trim()
    .replace(/^https?:\/\//i, "").replace(/\/.*$/, "").replace(/^www\./, "");

  if (!target) return res.status(400).json({ error: "No target provided" });

  if (target === "self") target = (req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || "").split(",")[0].trim().replace(/[^a-fA-F0-9.:]/g, "").slice(0, 45);
  if (!target) return res.status(400).json({ error: "Could not detect your IP address" });

  if (!IP_RE.test(target) && !DOMAIN_RE.test(target)) return res.status(400).json({ error: "Invalid IP or domain format" });

  const ip = (req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || "unknown").split(",")[0].trim();
  const safeIp = ip.replace(/[^a-fA-F0-9.:]/g, "").slice(0, 45);

  const [r1, r2] = await Promise.allSettled([
    fetchJson(`https://freeipapi.com/api/json/${encodeURIComponent(target)}`),
    fetchJson(`https://ipwho.is/${encodeURIComponent(target)}`),
  ]);

  const d1 = r1.status === "fulfilled" && r1.value.ok ? r1.value.data : null;
  const d2 = r2.status === "fulfilled" && r2.value.ok ? r2.value.data : null;

  if (!d1 && !d2) return res.status(502).json({ error: "All geolocation sources failed. Try again shortly." });

  let rdns = null;
  try {
    const rdnsTarget = (d1?.ipAddress || d2?.ip || target);
    if (!rdnsTarget.includes(":")) {
      const r = await fetchJson(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(rdnsTarget)}&type=PTR`, { Accept: "application/dns-json" });
      if (r.ok && r.data?.Answer?.[0]?.data) rdns = s(r.data.Answer[0].data, 100);
    }
  } catch {}

  const resolvedIp  = s(d1?.ipAddress || d2?.ip || target, 45);
  const country     = s(d1?.countryName  || d2?.country        || "", 80);
  const countryCode = s(d1?.countryCode  || d2?.country_code   || "", 5);
  const region      = s(d1?.regionName   || d2?.region         || "", 80);
  const city        = s(d1?.cityName     || d2?.city           || "", 80);
  const postal      = s(d1?.zipCode      || d2?.postal         || "", 20);
  const tz          = s(d1?.timeZone     || d2?.timezone       || "", 60);
  const lat         = d1?.latitude  || d2?.latitude  || null;
  const lon         = d1?.longitude || d2?.longitude || null;
  const isp         = s(d2?.connection?.isp || d2?.isp || "", 100);
  const org         = s(d2?.org || d2?.connection?.org || "", 100);
  const asn         = s(d2?.connection?.asn ? String(d2.connection.asn) : "", 20);
  const asname      = s(d2?.connection?.domain || "", 80);
  const currency    = s(d2?.currency?.name ? `${d2.currency.name} (${d2.currency.code})` : "", 60);
  const languages   = (d2?.languages || []).map(l => s(l.name || "", 40)).slice(0, 4).join(", ");
  const calling     = s(d2?.calling_code || "", 20);
  const continent   = s(d2?.continent || "", 40);
  const capital     = s(d2?.capital || "", 60);
  const eu          = d2?.is_eu ?? null;
  const isIPv6      = resolvedIp.includes(":");
  const isVpn       = !!(d1?.isProxy || d2?.security?.vpn);
  const isTor       = !!(d2?.security?.tor);
  const isProxy     = !!(d2?.security?.proxy);
  const isHosting   = !!(d2?.security?.hosting);
  const mobile      = !!(d2?.connection?.type === "mobile");

  let localTime = null;
  if (tz) { try { localTime = new Date().toLocaleString("en-GB", { timeZone: tz, hour: "2-digit", minute: "2-digit", second: "2-digit", day: "2-digit", month: "short" }); } catch {} }

  const result = { ip: resolvedIp, lat, lon, country, countryCode, region, city, postal, tz, localTime, isp, org, asn, asname, currency, languages, calling, continent, capital, eu, isIPv6, rdns, isVpn, isTor, isProxy, isHosting, mobile };

  const WEBHOOK_URL = process.env.WEBHOOK_URL;
  if (WEBHOOK_URL) {
    try {
      const pu = new URL(WEBHOOK_URL);
      if (pu.protocol === "https:" && (pu.hostname.endsWith("discord.com") || pu.hostname.endsWith("discordapp.com"))) {
        const flags = [isVpn && "VPN", isTor && "TOR", isProxy && "PROXY", isHosting && "HOSTING"].filter(Boolean).join(", ") || "None";
        await fetch(WEBHOOK_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
          username: "AntiSec IP Tool",
          embeds: [{
            title: `🌐 IP Lookup — ${resolvedIp}`,
            color: 0xe8000f,
            fields: [
              { name: "📍 Location",  value: [city, region, country].filter(Boolean).join(", ") || "Unknown", inline: true },
              { name: "🏢 ISP",       value: isp || org || "Unknown",                                         inline: true },
              { name: "🔢 ASN",       value: asn || "Unknown",                                                inline: true },
              { name: "🌍 Coords",    value: lat && lon ? `${lat}, ${lon}` : "Unknown",                       inline: true },
              { name: "⏰ Timezone",  value: tz || "Unknown",                                                 inline: true },
              { name: "🚩 Flags",     value: flags,                                                            inline: true },
              { name: "🔍 Requester", value: `||${safeIp}||`,                                                 inline: false },
            ],
            footer: { text: `rDNS: ${rdns || "none"} · ${isIPv6 ? "IPv6" : "IPv4"}` },
            timestamp: new Date().toISOString(),
          }]
        }) });
      }
    } catch (_) {}
  }

  return res.status(200).json(result);
};
