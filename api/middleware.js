"use strict";


const crypto = require("crypto");
const kv     = require("./kv");

const REQUIRED_VARS = [
  "SESSION_SECRET",
  "DISCORD_BOT_TOKEN",
  "DISCORD_GUILD_ID",
  "DISCORD_ROLE_ID",
  "DISCORD_INVITE",
  "APP_BASE_URL",
  "GITHUB_TOKEN",
];

let _envChecked = false;
function envCheck() {
  if (_envChecked) return null;
  const missing = REQUIRED_VARS.filter((v) => !process.env[v]);
  if (missing.length > 0) {
    console.error("[AntiSec] Missing required env vars:", missing.join(", "));
    return { error: `Server misconfiguration. Contact admin.`, missing };
  }
  _envChecked = true;
  return null;
}

async function kvRateLimit(key, max, windowSecs) {
  const count = await kv.incr(key, windowSecs);
  return count > max;
}

const MAX_AGE_MS    = 30_000; // 30 seconds
const MAX_FUTURE_MS =  5_000; //  5 seconds clock skew tolerance

function replayGuard(req) {
  const raw = req.headers["x-request-time"];
  if (!raw) return "Missing X-Request-Time header";
  const ts  = parseInt(raw, 10);
  if (!Number.isFinite(ts)) return "Invalid X-Request-Time";
  const now  = Date.now();
  const diff = now - ts;
  if (diff > MAX_AGE_MS)    return "Request expired — possible replay attack";
  if (diff < -MAX_FUTURE_MS) return "Request timestamp is in the future";
  return null;
}


function csrfSecret() {
  const s = process.env.SESSION_SECRET;
  if (!s) throw new Error("SESSION_SECRET not set");
  return s;
}

function currentHourTag() {
  return new Date().toISOString().slice(0, 13); // "2025-06-07T14"
}
function prevHourTag() {
  const d = new Date(Date.now() - 3_600_000);
  return d.toISOString().slice(0, 13);
}

function makeCsrfToken(userId) {
  const tag  = currentHourTag();
  const data = `${userId}:${tag}`;
  return crypto.createHmac("sha256", csrfSecret()).update(data).digest("hex");
}

function verifyCsrfToken(token, userId) {
  if (typeof token !== "string" || token.length !== 64) return false;
  const tokenBuf = Buffer.from(token, "hex");
  for (const tag of [currentHourTag(), prevHourTag()]) {
    const expected    = crypto.createHmac("sha256", csrfSecret()).update(`${userId}:${tag}`).digest("hex");
    const expectedBuf = Buffer.from(expected, "hex");
    try {
      if (tokenBuf.length === expectedBuf.length && crypto.timingSafeEqual(tokenBuf, expectedBuf)) return true;
    } catch { /* continue */ }
  }
  return false;
}

function getCorsHeaders(req) {
  const origin  = req.headers["origin"] || "";
  const allowed = process.env.APP_BASE_URL;
  const ao      = allowed && origin === allowed ? origin : (allowed || "null");
  return {
    "Access-Control-Allow-Origin":  ao,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token, X-Request-Time",
    "X-Content-Type-Options":       "nosniff",
    "X-Frame-Options":              "DENY",
    "Referrer-Policy":              "no-referrer",
    "Vary":                         "Origin",
  };
}

module.exports = { envCheck, kvRateLimit, replayGuard, makeCsrfToken, verifyCsrfToken, getCorsHeaders };
