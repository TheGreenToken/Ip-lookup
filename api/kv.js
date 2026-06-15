"use strict";

const KV_URL   = process.env.KV_REST_API_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN;
const USE_KV   = !!(KV_URL && KV_TOKEN);

async function kvFetch(method, path, body) {
  const url  = `${KV_URL}${path}`;
  const opts = {
    method,
    headers: { Authorization: `Bearer ${KV_TOKEN}`, "Content-Type": "application/json" },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res  = await fetch(url, opts);
  const json = await res.json().catch(() => ({}));
  return json;
}

const memStore = new Map();

function memSet(key, value, ttlSeconds) {
  memStore.set(key, { value, expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : null });
}
function memGet(key) {
  const entry = memStore.get(key);
  if (!entry) return null;
  if (entry.expiresAt && Date.now() > entry.expiresAt) { memStore.delete(key); return null; }
  return entry.value;
}
function memDel(key) { memStore.delete(key); }
function memIncr(key, ttlSeconds) {
  const entry = memStore.get(key);
  if (!entry || (entry.expiresAt && Date.now() > entry.expiresAt)) {
    memStore.set(key, { value: 1, expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : null });
    return 1;
  }
  entry.value = (entry.value || 0) + 1;
  return entry.value;
}

const kv = {
  async set(key, value, ttlSeconds) {
    if (!USE_KV) { memSet(key, value, ttlSeconds); return; }
    const encoded = encodeURIComponent(JSON.stringify(value));
    let path = `/set/${encodeURIComponent(key)}/${encoded}`;
    if (ttlSeconds) path += `?ex=${ttlSeconds}`;
    await kvFetch("POST", path).catch(console.error);
  },
  async get(key) {
    if (!USE_KV) return memGet(key);
    const data = await kvFetch("GET", `/get/${encodeURIComponent(key)}`).catch(() => ({}));
    if (data.result === null || data.result === undefined) return null;
    try { return JSON.parse(data.result); } catch { return data.result; }
  },
  async del(key) {
    if (!USE_KV) { memDel(key); return; }
    await kvFetch("POST", `/del/${encodeURIComponent(key)}`).catch(console.error);
  },

  async incr(key, ttlSeconds) {
    if (!USE_KV) return memIncr(key, ttlSeconds);
    try {
      const incrData = await kvFetch("POST", `/incr/${encodeURIComponent(key)}`);
      const count = Number(incrData.result) || 1;
      if (count === 1 && ttlSeconds) {
        await kvFetch("POST", `/expire/${encodeURIComponent(key)}/${ttlSeconds}`).catch(() => {});
      }
      return count;
    } catch { return 1; }
  },

  async blacklistToken(tokenHash, ttlSeconds) {
    await this.set(`antisec:blacklist:${tokenHash}`, 1, ttlSeconds);
  },
  async isBlacklisted(tokenHash) {
    const v = await this.get(`antisec:blacklist:${tokenHash}`);
    return v !== null;
  },
};

module.exports = kv;
