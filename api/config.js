"use strict";

const { getCorsHeaders } = require("./middleware");

module.exports = function handler(req, res) {
  Object.entries(getCorsHeaders(req)).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader("Cache-Control", "public, max-age=300");
  if (req.method === "OPTIONS") return res.status(204).end();
  return res.status(200).json({ invite: process.env.DISCORD_INVITE || "" });
};
