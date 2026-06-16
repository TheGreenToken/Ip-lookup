// Proxy for OSM tiles to avoid CSP issues
export default async function handler(req, res) {
  const { z, x, y } = req.query;
  if (!z || !x || !y) return res.status(400).end();
  // validate
  const zi=parseInt(z), xi=parseInt(x), yi=parseInt(y);
  if(isNaN(zi)||isNaN(xi)||isNaN(yi)||zi<0||zi>18) return res.status(400).end();

  const servers = ['a','b','c'];
  const s = servers[(xi+yi)%3];
  const url = `https://${s}.tile.openstreetmap.org/${zi}/${xi}/${yi}.png`;

  try {
    const r = await fetch(url, { headers: { 'User-Agent': 'AntiSec-IP-Tool/1.0' } });
    if (!r.ok) return res.status(r.status).end();
    const buf = await r.arrayBuffer();
    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.send(Buffer.from(buf));
  } catch(e) {
    res.status(502).end();
  }
}
