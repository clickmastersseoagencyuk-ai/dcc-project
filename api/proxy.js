const dns = require('dns').promises;
const net = require('net');

function isPrivateIP(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    if (p[0] === 10) return true;
    if (p[0] === 127) return true;
    if (p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    return false;
  }
  if (ip === '::1') return true;
  if (ip.startsWith('fc') || ip.startsWith('fd')) return true;
  return false;
}

async function isSafeUrl(urlString) {
  let parsed;
  try { parsed = new URL(urlString); } catch { return false; }
  if (!/^https?:$/.test(parsed.protocol)) return false;
  try {
    const { address } = await dns.lookup(parsed.hostname);
    if (isPrivateIP(address)) return false;
  } catch {
    return false;
  }
  return true;
}

module.exports = async function handler(req, res) {
  const targetUrl = req.query.url;

  res.setHeader('Access-Control-Allow-Origin', '*');

  if (!targetUrl) {
    res.status(400).send('Missing url parameter');
    return;
  }

  const safe = await isSafeUrl(targetUrl);
  if (!safe) {
    res.status(403).send('Invalid or blocked URL');
    return;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(targetUrl, {
      redirect: 'follow',
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; DuplicateContentChecker/1.0)' }
    });
    clearTimeout(timeout);

    const text = await response.text();
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(response.status).send(text);
  } catch (e) {
    res.status(502).send('Fetch failed: ' + (e.message || 'unknown error'));
  }
};
