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

exports.handler = async function (event) {
  const targetUrl = event.queryStringParameters && event.queryStringParameters.url;

  if (!targetUrl) {
    return { statusCode: 400, headers: { 'Access-Control-Allow-Origin': '*' }, body: 'Missing url parameter' };
  }

  const safe = await isSafeUrl(targetUrl);
  if (!safe) {
    return { statusCode: 403, headers: { 'Access-Control-Allow-Origin': '*' }, body: 'Invalid or blocked URL' };
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
    return {
      statusCode: response.status,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'text/plain; charset=utf-8'
      },
      body: text
    };
  } catch (e) {
    return {
      statusCode: 502,
      headers: { 'Access-Control-Allow-Origin': '*' },
      body: 'Fetch failed: ' + (e.message || 'unknown error')
    };
  }
};
