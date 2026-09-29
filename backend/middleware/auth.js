'use strict';
const crypto = require('crypto');

/**
 * Minimal HMAC-signed bearer token. Application-level authorisation only —
 * the ledger enforces its own rules independently via the role=issuer
 * certificate attribute, so a forged token here still cannot write.
 */
const SECRET = process.env.AUTH_SECRET || crypto.randomBytes(32).toString('hex');
const TTL_MS = 8 * 60 * 60 * 1000;

function sign(body) {
  return crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
}

function issueToken(username, role) {
  const body = Buffer.from(JSON.stringify({
    u: username, r: role, exp: Date.now() + TTL_MS,
  })).toString('base64url');
  return `${body}.${sign(body)}`;
}

function verifyToken(token) {
  const [body, sig] = String(token).split('.');
  if (!body || !sig) return null;
  const expected = sign(body);
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const claims = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (Date.now() > claims.exp) return null;
    return claims;
  } catch { return null; }
}

function requireRole(...roles) {
  return (req, res, next) => {
    const header = req.headers.authorization || '';
    const claims = verifyToken(header.replace(/^Bearer\s+/i, ''));
    if (!claims) return res.status(401).json({ error: 'Missing or invalid token' });
    if (!roles.includes(claims.r)) {
      return res.status(403).json({ error: `Requires one of: ${roles.join(', ')}` });
    }
    req.user = { username: claims.u, role: claims.r };
    next();
  };
}

module.exports = { issueToken, verifyToken, requireRole };
