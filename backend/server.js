'use strict';

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const fabric = require('./services/fabricService');
const presentation = require('./services/presentationService');
const wallet = require('./services/walletStore');
const { requireRole, issueToken } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(__dirname, '../frontend')));

/** Wraps an async handler so a rejected promise becomes a 4xx/5xx, not a hang. */
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const metrics = { submitted: 0, succeeded: 0, failed: 0, latencies: [] };

function record(ok, ms) {
  metrics.submitted += 1;
  ok ? (metrics.succeeded += 1) : (metrics.failed += 1);
  if (ms != null) metrics.latencies.push(ms);
}

// ----------------------------------------------------------------- auth

/** Demo login. A real deployment maps these roles to Fabric CA enrolments. */
app.post('/api/login', wrap(async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }
  if (!['issuer', 'verifier', 'holder', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'role must be issuer, verifier, holder or admin' });
  }
  res.json({ token: issueToken(username, role), username, role });
}));

// ------------------------------------------------------------- identity

app.post('/api/identity', requireRole('issuer', 'admin'), wrap(async (req, res) => {
  const { identityId, issuerId, personalData } = req.body;

  if (!identityId || !issuerId) {
    return res.status(400).json({ error: 'identityId and issuerId are required' });
  }
  if (!personalData || typeof personalData !== 'object') {
    return res.status(400).json({ error: 'personalData object is required' });
  }

  // personalData never leaves this process for the ledger — only its digest does.
  const metadataHash = fabric.canonicalHash(personalData);
  wallet.saveIdentityRecord(identityId, personalData);

  try {
    const out = await fabric.submit('registerIdentity', identityId, issuerId, metadataHash);
    record(true, out.latencyMs);
    res.status(201).json({ ...out, metadataHash, onChainFields: ['identityId', 'issuerId', 'metadataHash', 'status', 'createdAt'] });
  } catch (err) {
    record(false, null);
    throw err;
  }
}));

app.get('/api/identity/:id', wrap(async (req, res) => {
  const out = await fabric.evaluate('getIdentity', req.params.id);
  res.json(out);
}));

app.get('/api/identity/:id/credentials', wrap(async (req, res) => {
  const out = await fabric.evaluate('listCredentialsByHolder', req.params.id);
  res.json(out);
}));

// ----------------------------------------------------------- credential

app.post('/api/credential', requireRole('issuer', 'admin'), wrap(async (req, res) => {
  const { holderId, issuerId, credentialType, claims } = req.body;

  if (!holderId || !issuerId || !credentialType) {
    return res.status(400).json({ error: 'holderId, issuerId and credentialType are required' });
  }
  if (!claims || typeof claims !== 'object') {
    return res.status(400).json({ error: 'claims object is required' });
  }

  const credentialId = `cred-${crypto.randomUUID()}`;
  const body = { credentialId, holderId, issuerId, credentialType, claims };
  const credentialHash = fabric.canonicalHash(body);

  try {
    const out = await fabric.submit(
      'issueCredential', credentialId, holderId, issuerId, credentialType, credentialHash
    );
    record(true, out.latencyMs);

    // Full credential body goes to the holder-side store, not the ledger.
    wallet.saveCredential(holderId, { ...body, credentialHash, issuedAt: out.payload.issuedAt });

    const token = presentation.createPresentation({
      credentialId,
      issuerId,
      holderRef: crypto.createHash('sha256').update(holderId).digest('hex').slice(0, 16),
      credentialHash,
      credentialType,
    });

    res.status(201).json({ ...out, credentialId, credentialHash, presentationToken: token });
  } catch (err) {
    record(false, null);
    throw err;
  }
}));

app.get('/api/credential/:id', wrap(async (req, res) => {
  const out = await fabric.evaluate('getCredential', req.params.id);
  res.json(out);
}));

app.get('/api/credential/:id/history', wrap(async (req, res) => {
  const out = await fabric.evaluate('getCredentialHistory', req.params.id);
  res.json(out);
}));

/** Regenerates a short-lived QR token for a credential already in the wallet. */
app.post('/api/credential/:id/present', wrap(async (req, res) => {
  const stored = wallet.findCredential(req.params.id);
  if (!stored) return res.status(404).json({ error: 'Credential not held in this wallet' });

  const token = presentation.createPresentation({
    credentialId: stored.credentialId,
    issuerId: stored.issuerId,
    holderRef: crypto.createHash('sha256').update(stored.holderId).digest('hex').slice(0, 16),
    credentialHash: stored.credentialHash,
    credentialType: stored.credentialType,
  });
  res.json({ presentationToken: token, expiresInSeconds: 300 });
}));

app.post('/api/credential/:id/revoke', requireRole('issuer', 'admin'), wrap(async (req, res) => {
  try {
    const out = await fabric.submit('revokeCredential', req.params.id, req.body.reason || 'unspecified');
    record(true, out.latencyMs);
    res.json(out);
  } catch (err) {
    record(false, null);
    throw err;
  }
}));

// --------------------------------------------------------- verification

/**
 * Two-stage verification. The response always reports both stages separately
 * so the verifier UI can show exactly what was and was not checked.
 */
app.post('/api/verify', wrap(async (req, res) => {
  const { presentationToken, credentialId, credentialHash, offlineOnly } = req.body;

  let local = null;
  let cid = credentialId;
  let hash = credentialHash;

  if (presentationToken) {
    local = presentation.verifyPresentationLocally(presentationToken);
    if (local.payload) {
      cid = local.payload.cid;
      hash = local.payload.h;
    }
    if (['MALFORMED', 'BAD_SIGNATURE', 'UNKNOWN_ISSUER'].includes(local.localResult)) {
      return res.json({ finalResult: 'INVALID', local, ledger: null });
    }
  }

  if (!cid || !hash) {
    return res.status(400).json({ error: 'Supply a presentationToken, or credentialId and credentialHash' });
  }

  if (offlineOnly) {
    return res.json({
      finalResult: 'UNCONFIRMED',
      local,
      ledger: null,
      note: 'Offline check only. Signature verified; revocation status unknown until sync.',
    });
  }

  const out = await fabric.evaluate('verifyCredential', cid, hash);
  const ledger = out.payload;
  metrics.latencies.push(out.latencyMs);

  const finalResult =
    local && local.localResult === 'EXPIRED' ? 'EXPIRED' : ledger.result;

  res.json({ finalResult, local, ledger, verificationLatencyMs: out.latencyMs });
}));

/** Offline verifier reconciles its local log once connectivity returns. */
app.post('/api/sync', wrap(async (req, res) => {
  const { credentialIds } = req.body;
  if (!Array.isArray(credentialIds) || credentialIds.length === 0) {
    return res.status(400).json({ error: 'credentialIds must be a non-empty array' });
  }
  const out = await fabric.evaluate('syncStatuses', JSON.stringify(credentialIds));
  const stale = out.payload.statuses.filter((s) => s.status !== 'ACTIVE');
  res.json({ ...out.payload, staleAcceptances: stale, latencyMs: out.latencyMs });
}));

// -------------------------------------------------------------- metrics

app.get('/api/metrics', (req, res) => {
  const l = [...metrics.latencies].sort((a, b) => a - b);
  const pct = (p) => (l.length ? l[Math.min(l.length - 1, Math.floor(l.length * p))] : null);
  res.json({
    transactionsSubmitted: metrics.submitted,
    successful: metrics.succeeded,
    failed: metrics.failed,
    latencyMs: {
      count: l.length,
      mean: l.length ? Number((l.reduce((a, b) => a + b, 0) / l.length).toFixed(2)) : null,
      p50: pct(0.5),
      p95: pct(0.95),
      max: l.length ? l[l.length - 1] : null,
    },
  });
});

app.get('/api/health', wrap(async (req, res) => {
  try {
    await fabric.getContract();
    res.json({ status: 'up', fabric: 'connected' });
  } catch (err) {
    res.status(503).json({ status: 'degraded', fabric: 'unreachable', error: err.message });
  }
}));

// ---------------------------------------------------------- error handler

app.use((err, req, res, next) => {
  const message = err.details?.[0]?.message || err.message || 'Internal error';
  const clientFault = /already exists|not found|Unauthorized|must be|required|not registered|already revoked/i.test(message);
  console.error(`[${req.method} ${req.path}]`, message);
  res.status(clientFault ? 400 : 500).json({ error: message });
});

const server = app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
});

process.on('SIGINT', () => {
  fabric.close();
  server.close(() => process.exit(0));
});

module.exports = app;
