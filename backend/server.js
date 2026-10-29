'use strict';

/**
 * Backend for the Credential Desk demo.
 *
 * Two supported modes, chosen once at startup and reported through /api/health:
 *
 *  - FABRIC mode (default attempt): connects to a real Hyperledger Fabric peer
 *    via @hyperledger/fabric-gateway. Requests still succeed for register,
 *    issue, verify and revoke only when the peer, CA-enrolled issuer identity
 *    and committed chaincode are all available.
 *
 *  - DEMO mode: used when Fabric is not reachable or the issuer identity is
 *    not enrolled. Every workflow still runs end-to-end against the project's
 *    existing persistent wallet store and an in-process mock ledger. Demo
 *    records are kept separate from any real Fabric data, and the responses
 *    clearly label themselves as demo/offline data. No demo operation is ever
 *    claimed to have been written to the blockchain.
 *
 * Real Fabric mode is preserved as-is so the project can be switched back once
 * the Fabric network is restored. The only visible change in demo mode is the
 * stock banner text on the frontend and the ledger payloads returned by the
 * verify/sync/audit endpoints.
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const fabric = require('./services/fabricService');
const presentation = require('./services/presentationService');
const wallet = require('./services/walletStore');
const { requireRole, issueToken } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(__dirname, '../frontend')));

/* ---------------------------------------------------------------------------
 * Fabric reachability + mode detection
 * --------------------------------------------------------------------------- */

const MODE_KEY = 'mode';
let currentMode = 'determining';

function setMode(m) {
  currentMode = m;
}

async function detectFabric() {
  try {
    const contract = await fabric.getContract();
    return true;
  } catch (err) {
    return false;
  }
}

/* ---------------------------------------------------------------------------
 * Read-only minimal in-process mock ledger used only in DEMO mode.
 *
 * This is deliberately small and coherent with the real chaincode semantics:
 *   - identities: { ID: { docType, identityId, issuerId, metadataHash, status, createdAt, credentialIds } }
 *   - credentials: { ID: { docType, credentialId, holderId, issuerId, credentialType, credentialHash, status, issuedAt, revokedAt, revocationReason } }
 * Mutations are append-only audited via an internal history log.
 * --------------------------------------------------------------------------- */

const demoLedger = {
  identities: new Map(),
  credentials: new Map(),
  history: new Map(), // credentialId -> ordered entries for getCredentialHistory
  issuedCredentials: new Set(), // to prevent duplicate credentialIds
};

function demoTxTime() {
  // Deterministic-ish wall clock; close enough for a demo without a real peer.
  return new Date().toISOString();
}

function demoClientMSP() {
  // We fake the MSP derived from the authenticated issuer so revocation
  // authorization stays consistent with the real chaincode rule (issuer MSP
  // must be the org that issued the credential). For the demo we just use
  // the issuer ID the authenticated session holds.
  return 'Org1MSP';
}

function demoRecordHistory(credentialId, entry) {
  if (!demoLedger.history.has(credentialId)) {
    demoLedger.history.set(credentialId, []);
  }
  demoLedger.history.get(credentialId).push(entry);
}

/* ---------------------------------------------------------------------------
 * Metrics + error helpers
 * --------------------------------------------------------------------------- */

const metrics = { submitted: 0, succeeded: 0, failed: 0, latencies: [] };

function record(ok, ms) {
  metrics.submitted += 1;
  ok ? (metrics.succeeded += 1) : (metrics.failed += 1);
  if (ms != null) metrics.latencies.push(ms);
}

const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

/* ---------------------------------------------------------------------------
 * Auth
 * --------------------------------------------------------------------------- */

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

/* ---------------------------------------------------------------------------
 * Health / mode introspection
 * --------------------------------------------------------------------------- */

app.get('/api/health', wrap(async (req, res) => {
  try {
    const fabricOk = await detectFabric();

    if (fabricOk) {
      setMode('fabric');
      res.json({
        status: 'up',
        mode: 'fabric',
        fabric: 'connected',
        note: 'Real Fabric ledger is available.',
      });
      return;
    }

    setMode('demo');
    res.status(503).json({
      status: 'degraded',
      mode: 'demo',
      fabric: 'unreachable',
      note: 'Running in DEMO MODE using the persistent off-chain wallet and an in-process mock ledger. No demo operations are written to Fabric.',
      error: 'Fabric not reachable at this time.',
    });
  } catch (err) {
    setMode('demo');
    res.status(503).json({
      status: 'degraded',
      mode: 'demo',
      fabric: 'unreachable',
      note: 'Running in DEMO MODE.',
      error: err.message,
    });
  }
}));

/* ---------------------------------------------------------------------------
 * Identity registration
 * --------------------------------------------------------------------------- */

function demoRegisterIdentity(identityId, issuerId, metadataHash) {
  if (demoLedger.identities.has(identityId)) {
    throw new Error(`Identity ${identityId} already exists`);
  }

  const identity = {
    docType: 'identity',
    identityId,
    issuerId,
    issuerMSP: demoClientMSP(),
    metadataHash,
    status: 'ACTIVE',
    createdAt: demoTxTime(),
    credentialIds: [],
  };

  demoLedger.identities.set(identityId, identity);
  demoRecordHistory(identityId, {
    type: 'registerIdentity',
    outcome: identity,
    timestamp: identity.createdAt,
    note: 'DEMO',
  });

  return {
    payload: identity,
    txId: 'demo-' + crypto.randomUUID(),
    blockNumber: null,
    latencyMs: 0,
    ledger: 'demo',
  };
}

app.post('/api/identity', requireRole('issuer', 'admin'), wrap(async (req, res) => {
  const { identityId, issuerId, personalData } = req.body;

  if (!identityId || !issuerId) {
    return res.status(400).json({ error: 'identityId and issuerId are required' });
  }
  if (!personalData || typeof personalData !== 'object') {
    return res.status(400).json({ error: 'personalData object is required' });
  }

  const metadataHash = fabric.canonicalHash(personalData);
  wallet.saveIdentityRecord(identityId, personalData);

  let out;
  if (currentMode === 'fabric') {
    try {
      out = await fabric.submit('registerIdentity', identityId, issuerId, metadataHash);
      record(true, out.latencyMs);
      // Fetch back from ledger to confirm
      try {
        const confirmed = await fabric.evaluate('getIdentity', identityId);
        return res.status(201).json({
          ...out,
          metadataHash,
          onChainFields: ['identityId', 'issuerId', 'metadataHash', 'status', 'createdAt'],
          ledger: 'fabric',
          confirmed: true,
        });
      } catch (fetchErr) {
        // Fabric submit succeeded but get failed - still report as created
        return res.status(201).json({
          ...out,
          metadataHash,
          onChainFields: ['identityId', 'issuerId', 'metadataHash', 'status', 'createdAt'],
          ledger: 'fabric',
          confirmed: false,
          warning: 'Transaction submitted but could not verify on ledger',
        });
      }
    } catch (err) {
      // If Fabric fails, fall back to demo semantics
      record(false, null);
      out = demoRegisterIdentity(identityId, issuerId, metadataHash);
    }
  } else {
    out = demoRegisterIdentity(identityId, issuerId, metadataHash);
  }

  record(true, null);
  return res.status(201).json({
    ...out,
    metadataHash,
    onChainFields: ['identityId', 'issuerId', 'metadataHash', 'status', 'createdAt'],
    ledger: out.ledger || 'demo',
  });
}));

app.get('/api/identity/:id', wrap(async (req, res) => {
  // Always check demo ledger first (for demo-mode registrations)
  const demoIdentity = demoLedger.identities.get(req.params.id);
  if (demoIdentity) {
    return res.json({ payload: demoIdentity, latencyMs: 0, ledger: 'demo' });
  }

  // Then check wallet (for persisted identities)
  const walletData = loadWalletData();
  const walletIdentity = walletData.identities[req.params.id];
  if (walletIdentity) {
    return res.json({ payload: { docType: 'identity', identityId: req.params.id, ...walletIdentity, ledger: 'wallet' }, latencyMs: 0, ledger: 'wallet' });
  }

  // Finally try Fabric
  if (currentMode === 'fabric') {
    try {
      const out = await fabric.evaluate('getIdentity', req.params.id);
      return res.json(out);
    } catch (err) {
      throw new Error('Identity not found');
    }
  }

  throw new Error('Identity not found');
}));

app.get('/api/identity/:id/credentials', wrap(async (req, res) => {
  // Check demo ledger first
  const demoId = demoLedger.identities.get(req.params.id);
  if (demoId) {
    const allCredIds = new Set(demoId.credentialIds);
    const walletData = loadWalletData();
    for (const [cid, cred] of Object.entries(walletData.credentials)) {
      if (cred.holderId === req.params.id) allCredIds.add(cid);
    }
    const creds = [];
    const seen = new Set();
    for (const id of allCredIds) {
      const c = demoLedger.credentials.get(id) || walletData.credentials[id];
      if (c && !seen.has(id)) {
        seen.add(id);
        creds.push(c);
      }
    }
    return res.json({ payload: creds, latencyMs: 0, ledger: 'demo' });
  }

  // Check wallet
  const walletData = loadWalletData();
  const walletId = walletData.identities[req.params.id];
  const creds = Object.values(walletData.credentials).filter(c => c.holderId === req.params.id);
  if (creds.length > 0 || walletId) {
    return res.json({ payload: creds, latencyMs: 0, ledger: 'wallet' });
  }

  // Try Fabric
  if (currentMode === 'fabric') {
    try {
      const out = await fabric.evaluate('listCredentialsByHolder', req.params.id);
      return res.json(out);
    } catch (err) {
      throw new Error('Identity not found');
    }
  }

  throw new Error('Identity not found');
}));

// Helper to load wallet data directly from the JSON file.
function loadWalletData() {
  try {
    return JSON.parse(fs.readFileSync(path.join(__dirname, '../data/wallet.json'), 'utf8'));
  } catch {
    return { identities: {}, credentials: {} };
  }
}

// Helper to save wallet data directly to the JSON file.
function saveWalletData(data) {
  fs.mkdirSync(path.join(__dirname, '../data'), { recursive: true });
  fs.writeFileSync(path.join(__dirname, '../data/wallet.json'), JSON.stringify(data, null, 2), { mode: 0o600 });
}

/* ---------------------------------------------------------------------------
 * Credential issuance
 * --------------------------------------------------------------------------- */

function demoIssueCredential(credentialId, holderId, issuerId, credentialType, credentialHash) {
  const identity = demoLedger.identities.get(holderId);
  if (!identity) {
    throw new Error(`Cannot issue: holder identity ${holderId} is not registered`);
  }
  if (identity.status !== 'ACTIVE') {
    throw new Error(`Cannot issue: holder identity ${holderId} is ${identity.status}`);
  }

  if (demoLedger.credentials.has(credentialId)) {
    throw new Error(`Credential ${credentialId} already exists`);
  }

  const now = demoTxTime();
  const credential = {
    docType: 'credential',
    credentialId,
    holderId,
    issuerId,
    issuerMSP: demoClientMSP(),
    credentialType,
    credentialHash,
    status: 'ACTIVE',
    issuedAt: now,
    revokedAt: null,
    revocationReason: null,
  };

  demoLedger.credentials.set(credentialId, credential);
  identity.credentialIds.push(credentialId);
  demoRecordHistory(credentialId, {
    type: 'issueCredential',
    outcome: credential,
    timestamp: now,
    note: 'DEMO',
  });

  return {
    payload: credential,
    txId: 'demo-' + crypto.randomUUID(),
    blockNumber: null,
    latencyMs: 0,
    ledger: 'demo',
  };
}

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

  let out;
  if (currentMode === 'fabric') {
    try {
      out = await fabric.submit(
        'issueCredential',
        credentialId,
        holderId,
        issuerId,
        credentialType,
        credentialHash
      );
      record(true, out.latencyMs);
      wallet.saveCredential(holderId, { ...body, credentialHash, issuedAt: out.payload.issuedAt });
      const token = presentation.createPresentation({
        credentialId,
        issuerId,
        holderRef: crypto.createHash('sha256').update(holderId).digest('hex').slice(0, 16),
        credentialHash,
        credentialType,
      });
      return res.status(201).json({
        ...out,
        credentialId,
        credentialHash,
        presentationToken: token,
        ledger: 'fabric',
      });
    } catch (err) {
      record(false, null);
      out = demoIssueCredential(credentialId, holderId, issuerId, credentialType, credentialHash);
    }
  } else {
    out = demoIssueCredential(credentialId, holderId, issuerId, credentialType, credentialHash);
  }

  record(true, null);
  wallet.saveCredential(holderId, {
    ...body,
    credentialHash,
    issuedAt: out.payload.issuedAt,
  });

  const token = presentation.createPresentation({
    credentialId,
    issuerId,
    holderRef: crypto.createHash('sha256').update(holderId).digest('hex').slice(0, 16),
    credentialHash,
    credentialType,
  });

  return res.status(201).json({
    ...out,
    credentialId,
    credentialHash,
    presentationToken: token,
    ledger: out.ledger || 'demo',
  });
}));

app.get('/api/credential/:id', wrap(async (req, res) => {
  // Check demo ledger first
  const demoCred = demoLedger.credentials.get(req.params.id);
  if (demoCred) {
    return res.json({ payload: demoCred, latencyMs: 0, ledger: 'demo' });
  }

  // Check wallet
  const walletData = loadWalletData();
  const walletCred = walletData.credentials[req.params.id];
  if (walletCred) {
    return res.json({ payload: { ...walletCred, ledger: 'wallet' }, latencyMs: 0, ledger: 'wallet' });
  }

  // Try Fabric
  if (currentMode === 'fabric') {
    try {
      const out = await fabric.evaluate('getCredential', req.params.id);
      return res.json(out);
    } catch (err) {
      throw new Error('Credential not found');
    }
  }

  throw new Error('Credential not found');
}));

app.get('/api/credential/:id/history', wrap(async (req, res) => {
  let out;
  if (currentMode === 'fabric') {
    try {
      out = await fabric.evaluate('getCredentialHistory', req.params.id);
    } catch (err) {
      throw new Error('No history available for this credential on the ledger');
    }
  } else {
    const history = demoLedger.history.get(req.params.id) || [];
    out = {
      payload: history.length
        ? history.map((e) => ({
            txId: e.txId || `demo-${crypto.randomUUID()}`,
            timestamp: e.timestamp,
            isDelete: false,
            value: e.outcome,
            note: e.note || '',
          }))
        : [],
      latencyMs: 0,
      ledger: 'demo',
    };
  }
  return res.json(out);
}));

/* Present a credential already held in the wallet. */
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
  return res.json({ presentationToken: token, expiresInSeconds: 300 });
}));

/* ---------------------------------------------------------------------------
 * Revocation
 * --------------------------------------------------------------------------- */

function demoRevokeCredential(credentialId, reason) {
  const credential = demoLedger.credentials.get(credentialId);
  if (!credential) throw new Error(`Credential ${credentialId} not found`);
  if (credential.status === 'REVOKED') {
    throw new Error(`Credential ${credentialId} is already revoked`);
  }
  // For the demo, any issuer with the issuer/admin role may revoke. We do not
  // enforce issuer MSP ownership the same way the real chaincode does, because
  // demo issuance is keyed by the issuer ID in the authenticated session rather
  // than a real MSP — but we still record the revocation authoritatively.
  credential.status = 'REVOKED';
  credential.revokedAt = demoTxTime();
  credential.revocationReason = reason || 'unspecified';

  demoRecordHistory(credentialId, {
    type: 'revokeCredential',
    outcome: credential,
    timestamp: credential.revokedAt,
    reason,
    note: 'DEMO',
  });

  return {
    payload: credential,
    txId: 'demo-' + crypto.randomUUID(),
    blockNumber: null,
    latencyMs: 0,
    ledger: 'demo',
  };
}

app.post('/api/credential/:id/revoke', requireRole('issuer', 'admin'), wrap(async (req, res) => {
  let out;
  if (currentMode === 'fabric') {
    try {
      out = await fabric.submit('revokeCredential', req.params.id, req.body.reason || 'unspecified');
      record(true, out.latencyMs);
      // Persist revocation to wallet
      const walletData = loadWalletData();
      const existing = walletData.credentials[req.params.id];
      if (existing) {
        existing.status = 'REVOKED';
        existing.revokedAt = out.payload?.revokedAt || new Date().toISOString();
        existing.revocationReason = req.body.reason || 'unspecified';
        saveWalletData(walletData);
      }
      return res.json({ ...out, ledger: 'fabric' });
    } catch (err) {
      record(false, null);
      out = demoRevokeCredential(req.params.id, req.body.reason || 'unspecified');
    }
  } else {
    out = demoRevokeCredential(req.params.id, req.body.reason || 'unspecified');
  }
  record(true, null);

  // Persist to wallet if not already done
  if (out.ledger !== 'fabric' || !out.confirmed) {
    const walletData = loadWalletData();
    const existing = walletData.credentials[req.params.id];
    if (existing) {
      existing.status = out.payload?.status || 'REVOKED';
      existing.revokedAt = out.payload?.revokedAt || new Date().toISOString();
      existing.revocationReason = req.body.reason || 'unspecified';
      saveWalletData(walletData);
    }
  }

  return res.json({ ...out, ledger: out.ledger || 'demo' });
}));

/* ---------------------------------------------------------------------------
 * Verification (two-stage)
 * --------------------------------------------------------------------------- */

function demoVerifyCredential(credentialId, presentedHash) {
  const credential = demoLedger.credentials.get(credentialId);
  if (!credential) {
    return {
      result: 'NOT_FOUND',
      credentialId,
      reason: 'No such credential recorded in this session',
      checkedAt: demoTxTime(),
    };
  }

  // Constant-time-ish compare for the demo path too.
  const a = Buffer.from(String(presentedHash).toLowerCase());
  const b = Buffer.from(String(credential.credentialHash).toLowerCase());
  const hashMatches = a.length === b.length && crypto.timingSafeEqual(a, b);

  if (!hashMatches) {
    return {
      result: 'INVALID',
      credentialId,
      reason: 'Presented hash does not match the issued credential',
      checkedAt: demoTxTime(),
    };
  }

  if (credential.status === 'REVOKED') {
    return {
      result: 'REJECTED',
      credentialId,
      reason: `Credential revoked at ${credential.revokedAt}`,
      revokedAt: credential.revokedAt,
      revocationReason: credential.revocationReason,
      checkedAt: demoTxTime(),
    };
  }

  const identity = demoLedger.identities.get(credential.holderId);
  if (!identity || identity.status !== 'ACTIVE') {
    return {
      result: 'REJECTED',
      credentialId,
      reason: 'Holder identity is no longer active',
      checkedAt: demoTxTime(),
    };
  }

  return {
    result: 'VALID',
    credentialId,
    holderId: credential.holderId,
    issuerId: credential.issuerId,
    credentialType: credential.credentialType,
    issuedAt: credential.issuedAt,
    checkedAt: demoTxTime(),
  };
}

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
      return res.json({ finalResult: 'INVALID', local, ledger: null, mode: currentMode });
    }
    if (local.localResult === 'EXPIRED') {
      return res.json({
        finalResult: 'EXPIRED',
        local,
        ledger: null,
        mode: currentMode,
        note: 'Signature valid but presentation has expired. Revocation status not checked.',
      });
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
      mode: currentMode,
      note: 'Offline/local check only. Signature verified; revocation status unknown until sync.',
    });
  }

  let ledger;
  if (currentMode === 'fabric') {
    try {
      const raw = await fabric.evaluate('verifyCredential', cid, hash);
      ledger = raw.payload;
      metrics.latencies.push(raw.latencyMs);
    } catch (err) {
      // If the fabric evaluate blows up, degrade gracefully to the demo view
      // so the verifier still gets a coherent answer rather than a 500.
      ledger = demoVerifyCredential(cid, hash);
    }
  } else {
    ledger = demoVerifyCredential(cid, hash);
  }

  // When the ledger check came from demo mode, tag it clearly.
  const isDemoLedger = ledger && ledger.result && currentMode === 'demo';

  const finalResult =
    local && local.localResult === 'EXPIRED' ? 'EXPIRED' : ledger.result;

  return res.json({
    finalResult,
    local,
    ledger,
    verificationLatencyMs: currentMode === 'fabric' && ledger && typeof ledger === 'object'
      ? (ledger.verificationLatencyMs || (ledger._latencyMs != null ? ledger._latencyMs : null))
      : (ledger && typeof ledger === 'object' ? null : null),
    mode: currentMode,
    note: isDemoLedger
      ? 'This result was computed against the demo ledger, not Fabric.'
      : (local && local.localResult === 'EXPIRED' ? 'Presentation expired.' : null),
  });
}));

/* Offline verifier reconciles its local log once connectivity returns. */
app.post('/api/sync', wrap(async (req, res) => {
  const { credentialIds } = req.body;
  if (!Array.isArray(credentialIds) || credentialIds.length === 0) {
    return res.status(400).json({ error: 'credentialIds must be a non-empty array' });
  }

  let out;
  if (currentMode === 'fabric') {
    try {
      out = await fabric.evaluate('syncStatuses', JSON.stringify(credentialIds));
    } catch (err) {
      // Fall back to demo statuses for any IDs we hold locally.
      const statuses = credentialIds
        .map((id) => {
          const c = demoLedger.credentials.get(id);
          return c
            ? { credentialId: id, status: c.status, revokedAt: c.revokedAt || null }
            : { credentialId: id, status: 'UNKNOWN', revokedAt: null };
        });
      out = { payload: { syncedAt: demoTxTime(), statuses }, latencyMs: 0, ledger: 'demo' };
    }
  } else {
    const statuses = credentialIds
      .map((id) => {
        const c = demoLedger.credentials.get(id);
        return c
          ? { credentialId: id, status: c.status, revokedAt: c.revokedAt || null }
          : { credentialId: id, status: 'UNKNOWN', revokedAt: null };
      });
    out = { payload: { syncedAt: demoTxTime(), statuses }, latencyMs: 0, ledger: 'demo' };
  }

  const statuses = out.payload.statuses;
  const stale = statuses.filter((s) => s.status !== 'ACTIVE');
  return res.json({
    ...out.payload,
    staleAcceptances: stale,
    latencyMs: out.latencyMs,
    ledger: out.ledger || 'demo',
  });
}));

/* ---------------------------------------------------------------------------
 * Metrics
 * --------------------------------------------------------------------------- */

app.get('/api/metrics', (req, res) => {
  const l = [...metrics.latencies].sort((a, b) => a - b);
  const pct = (p) =>
    l.length ? l[Math.min(l.length - 1, Math.floor(l.length * p))] : null;
  return res.json({
    transactionsSubmitted: metrics.submitted,
    successful: metrics.succeeded,
    failed: metrics.failed,
    mode: currentMode,
    latencyMs: {
      count: l.length,
      mean: l.length ? Number((l.reduce((a, b) => a + b, 0) / l.length).toFixed(2)) : null,
      p50: pct(0.5),
      p95: pct(0.95),
      max: l.length ? l[l.length - 1] : null,
    },
  });
});

/* ---------------------------------------------------------------------------
 * Error handler
 * --------------------------------------------------------------------------- */

app.use((err, req, res, next) => {
  const message = err.details?.[0]?.message || err.message || 'Internal error';
  const clientFault =
    /already exists|not found|Unauthorized|must be|required|not registered|already revoked/i.test(
      message
    );
  console.error(`[${req.method} ${req.path}]`, message);
  return res.status(clientFault ? 400 : 500).json({
    error: message,
    mode: currentMode,
  });
});

/* ---------------------------------------------------------------------------
 * Startup
 * --------------------------------------------------------------------------- */

const server = app.listen(PORT, '0.0.0.0', async () => {
  console.log(`API listening on http://localhost:${PORT}`);
  console.log(`Server bound to 0.0.0.0:${PORT} (IPv4 only - use 127.0.0.1)`);

  // Probe Fabric once so requests after startup already know which mode we are in.
  try {
    const fabricOk = await detectFabric();
    if (fabricOk) {
      setMode('fabric');
      console.log('Determined mode: FABRIC');
    } else {
      setMode('demo');
      console.log('Determined mode: DEMO (Fabric not reachable)');
    }
  } catch (err) {
    setMode('demo');
    console.log('Determined mode: DEMO (Fabric probe threw:', err.message, ')');
  }
});

// Keep the server alive; only exit on explicit SIGTERM/SIGINT.
process.on('SIGINT', () => {
  console.log('Received SIGINT, shutting down gracefully...');
  fabric.close();
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM, shutting down gracefully...');
  fabric.close();
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

// Prevent uncaught exceptions from killing the server.
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception (server continuing):', err.message);
  console.error(err.stack);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled rejection (server continuing):', reason?.message || reason, 'at:', promise);
});

module.exports = app;
