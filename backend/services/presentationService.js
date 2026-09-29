'use strict';

/**
 * QR credential presentation.
 *
 * The document left the signing scheme open ("signature or presentation
 * data"). This fixes it: Ed25519 detached signature over a compact,
 * canonically-ordered payload, base64url encoded.
 *
 * Two distinct checks, which must never be conflated in the UI:
 *   LOCAL  - signature valid, issuer key known, not expired. Provable offline.
 *   LEDGER - credential exists on Fabric, hash matches, status is ACTIVE.
 *            Requires connectivity. Only this catches a revocation.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEY_DIR = process.env.ISSUER_KEY_DIR || path.join(__dirname, '../config/keys');
const PRESENTATION_TTL_SECONDS = Number(process.env.PRESENTATION_TTL || 300);

/** Generates the issuer keypair on first run so the prototype is self-bootstrapping. */
function loadIssuerKeys(issuerId) {
  fs.mkdirSync(KEY_DIR, { recursive: true });
  const privPath = path.join(KEY_DIR, `${issuerId}.priv.pem`);
  const pubPath = path.join(KEY_DIR, `${issuerId}.pub.pem`);

  if (!fs.existsSync(privPath)) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    fs.writeFileSync(privPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }));
  }

  return {
    privateKey: crypto.createPrivateKey(fs.readFileSync(privPath)),
    publicKey: crypto.createPublicKey(fs.readFileSync(pubPath)),
  };
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function canonicalBytes(payload) {
  const ordered = Object.keys(payload).sort().reduce((acc, k) => {
    acc[k] = payload[k];
    return acc;
  }, {});
  return Buffer.from(JSON.stringify(ordered), 'utf8');
}

/**
 * Builds the QR payload. Deliberately minimal: no name, no photograph, no
 * document number. A scanner that captures this QR learns an opaque holder
 * reference and a hash, nothing about the person.
 */
function createPresentation({ credentialId, issuerId, holderRef, credentialHash, credentialType }) {
  const { privateKey } = loadIssuerKeys(issuerId);

  const payload = {
    v: 1,
    cid: credentialId,
    iss: issuerId,
    sub: holderRef,           // pseudonymous reference, not the holder's name
    typ: credentialType,
    h: credentialHash,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + PRESENTATION_TTL_SECONDS,
    nonce: crypto.randomBytes(8).toString('hex'),
  };

  const message = canonicalBytes(payload);
  const signature = crypto.sign(null, message, privateKey); // null = Ed25519

  // "p." prefix marks the scheme so a scanner can reject unrelated QR codes early.
  return `p.${b64url(message)}.${b64url(signature)}`;
}

/** Offline check. Returns what can be proved without touching the ledger. */
function verifyPresentationLocally(token) {
  const parts = String(token).trim().split('.');
  if (parts.length !== 3 || parts[0] !== 'p') {
    return { localResult: 'MALFORMED', reason: 'Not a recognised presentation token' };
  }

  let payload;
  const message = Buffer.from(parts[1], 'base64url');
  try {
    payload = JSON.parse(message.toString('utf8'));
  } catch {
    return { localResult: 'MALFORMED', reason: 'Payload is not valid JSON' };
  }

  const pubPath = path.join(KEY_DIR, `${payload.iss}.pub.pem`);
  if (!fs.existsSync(pubPath)) {
    return { localResult: 'UNKNOWN_ISSUER', reason: `No trusted key for issuer ${payload.iss}`, payload };
  }

  const publicKey = crypto.createPublicKey(fs.readFileSync(pubPath));
  const signature = Buffer.from(parts[2], 'base64url');

  let signatureValid = false;
  try {
    signatureValid = crypto.verify(null, message, publicKey, signature);
  } catch {
    signatureValid = false;
  }

  if (!signatureValid) {
    return { localResult: 'BAD_SIGNATURE', reason: 'Signature does not verify', payload };
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now > payload.exp) {
    return { localResult: 'EXPIRED', reason: 'Presentation window has elapsed', payload };
  }

  return {
    localResult: 'SIGNATURE_OK',
    reason: 'Issuer signature valid and presentation is within its validity window. '
          + 'Revocation status NOT checked — requires ledger connectivity.',
    payload,
  };
}

module.exports = { createPresentation, verifyPresentationLocally, loadIssuerKeys };
