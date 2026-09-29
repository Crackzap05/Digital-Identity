'use strict';
const fs = require('fs');
const path = require('path');

/**
 * Off-chain store. Everything the ledger deliberately does not hold —
 * names, dates of birth, document references, full credential bodies —
 * lives here. In deployment this is the holder's device; for the prototype
 * it is a JSON file so the demo runs on one machine.
 */
const FILE = process.env.WALLET_PATH || path.join(__dirname, '../data/wallet.json');

function load() {
  try { return JSON.parse(fs.readFileSync(FILE, 'utf8')); }
  catch { return { identities: {}, credentials: {} }; }
}

function persist(db) {
  fs.mkdirSync(path.dirname(FILE), { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(db, null, 2), { mode: 0o600 });
}

function saveIdentityRecord(identityId, personalData) {
  const db = load();
  db.identities[identityId] = { ...personalData, storedAt: new Date().toISOString() };
  persist(db);
}

function saveCredential(holderId, credential) {
  const db = load();
  db.credentials[credential.credentialId] = { ...credential, holderId };
  persist(db);
}

function findCredential(credentialId) {
  return load().credentials[credentialId] || null;
}

function listCredentials(holderId) {
  const db = load();
  return Object.values(db.credentials).filter((c) => c.holderId === holderId);
}

module.exports = { saveIdentityRecord, saveCredential, findCredential, listCredentials };
