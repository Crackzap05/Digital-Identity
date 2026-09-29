'use strict';

/**
 * End-to-end test harness.
 *
 * Runs the seven test cases from the methodology against a live backend and
 * prints a markdown results table (test case | input | expected | actual |
 * latency) that can be pasted straight into the report.
 *
 *   node tests/e2e.test.js
 *   BASE_URL=http://localhost:3000 node tests/e2e.test.js
 */

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const stamp = Date.now();
const HOLDER = `holder-${stamp}`;
const ISSUER = 'ngo-alpha';

let token = null;
const rows = [];

async function api(path, { method = 'GET', body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const started = process.hrtime.bigint();
  const res = await fetch(BASE + path, { method, headers, body: body && JSON.stringify(body) });
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data, ms: Number(ms.toFixed(1)) };
}

function record(name, input, expected, actual, ms) {
  const pass = actual === expected;
  rows.push({ name, input, expected, actual, ms, pass });
  const mark = pass ? 'PASS' : 'FAIL';
  console.log(`${mark.padEnd(5)} ${name.padEnd(42)} expected=${expected.padEnd(12)} actual=${actual} (${ms} ms)`);
  return pass;
}

async function main() {
  console.log(`Running against ${BASE}\n`);

  const login = await api('/api/login', {
    method: 'POST', body: { username: 'tester', password: 'tester', role: 'issuer' },
  });
  if (!login.ok) throw new Error('Login failed — is the backend running?');
  token = login.data.token;

  // TC1 — register a new identity
  let r = await api('/api/identity', {
    method: 'POST',
    body: { identityId: HOLDER, issuerId: ISSUER, personalData: { fullName: 'Test Subject', dateOfBirth: '1990-01-01' } },
  });
  record('TC1 register new identity', HOLDER, 'CREATED', r.ok ? 'CREATED' : `ERROR: ${r.data.error}`, r.ms);

  // TC2 — duplicate registration must be rejected
  r = await api('/api/identity', {
    method: 'POST',
    body: { identityId: HOLDER, issuerId: ISSUER, personalData: { fullName: 'Test Subject' } },
  });
  record('TC2 duplicate identity', HOLDER, 'REJECTED', r.ok ? 'CREATED' : 'REJECTED', r.ms);

  // TC3 — issue a credential
  r = await api('/api/credential', {
    method: 'POST',
    body: { holderId: HOLDER, issuerId: ISSUER, credentialType: 'ProofOfIdentity', claims: { nationality: 'MM' } },
  });
  const credentialId = r.data.credentialId;
  const presentationToken = r.data.presentationToken;
  const credentialHash = r.data.credentialHash;
  record('TC3 issue credential', HOLDER, 'ACTIVE', r.data?.payload?.status || `ERROR: ${r.data.error}`, r.ms);

  // TC4 — verify the active credential
  r = await api('/api/verify', { method: 'POST', body: { presentationToken } });
  record('TC4 verify active credential', credentialId, 'VALID', r.data.finalResult || 'ERROR', r.ms);

  // TC4b — offline check reports UNCONFIRMED, never VALID
  r = await api('/api/verify', { method: 'POST', body: { presentationToken, offlineOnly: true } });
  record('TC4b offline check does not confirm', credentialId, 'UNCONFIRMED', r.data.finalResult || 'ERROR', r.ms);

  // TC5 — issuing org revokes it
  r = await api(`/api/credential/${credentialId}/revoke`, {
    method: 'POST', body: { reason: 'automated test' },
  });
  record('TC5 revoke credential', credentialId, 'REVOKED', r.data?.payload?.status || `ERROR: ${r.data.error}`, r.ms);

  // TC6 — the same presentation must now be rejected
  r = await api('/api/verify', { method: 'POST', body: { presentationToken } });
  record('TC6 verify after revocation', credentialId, 'REJECTED', r.data.finalResult || 'ERROR', r.ms);

  // TC7 — altered hash must not verify
  r = await api('/api/verify', {
    method: 'POST', body: { credentialId, credentialHash: 'f'.repeat(64) },
  });
  record('TC7 altered hash', 'tampered digest', 'INVALID', r.data.finalResult || 'ERROR', r.ms);

  // TC8 — unknown credential
  r = await api('/api/verify', {
    method: 'POST', body: { credentialId: 'cred-does-not-exist', credentialHash: credentialHash },
  });
  record('TC8 unknown credential', 'cred-does-not-exist', 'NOT_FOUND', r.data.finalResult || 'ERROR', r.ms);

  // TC9 — unauthenticated write must be refused before it reaches Fabric
  const saved = token; token = null;
  r = await api('/api/credential', {
    method: 'POST', body: { holderId: HOLDER, issuerId: ISSUER, credentialType: 'ProofOfIdentity', claims: {} },
  });
  record('TC9 unauthenticated issuance', 'no bearer token', 'DENIED', r.status === 401 ? 'DENIED' : `HTTP ${r.status}`, r.ms);
  token = saved;

  // TC10 — verifier reconciles an acceptance it made while offline
  r = await api('/api/sync', { method: 'POST', body: { credentialIds: [credentialId] } });
  const flagged = r.data.staleAcceptances?.length === 1 ? 'FLAGGED' : 'NOT_FLAGGED';
  record('TC10 sync flags stale acceptance', credentialId, 'FLAGGED', flagged, r.ms);

  // ---- report ----
  const passed = rows.filter((x) => x.pass).length;
  console.log(`\n${passed}/${rows.length} passed\n`);

  console.log('| Test case | Input | Expected | Actual | Latency (ms) | Result |');
  console.log('|---|---|---|---|---|---|');
  for (const x of rows) {
    console.log(`| ${x.name} | \`${x.input}\` | ${x.expected} | ${x.actual} | ${x.ms} | ${x.pass ? 'Pass' : 'Fail'} |`);
  }

  const m = await api('/api/metrics');
  console.log('\nBackend metrics:', JSON.stringify(m.data, null, 2));

  process.exit(passed === rows.length ? 0 : 1);
}

main().catch((e) => { console.error('\nHarness error:', e.message); process.exit(1); });
