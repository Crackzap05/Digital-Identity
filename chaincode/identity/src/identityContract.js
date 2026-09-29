'use strict';

const { Contract } = require('fabric-contract-api');
const crypto = require('crypto');

const IDENTITY_PREFIX = 'IDENTITY_';
const CREDENTIAL_PREFIX = 'CREDENTIAL_';

const STATUS = {
  ACTIVE: 'ACTIVE',
  REVOKED: 'REVOKED',
};

const VERIFY = {
  VALID: 'VALID',
  REJECTED: 'REJECTED',
  INVALID: 'INVALID',
  NOT_FOUND: 'NOT_FOUND',
};

/**
 * IdentityContract
 *
 * On-chain data ONLY: identifiers, hashes, status, timestamps, issuer refs.
 * Never written on-chain: names, dates of birth, photographs, addresses,
 * biometrics, document scans. Those stay in the off-chain holder wallet and
 * the issuer's own records; the ledger carries a SHA-256 commitment instead.
 */
class IdentityContract extends Contract {

  constructor() {
    super('IdentityContract');
  }

  // ---------------------------------------------------------------- helpers

  /**
   * Deterministic timestamp. Date.now() is NOT deterministic across endorsing
   * peers and will cause read/write-set mismatch, so we take the time from the
   * transaction proposal, which every endorser sees identically.
   */
  _txTime(ctx) {
    const ts = ctx.stub.getTxTimestamp();
    const millis = Number(ts.seconds) * 1000 + Math.round(ts.nanos / 1e6);
    return new Date(millis).toISOString();
  }

  _clientMSP(ctx) {
    return ctx.clientIdentity.getMSPID();
  }

  /**
   * Authorization. An identity may register or issue only if its certificate
   * carries the attribute role=issuer (set at enrolment time via Fabric CA),
   * or if it belongs to an MSP listed as an issuer org on the ledger config.
   */
  _assertIssuer(ctx) {
    const isIssuer = ctx.clientIdentity.assertAttributeValue('role', 'issuer');
    if (!isIssuer) {
      throw new Error(
        `Unauthorized: client ${this._clientMSP(ctx)} does not hold role=issuer`
      );
    }
  }

  async _get(ctx, key) {
    const bytes = await ctx.stub.getState(key);
    if (!bytes || bytes.length === 0) return null;
    return JSON.parse(bytes.toString());
  }

  async _put(ctx, key, value) {
    await ctx.stub.putState(key, Buffer.from(JSON.stringify(value)));
  }

  _assertHash(value, label) {
    if (typeof value !== 'string' || !/^[a-f0-9]{64}$/i.test(value)) {
      throw new Error(`${label} must be a 64-character hex SHA-256 digest`);
    }
  }

  _assertId(value, label) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_.:-]{4,64}$/.test(value)) {
      throw new Error(`${label} must be 4-64 chars of [A-Za-z0-9_.:-]`);
    }
  }

  // -------------------------------------------------------------- lifecycle

  /**
   * Stage 1 — Registration.
   * Creates the identity record after the issuer has verified the submitted
   * information off-chain. metadataHash commits to that off-chain record.
   */
  async registerIdentity(ctx, identityId, issuerId, metadataHash) {
    this._assertIssuer(ctx);
    this._assertId(identityId, 'identityId');
    this._assertId(issuerId, 'issuerId');
    this._assertHash(metadataHash, 'metadataHash');

    const key = IDENTITY_PREFIX + identityId;
    if (await this._get(ctx, key)) {
      throw new Error(`Identity ${identityId} already exists`);
    }

    const identity = {
      docType: 'identity',
      identityId,
      issuerId,
      issuerMSP: this._clientMSP(ctx),
      metadataHash,
      status: STATUS.ACTIVE,
      createdAt: this._txTime(ctx),
      credentialIds: [],
    };

    await this._put(ctx, key, identity);
    ctx.stub.setEvent('IdentityRegistered', Buffer.from(JSON.stringify({
      identityId, issuerId, createdAt: identity.createdAt,
    })));
    return JSON.stringify(identity);
  }

  async getIdentity(ctx, identityId) {
    const identity = await this._get(ctx, IDENTITY_PREFIX + identityId);
    if (!identity) throw new Error(`Identity ${identityId} not found`);
    return JSON.stringify(identity);
  }

  /**
   * Stage 2 — Issuance.
   * credentialHash is SHA-256 over the canonical off-chain credential body.
   * The body itself goes to the holder's wallet, never to the ledger.
   */
  async issueCredential(ctx, credentialId, holderId, issuerId, credentialType, credentialHash) {
    this._assertIssuer(ctx);
    this._assertId(credentialId, 'credentialId');
    this._assertId(holderId, 'holderId');
    this._assertId(issuerId, 'issuerId');
    this._assertHash(credentialHash, 'credentialHash');

    const identityKey = IDENTITY_PREFIX + holderId;
    const identity = await this._get(ctx, identityKey);
    if (!identity) {
      throw new Error(`Cannot issue: holder identity ${holderId} is not registered`);
    }
    if (identity.status !== STATUS.ACTIVE) {
      throw new Error(`Cannot issue: holder identity ${holderId} is ${identity.status}`);
    }

    const credKey = CREDENTIAL_PREFIX + credentialId;
    if (await this._get(ctx, credKey)) {
      throw new Error(`Credential ${credentialId} already exists`);
    }

    const now = this._txTime(ctx);
    const credential = {
      docType: 'credential',
      credentialId,
      holderId,
      issuerId,
      issuerMSP: this._clientMSP(ctx),
      credentialType,
      credentialHash,
      status: STATUS.ACTIVE,
      issuedAt: now,
      revokedAt: null,
      revocationReason: null,
    };

    await this._put(ctx, credKey, credential);

    identity.credentialIds.push(credentialId);
    await this._put(ctx, identityKey, identity);

    ctx.stub.setEvent('CredentialIssued', Buffer.from(JSON.stringify({
      credentialId, holderId, issuerId, issuedAt: now,
    })));
    return JSON.stringify(credential);
  }

  async getCredential(ctx, credentialId) {
    const credential = await this._get(ctx, CREDENTIAL_PREFIX + credentialId);
    if (!credential) throw new Error(`Credential ${credentialId} not found`);
    return JSON.stringify(credential);
  }

  /**
   * Stage 4 — Verification (ledger-backed).
   * Returns a verdict object rather than throwing, so the verifier UI can
   * distinguish "revoked" from "tampered" from "unknown".
   *
   * Read-only: call this with evaluateTransaction, not submitTransaction.
   */
  async verifyCredential(ctx, credentialId, presentedHash) {
    const credential = await this._get(ctx, CREDENTIAL_PREFIX + credentialId);

    if (!credential) {
      return JSON.stringify({
        result: VERIFY.NOT_FOUND,
        credentialId,
        reason: 'No such credential on the ledger',
        checkedAt: this._txTime(ctx),
      });
    }

    // Constant-time compare so a verifier terminal cannot be used as an oracle
    // to grind out a matching hash byte by byte.
    const a = Buffer.from(String(presentedHash).toLowerCase());
    const b = Buffer.from(String(credential.credentialHash).toLowerCase());
    const hashMatches = a.length === b.length && crypto.timingSafeEqual(a, b);

    if (!hashMatches) {
      return JSON.stringify({
        result: VERIFY.INVALID,
        credentialId,
        reason: 'Presented hash does not match the issued credential',
        checkedAt: this._txTime(ctx),
      });
    }

    if (credential.status === STATUS.REVOKED) {
      return JSON.stringify({
        result: VERIFY.REJECTED,
        credentialId,
        reason: `Credential revoked at ${credential.revokedAt}`,
        revokedAt: credential.revokedAt,
        revocationReason: credential.revocationReason,
        checkedAt: this._txTime(ctx),
      });
    }

    const identity = await this._get(ctx, IDENTITY_PREFIX + credential.holderId);
    if (!identity || identity.status !== STATUS.ACTIVE) {
      return JSON.stringify({
        result: VERIFY.REJECTED,
        credentialId,
        reason: 'Holder identity is no longer active',
        checkedAt: this._txTime(ctx),
      });
    }

    return JSON.stringify({
      result: VERIFY.VALID,
      credentialId,
      holderId: credential.holderId,
      issuerId: credential.issuerId,
      credentialType: credential.credentialType,
      issuedAt: credential.issuedAt,
      checkedAt: this._txTime(ctx),
    });
  }

  /**
   * Stage 5 — Revocation.
   * Only the issuing organisation may revoke its own credential.
   */
  async revokeCredential(ctx, credentialId, reason) {
    this._assertIssuer(ctx);
    const key = CREDENTIAL_PREFIX + credentialId;
    const credential = await this._get(ctx, key);
    if (!credential) throw new Error(`Credential ${credentialId} not found`);

    if (credential.issuerMSP !== this._clientMSP(ctx)) {
      throw new Error(
        `Unauthorized: ${this._clientMSP(ctx)} did not issue credential ${credentialId}`
      );
    }
    if (credential.status === STATUS.REVOKED) {
      throw new Error(`Credential ${credentialId} is already revoked`);
    }

    credential.status = STATUS.REVOKED;
    credential.revokedAt = this._txTime(ctx);
    credential.revocationReason = reason || 'unspecified';

    await this._put(ctx, key, credential);
    ctx.stub.setEvent('CredentialRevoked', Buffer.from(JSON.stringify({
      credentialId, revokedAt: credential.revokedAt, reason: credential.revocationReason,
    })));
    return JSON.stringify(credential);
  }

  // ---------------------------------------------------------- sync + audit

  /**
   * Stage 6 — Synchronisation.
   * A verifier that was offline replays the credential IDs it saw locally and
   * gets back the authoritative ledger status for each, so it can flag any
   * acceptance it made against a credential that had already been revoked.
   */
  async syncStatuses(ctx, credentialIdsJSON) {
    const ids = JSON.parse(credentialIdsJSON);
    if (!Array.isArray(ids)) throw new Error('Expected a JSON array of credential IDs');
    if (ids.length > 100) throw new Error('Sync batch limited to 100 credentials');

    const out = [];
    for (const id of ids) {
      const credential = await this._get(ctx, CREDENTIAL_PREFIX + id);
      out.push(credential
        ? { credentialId: id, status: credential.status, revokedAt: credential.revokedAt }
        : { credentialId: id, status: 'UNKNOWN', revokedAt: null });
    }
    return JSON.stringify({ syncedAt: this._txTime(ctx), statuses: out });
  }

  /** Full tamper-evident history of one credential, straight from the ledger. */
  async getCredentialHistory(ctx, credentialId) {
    const iterator = await ctx.stub.getHistoryForKey(CREDENTIAL_PREFIX + credentialId);
    const history = [];
    let res = await iterator.next();
    while (!res.done) {
      const { txId, timestamp, isDelete, value } = res.value;
      history.push({
        txId,
        timestamp: new Date(Number(timestamp.seconds) * 1000).toISOString(),
        isDelete,
        value: isDelete ? null : JSON.parse(value.toString()),
      });
      res = await iterator.next();
    }
    await iterator.close();
    return JSON.stringify(history);
  }

  async listCredentialsByHolder(ctx, holderId) {
    const identity = await this._get(ctx, IDENTITY_PREFIX + holderId);
    if (!identity) throw new Error(`Identity ${holderId} not found`);
    const creds = [];
    for (const id of identity.credentialIds) {
      const c = await this._get(ctx, CREDENTIAL_PREFIX + id);
      if (c) creds.push(c);
    }
    return JSON.stringify(creds);
  }
}

module.exports = IdentityContract;
module.exports.STATUS = STATUS;
module.exports.VERIFY = VERIFY;
