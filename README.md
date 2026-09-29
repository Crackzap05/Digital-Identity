# Blockchain-Based Digital Identity for the Unbanked & Refugees

Prototype implementation of a permissioned digital-identity workflow on Hyperledger Fabric 2.x. Covers the six lifecycle stages from the methodology: registration, issuance, presentation, verification, revocation and synchronisation.

Team: Soham (25BCE5558), Rahul (25BCE5687) — VIT Chennai. Guide: Saranya M.

## Architecture

```
Browser UI  ──HTTP/JSON──>  Express API  ──gRPC/TLS──>  Fabric Gateway
(frontend/)                 (backend/)                  (peer0.org1)
                                 │                            │
                          off-chain wallet            chaincode: IdentityContract
                          (personal data)             ledger: hashes + status only
```

The user-facing layer is deliberately separate from the trust layer, so the UI and the chaincode can be tested independently before the integrated workflow is demonstrated.

## On-chain vs off-chain

The ledger is immutable, so anything written to it is permanently disclosed to every organisation on the channel. Only non-identifying commitments go on-chain.

| Data | Location | Reason |
|---|---|---|
| `identityId`, `issuerId`, `issuerMSP` | On-chain | Needed for authorisation and audit |
| `metadataHash`, `credentialHash` (SHA-256) | On-chain | Tamper evidence without disclosure |
| `status`, `createdAt`, `issuedAt`, `revokedAt` | On-chain | Revocation must be globally visible |
| Name, date of birth, registration site | Off-chain (`backend/data/wallet.json`) | Personally identifying |
| Credential claim body | Off-chain wallet | Only its digest is committed |
| Issuer Ed25519 private key | `backend/config/keys/`, mode 0600 | Never leaves the issuer |
| Fabric private key | MSP keystore, server-side only | Never reaches the browser |

The QR payload carries `cid`, `iss`, a pseudonymous `sub` reference, `typ`, `h`, `iat`, `exp` and a nonce — no name, no photograph, no document number.

## Prerequisites

Docker and Docker Compose, Node.js 18+, Go 1.20+, jq, and `fabric-samples` cloned alongside this repository:

```bash
curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh
chmod +x install-fabric.sh && ./install-fabric.sh docker samples binary
```

## Setup

```bash
# 1. Network up, channel created, chaincode installed + committed
./network/scripts/deploy.sh

# 2. Enrol an identity carrying the role=issuer certificate attribute
export FABRIC_SAMPLES=../fabric-samples
./network/scripts/seed-identities.sh
# then export the CERT_PATH / KEY_DIRECTORY_PATH it prints

# 3. API + UI
cd backend && npm install && npm start
# open http://localhost:3000

# 4. Test suite
node tests/e2e.test.js
```

## Chaincode functions

| Function | Type | Authorisation | Behaviour |
|---|---|---|---|
| `registerIdentity(identityId, issuerId, metadataHash)` | submit | `role=issuer` | Creates identity; rejects duplicates |
| `getIdentity(identityId)` | evaluate | any member | Reads current identity state |
| `issueCredential(credentialId, holderId, issuerId, type, hash)` | submit | `role=issuer` | Requires an ACTIVE holder identity; sets status ACTIVE |
| `getCredential(credentialId)` | evaluate | any member | Reads credential state |
| `verifyCredential(credentialId, presentedHash)` | evaluate | any member | Returns VALID / REJECTED / INVALID / NOT_FOUND |
| `revokeCredential(credentialId, reason)` | submit | issuing MSP only | Sets status REVOKED |
| `syncStatuses(credentialIdsJSON)` | evaluate | any member | Batch status lookup, max 100 |
| `getCredentialHistory(credentialId)` | evaluate | any member | Full transaction history for the key |
| `listCredentialsByHolder(holderId)` | evaluate | any member | Credentials linked to an identity |

Endorsement policy: `OR('Org1MSP.peer','Org2MSP.peer')` for the prototype. Tighten to `AND(...)` to require both institutions to endorse a write.

## REST API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/login` | — | Issue a session token |
| POST | `/api/identity` | issuer, admin | Register an identity |
| GET | `/api/identity/:id` | — | Read identity |
| GET | `/api/identity/:id/credentials` | — | List credentials for a holder |
| POST | `/api/credential` | issuer, admin | Issue a credential, return QR token |
| GET | `/api/credential/:id` | — | Read credential |
| GET | `/api/credential/:id/history` | — | Ledger history of the key |
| POST | `/api/credential/:id/present` | — | Mint a fresh 5-minute QR token |
| POST | `/api/credential/:id/revoke` | issuer, admin | Revoke |
| POST | `/api/verify` | — | Local + ledger verification |
| POST | `/api/sync` | — | Reconcile offline acceptances |
| GET | `/api/metrics` | — | Latency and transaction counts |
| GET | `/api/health` | — | Fabric connectivity probe |

## The two verification stages

The report must not conflate these:

- **Local (offline).** Ed25519 signature over the canonical QR payload, checked against the issuer's known public key, plus an expiry window. Proves the credential was issued by that issuer and has not been altered. **Cannot detect revocation.** Reported as `UNCONFIRMED`.
- **Ledger (online).** Fabric confirms the credential exists, the presented hash matches the issued one, and the status is still ACTIVE. Only this catches a revocation. Reported as `VALID` / `REJECTED` / `INVALID` / `NOT_FOUND`.

The `/api/verify` response always returns both stages separately, and the UI renders them as separate lines.

## Security measures implemented

- Role-based authorisation at two independent layers: an HMAC bearer token at the API, and the `role=issuer` certificate attribute enforced inside chaincode. A forged API token still cannot write to the ledger.
- Revocation restricted to the issuing MSP — one NGO cannot revoke another's credentials.
- Input validation on every field: ID charset and length, 64-hex digest format, JSON shape, 100-item sync cap, 256 KB body limit.
- Constant-time hash comparison in `verifyCredential`, so a verifier terminal cannot be used as an oracle.
- Deterministic timestamps from `getTxTimestamp()` rather than `Date.now()`, which would break endorsement across peers.
- Short-lived presentation tokens with a nonce, limiting replay of a captured QR code.
- No Fabric or issuer private key material in frontend code.

## Evidence checklist for review

1. `docker ps` showing peers, orderer, CAs and CouchDB
2. `peer lifecycle chaincode querycommitted` output
3. Chaincode source (`chaincode/identity/src/identityContract.js`)
4. UI: identity registered, with the returned transaction ID and block number
5. UI: credential issued, QR rendered
6. UI: verification returning VALID, both stages shown
7. UI: revocation confirmed
8. UI: same QR re-verified, now REJECTED
9. Offline check showing UNCONFIRMED, then sync flagging the stale acceptance
10. Audit tab: credential history and `/api/metrics` output
11. `node tests/e2e.test.js` markdown results table

## Known limits

- Single-machine prototype; the holder wallet is a server-side JSON file rather than a real device wallet.
- Presentation nonces are not yet tracked server-side, so replay within the 5-minute window is not blocked.
- Selective disclosure is not implemented — the credential is hashed whole, so a holder cannot reveal one claim in isolation. Zero-knowledge or BBS+ signatures would be the next step.
- `syncStatuses` iterates keys individually; a production version would use a CouchDB rich query.
