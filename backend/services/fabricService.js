'use strict';

const grpc = require('@grpc/grpc-js');
const { connect, signers } = require('@hyperledger/fabric-gateway');
const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');
const config = require('../config/fabric.config');

const utf8 = new TextDecoder('utf-8');

let gateway = null;
let client = null;
let contract = null;

/** Reads the single private key file out of an MSP keystore directory. */
async function readPrivateKey(keystoreDir) {
  const files = await fs.readdir(keystoreDir);
  if (files.length === 0) throw new Error(`No private key in ${keystoreDir}`);
  return fs.readFile(path.join(keystoreDir, files[0]));
}

async function newGrpcConnection() {
  const tlsRootCert = await fs.readFile(config.tlsCertPath);
  const credentials = grpc.credentials.createSsl(tlsRootCert);
  return new grpc.Client(config.peerEndpoint, credentials, {
    'grpc.ssl_target_name_override': config.peerHostAlias,
    'grpc.max_receive_message_length': 20 * 1024 * 1024,
  });
}

/** Idempotent: safe to call from every request handler. */async function canConnectToFabric() {
  try {
    await fs.access(config.tlsCertPath);
    await fs.access(config.certPath);
    await fs.access(config.keyDirectoryPath);
    return true;
  } catch {
    return false;
  }
}

async function getContract() {
  if (contract) return contract;

  if (!(await canConnectToFabric())) {
    throw new Error('Fabric identity files not found — skipping Fabric connection');
  }

  client = await newGrpcConnection();

  const certificate = await fs.readFile(config.certPath);
  const privateKeyPem = await readPrivateKey(config.keyDirectoryPath);
  const privateKey = crypto.createPrivateKey(privateKeyPem);

  gateway = connect({
    client,
    identity: { mspId: config.mspId, credentials: certificate },
    signer: signers.newPrivateKeySigner(privateKey),
    // Timeouts keep a stalled peer from hanging the REST API.
    evaluateOptions:      () => ({ deadline: Date.now() + 10_000 }),
    endorseOptions:       () => ({ deadline: Date.now() + 20_000 }),
    submitOptions:        () => ({ deadline: Date.now() + 10_000 }),
    commitStatusOptions:  () => ({ deadline: Date.now() + 60_000 }),
  });

  const network = gateway.getNetwork(config.channelName);
  contract = network.getContract(config.chaincodeName, config.contractName);
  return contract;
}

/**
 * Write path. Goes through proposal -> endorsement -> ordering -> commit and
 * only resolves once the transaction is committed to the ledger.
 * Returns the parsed payload plus the transaction ID and wall-clock latency,
 * which the evaluation table needs.
 */
async function submit(fn, ...args) {
  const c = await getContract();
  const started = process.hrtime.bigint();

  const proposal = c.newProposal(fn, { arguments: args });
  const transaction = await proposal.endorse();
  const commit = await transaction.submit();
  const status = await commit.getStatus();

  const latencyMs = Number(process.hrtime.bigint() - started) / 1e6;

  if (!status.successful) {
    throw new Error(`Transaction ${status.transactionId} failed with code ${status.code}`);
  }

  const raw = utf8.decode(transaction.getResult());
  return {
    payload: raw ? JSON.parse(raw) : null,
    txId: status.transactionId,
    blockNumber: Number(status.blockNumber),
    latencyMs: Number(latencyMs.toFixed(2)),
  };
}

/** Read path. Endorsing peer only, no ordering, no commit. */
async function evaluate(fn, ...args) {
  const c = await getContract();
  const started = process.hrtime.bigint();
  const result = await c.evaluateTransaction(fn, ...args);
  const latencyMs = Number(process.hrtime.bigint() - started) / 1e6;
  const raw = utf8.decode(result);
  return {
    payload: raw ? JSON.parse(raw) : null,
    latencyMs: Number(latencyMs.toFixed(2)),
  };
}

function close() {
  gateway?.close();
  client?.close();
  gateway = client = contract = null;
}

/**
 * Canonical hashing. Both the issuer and the verifier must derive the same
 * digest from the same credential body, so key order is normalised before
 * hashing — JSON.stringify alone is not canonical.
 */
function canonicalHash(obj) {
  const canonical = (v) => {
    if (v === null || typeof v !== 'object') return v;
    if (Array.isArray(v)) return v.map(canonical);
    return Object.keys(v).sort().reduce((acc, k) => {
      acc[k] = canonical(v[k]);
      return acc;
    }, {});
  };
  return crypto.createHash('sha256')
    .update(JSON.stringify(canonical(obj)))
    .digest('hex');
}

module.exports = { getContract, submit, evaluate, close, canonicalHash };
