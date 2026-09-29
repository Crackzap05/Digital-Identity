'use strict';
const path = require('path');

/**
 * Defaults point at the standard fabric-samples test-network layout
 * (Org1, mychannel). Override any of these with environment variables.
 */
const CRYPTO_ROOT = process.env.CRYPTO_PATH || path.resolve(
  __dirname, '..', '..', '..', 'fabric-samples', 'test-network',
  'organizations', 'peerOrganizations', 'org1.example.com'
);

module.exports = {
  channelName:   process.env.CHANNEL_NAME   || 'mychannel',
  chaincodeName: process.env.CHAINCODE_NAME || 'identity',
  contractName:  process.env.CONTRACT_NAME  || 'IdentityContract',
  mspId:         process.env.MSP_ID         || 'Org1MSP',

  // Signing identity used by the backend when it invokes chaincode.
  keyDirectoryPath: process.env.KEY_DIRECTORY_PATH ||
    path.join(CRYPTO_ROOT, 'users', 'User1@org1.example.com', 'msp', 'keystore'),
  certPath: process.env.CERT_PATH ||
    path.join(CRYPTO_ROOT, 'users', 'User1@org1.example.com', 'msp', 'signcerts', 'cert.pem'),

  // TLS material for the gRPC channel to the gateway peer.
  tlsCertPath: process.env.TLS_CERT_PATH ||
    path.join(CRYPTO_ROOT, 'peers', 'peer0.org1.example.com', 'tls', 'ca.crt'),
  peerEndpoint:  process.env.PEER_ENDPOINT   || 'localhost:7051',
  peerHostAlias: process.env.PEER_HOST_ALIAS || 'peer0.org1.example.com',
};
