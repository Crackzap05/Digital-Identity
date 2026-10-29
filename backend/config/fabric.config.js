'use strict';

const path = require('path');

const CRYPTO_ROOT = process.env.CRYPTO_PATH || path.join(
  process.env.HOME,
  'fabric-samples',
  'test-network',
  'organizations',
  'peerOrganizations',
  'org1.example.com'
);

const ISSUER = process.env.FABRIC_IDENTITY || 'ngoIssuer@org1.example.com';

module.exports = {
  channelName: process.env.CHANNEL_NAME || 'mychannel',
  chaincodeName: process.env.CHAINCODE_NAME || 'identity',
  contractName: process.env.CONTRACT_NAME || 'IdentityContract',
  mspId: process.env.MSP_ID || 'Org1MSP',

  keyDirectoryPath: process.env.KEY_DIRECTORY_PATH ||
    path.join(CRYPTO_ROOT, 'users', ISSUER, 'msp', 'keystore'),

  certPath: process.env.CERT_PATH ||
    path.join(CRYPTO_ROOT, 'users', ISSUER, 'msp', 'signcerts', 'cert.pem'),

  tlsCertPath: process.env.TLS_CERT_PATH ||
    path.join(CRYPTO_ROOT, 'peers', 'peer0.org1.example.com', 'tls', 'ca.crt'),

  peerEndpoint: process.env.PEER_ENDPOINT || 'localhost:7051',
  peerHostAlias: process.env.PEER_HOST_ALIAS || 'peer0.org1.example.com',
};
