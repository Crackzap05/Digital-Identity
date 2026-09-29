#!/usr/bin/env bash
# Enrols an issuer identity carrying the role=issuer certificate attribute
# that the chaincode's _assertIssuer check requires.
set -euo pipefail

FABRIC_SAMPLES="${FABRIC_SAMPLES:?set FABRIC_SAMPLES to your fabric-samples path}"
export PATH="$FABRIC_SAMPLES/bin:$PATH"
export FABRIC_CA_CLIENT_HOME="$FABRIC_SAMPLES/test-network/organizations/peerOrganizations/org1.example.com"
CA_TLS="$FABRIC_SAMPLES/test-network/organizations/fabric-ca/org1/ca-cert.pem"

fabric-ca-client register \
  --caname ca-org1 \
  --id.name ngoIssuer --id.secret issuerpw --id.type client \
  --id.attrs 'role=issuer:ecert' \
  --tls.certfiles "$CA_TLS"

fabric-ca-client enroll \
  -u https://ngoIssuer:issuerpw@localhost:7054 \
  --caname ca-org1 \
  -M "$FABRIC_CA_CLIENT_HOME/users/ngoIssuer@org1.example.com/msp" \
  --enrollment.attrs "role,hf.Type" \
  --tls.certfiles "$CA_TLS"

cp "$FABRIC_CA_CLIENT_HOME/msp/config.yaml" \
   "$FABRIC_CA_CLIENT_HOME/users/ngoIssuer@org1.example.com/msp/config.yaml"

echo "Issuer enrolled. Point the backend at it:"
echo "  export CERT_PATH=$FABRIC_CA_CLIENT_HOME/users/ngoIssuer@org1.example.com/msp/signcerts/cert.pem"
echo "  export KEY_DIRECTORY_PATH=$FABRIC_CA_CLIENT_HOME/users/ngoIssuer@org1.example.com/msp/keystore"
