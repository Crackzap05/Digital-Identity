#!/usr/bin/env bash
# Brings up a two-org Fabric network and deploys the identity chaincode.
# Requires: Docker, Go, jq, and fabric-samples cloned as a sibling of this repo.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$HERE/../.." && pwd)"
FABRIC_SAMPLES="$HOME/fabric-samples"
CHANNEL="${CHANNEL_NAME:-mychannel}"
CC_NAME="${CHAINCODE_NAME:-identity}"
CC_PATH="$PROJECT_ROOT/chaincode/identity"

if [ ! -d "$FABRIC_SAMPLES/test-network" ]; then
  echo "fabric-samples not found at $FABRIC_SAMPLES"
  echo "Clone it first:"
  echo "  curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh"
  echo "  chmod +x install-fabric.sh && ./install-fabric.sh docker samples binary"
  exit 1
fi

echo "==> Installing chaincode dependencies"
(cd "$CC_PATH" && npm install --omit=dev)

cd "$FABRIC_SAMPLES/test-network"

echo "==> Tearing down any previous network"
./network.sh down

echo "==> Starting network with CouchDB and creating channel '$CHANNEL'"
# CouchDB is required for rich queries and gives readable state during the demo.
./network.sh up createChannel -c "$CHANNEL" -ca -s couchdb

echo "==> Packaging, installing, approving and committing chaincode"
./network.sh deployCC \
  -c "$CHANNEL" \
  -ccn "$CC_NAME" \
  -ccp "$CC_PATH" \
  -ccl javascript \
  -ccv 1.0 \
  -ccs 1 \
  -ccep "OR('Org1MSP.peer','Org2MSP.peer')"

echo
echo "==> Committed chaincode on the channel:"
export PATH="$FABRIC_SAMPLES/bin:$PATH"
export FABRIC_CFG_PATH="$FABRIC_SAMPLES/config"
source ./scripts/envVar.sh
setGlobals 1
peer lifecycle chaincode querycommitted --channelID "$CHANNEL" --name "$CC_NAME"

echo
echo "==> Organisations and peers now running:"
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep -E 'peer|orderer|ca_|couchdb' || true

echo
echo "Network is up. Start the API with:  cd $PROJECT_ROOT/backend && npm start"
