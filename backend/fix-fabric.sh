#!/bin/bash
set -e

echo "=== Fixing Fabric peer CouchDB connection ==="

# Stop the peer first
echo "Stopping peer..."
docker stop peer0.org1.example.com 2>/dev/null || true
sleep 2

# The peer config references couchdb0:5984 with password "password"
# but CouchDB has admin:adminpw. We need to fix the peer's environment.
echo "Updating peer environment..."

# Get the container ID
CONTAINER_ID=$(docker ps -aqf "name=peer0.org1.example.com")
if [ -z "$CONTAINER_ID" ]; then
    echo "ERROR: peer0 container not found"
    exit 1
fi

# Stop and remove the peer container
echo "Removing peer container..."
docker rm peer0.org1.example.com 2>/dev/null || true
sleep 2

# Restart peer with correct CouchDB credentials using docker-compose or manual docker run
# First check if docker-compose file exists
COMPOSE_FILE="/Users/sohamk/fabric-samples/test-network/docker/docker-compose-test-net.yaml"
if [ -f "$COMPOSE_FILE" ]; then
    echo "Found docker-compose file: $COMPOSE_FILE"
    cd "/Users/sohamk/fabric-samples/test-network"
    # Start just the peer with corrected env vars
    export CORE_LEDGER_STATE_COUCHDB_USERNAME=admin
    export CORE_LEDGER_STATE_COUCHDB_PASSWORD=adminpw
    docker-compose -f docker/docker-compose-test-net.yaml up -d peer0.org1.example.com
else
    echo "No docker-compose file found, attempting manual restart..."
    # Get the image name from the existing container
    IMAGE=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep hyperledger/fabric-peer | head -1)
    if [ -z "$IMAGE" ]; then
        echo "ERROR: No fabric-peer image found"
        exit 1
    fi

    # Run peer with correct environment
    docker run -d --name peer0.org1.example.com \
        -e CORE_LEDGER_STATE_STATEDATABASE=CouchDB \
        -e CORE_LEDGER_STATE_COUCHDB_ADDRESS=couchdb0:5984 \
        -e CORE_LEDGER_STATE_COUCHDB_USERNAME=admin \
        -e CORE_LEDGER_STATE_COUCHDB_PASSWORD=adminpw \
        -e CORE_PEER_ID=peer0.org1.example.com \
        -e CORE_PEER_ADDRESS=peer0.org1.example.com:7051 \
        -e CORE_PEER_LISTENADDRESS=0.0.0.0:7051 \
        -e CORE_PEER_CHAINCODEADDRESS=peer0.org1.example.com:7052 \
        -e CORE_PEER_CHAINCODELISTENADDRESS=0.0.0.0:7052 \
        -e CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer0.org1.example.com:7051 \
        -e CORE_PEER_GOSSIP_BOOTSTRAP=peer0.org1.example.com:7051 \
        -e CORE_PEER_LOCALMSPID=Org1MSP \
        -e CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/msp \
        -e CORE_PEER_TLS_ENABLED=true \
        -e CORE_PEER_TLS_CERT_FILE=/etc/hyperledger/fabric/msp/signcerts/peer.pem \
        -e CORE_PEER_TLS_KEY_FILE=/etc/hyperledger/fabric/msp/keystore/key.pem \
        -e CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/msp/cacerts/ca.peer.org1.example.com.pem \
        -v "/Users/sohamk/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/":/etc/hyperledger/fabric/msp \
        -v "/Users/sohamk/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/":/var/hyperledger/production \
        -p 7051:7051 -p 7052:7052 -p 7053:7053 \
        $IMAGE peer node start
fi

echo "Waiting for peer to start..."
sleep 10

# Check if peer is running
if docker ps | grep -q "peer0.org1.example.com"; then
    echo "Peer is running"
    docker logs peer0.org1.example.com --tail 20
else
    echo "ERROR: Peer failed to start"
    exit 1
fi
