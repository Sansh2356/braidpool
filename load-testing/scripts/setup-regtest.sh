#!/usr/bin/env bash
# Setup regtest environment for stratum load testing
# Starts bitcoind in regtest mode, generates initial blocks, starts braidpool node
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOAD_TEST_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configuration — override via environment variables
BITCOIN_DATADIR="${BITCOIN_DATADIR:-/tmp/braidpool-loadtest-bitcoin}"
IPC_SOCKET="${IPC_SOCKET:-/tmp/bitcoin-loadtest-regtest.sock}"
RPC_USER="${RPC_USER:-loadtest}"
RPC_PASS="${RPC_PASS:-loadtest}"
RPC_PORT="${BITCOIN_RPC_PORT:-18443}"
STRATUM_PORT="${STRATUM_PORT:-3333}"
BRAIDPOOL_RPC_PORT="${BRAIDPOOL_RPC_PORT:-6682}"
NETWORK="${NETWORK:-regtest}"
PIDFILE_DIR="${LOAD_TEST_DIR}/.pids"

mkdir -p "$PIDFILE_DIR"
mkdir -p "$BITCOIN_DATADIR"

echo "=== Braidpool Load Test Environment Setup ==="
echo "Bitcoin datadir:  $BITCOIN_DATADIR"
echo "IPC socket:       $IPC_SOCKET"
echo "Network:          $NETWORK"
echo "Stratum port:     $STRATUM_PORT"
echo ""

# ── Step 1: Start bitcoind ────────────────────────────────────────────────────
echo "[1/6] Starting bitcoind in regtest mode..."

# Clean up stale socket if present
rm -f "$IPC_SOCKET"

bitcoind \
    -regtest \
    -server \
    -daemon \
    -datadir="$BITCOIN_DATADIR" \
    -rpcuser="$RPC_USER" \
    -rpcpassword="$RPC_PASS" \
    -rpcport="$RPC_PORT" \
    -rpcallowip=0.0.0.0/0 \
    -fallbackfee=0.0001 \
    -ipcbind="unix://$IPC_SOCKET" \
    -txindex=1

echo "  bitcoind started (datadir: $BITCOIN_DATADIR)"

# ── Step 2: Wait for bitcoind to be ready ─────────────────────────────────────
echo "[2/6] Waiting for bitcoind RPC to be ready..."

MAX_WAIT=60
WAITED=0
while ! bitcoin-cli -regtest -datadir="$BITCOIN_DATADIR" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" -rpcport="$RPC_PORT" getblockchaininfo &>/dev/null; do
    sleep 1
    WAITED=$((WAITED + 1))
    if [ "$WAITED" -ge "$MAX_WAIT" ]; then
        echo "  ERROR: bitcoind did not become ready within ${MAX_WAIT}s"
        exit 1
    fi
done
echo "  bitcoind ready (waited ${WAITED}s)"

# ── Step 3: Create wallet and generate initial blocks ─────────────────────────
echo "[3/6] Creating wallet and generating initial blocks..."

# Create wallet (ignore error if already exists)
bitcoin-cli -regtest -datadir="$BITCOIN_DATADIR" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" -rpcport="$RPC_PORT" \
    createwallet "loadtest" 2>/dev/null || true

# Get a new address for mining rewards
MINING_ADDRESS=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATADIR" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" -rpcport="$RPC_PORT" \
    getnewaddress "" "bech32")

# Generate 101 blocks to have mature coinbase
bitcoin-cli -regtest -datadir="$BITCOIN_DATADIR" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" -rpcport="$RPC_PORT" \
    generatetoaddress 101 "$MINING_ADDRESS" > /dev/null

BLOCK_COUNT=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATADIR" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" -rpcport="$RPC_PORT" \
    getblockcount)
echo "  Wallet created, ${BLOCK_COUNT} blocks generated"
echo "  Mining address: $MINING_ADDRESS"

# Save mining address for generate-blocks.sh
echo "$MINING_ADDRESS" > "$PIDFILE_DIR/mining-address.txt"

# ── Step 4: Start braidpool node ──────────────────────────────────────────────
echo "[4/6] Starting braidpool node..."

BRAIDPOOL_BIN="$PROJECT_ROOT/target/release/braidpool-node"
if [ ! -f "$BRAIDPOOL_BIN" ]; then
    BRAIDPOOL_BIN="$PROJECT_ROOT/target/debug/braidpool-node"
fi
if [ ! -f "$BRAIDPOOL_BIN" ]; then
    echo "  ERROR: braidpool-node binary not found. Run 'cargo build --release' from node/"
    exit 1
fi

BRAIDPOOL_LOG="$LOAD_TEST_DIR/reports/braidpool-node.log"
"$BRAIDPOOL_BIN" \
    --ipc-socket "$IPC_SOCKET" \
    --network "$NETWORK" \
    --rpcuser "$RPC_USER" \
    --rpcpass "$RPC_PASS" \
    --rpcport "$RPC_PORT" \
    > "$BRAIDPOOL_LOG" 2>&1 &

BRAIDPOOL_PID=$!
echo "$BRAIDPOOL_PID" > "$PIDFILE_DIR/braidpool.pid"
echo "  braidpool-node started (PID: $BRAIDPOOL_PID, log: $BRAIDPOOL_LOG)"

# ── Step 5: Wait for stratum server ──────────────────────────────────────────
echo "[5/6] Waiting for stratum server on port $STRATUM_PORT..."

MAX_WAIT=30
WAITED=0
while ! nc -z localhost "$STRATUM_PORT" 2>/dev/null; do
    sleep 1
    WAITED=$((WAITED + 1))
    if [ "$WAITED" -ge "$MAX_WAIT" ]; then
        echo "  ERROR: Stratum server did not start within ${MAX_WAIT}s"
        echo "  Check log: $BRAIDPOOL_LOG"
        exit 1
    fi
done
echo "  Stratum server ready on port $STRATUM_PORT (waited ${WAITED}s)"

# ── Step 6: Start background block generation ─────────────────────────────────
echo "[6/6] Starting background block generation..."

"$SCRIPT_DIR/generate-blocks.sh" &
GEN_PID=$!
echo "$GEN_PID" > "$PIDFILE_DIR/generate-blocks.pid"
echo "  Block generator started (PID: $GEN_PID)"

echo ""
echo "=== Setup Complete ==="
echo "  Stratum server:   localhost:$STRATUM_PORT"
echo "  Braidpool RPC:    localhost:$BRAIDPOOL_RPC_PORT"
echo "  Bitcoin RPC:      localhost:$RPC_PORT"
echo "  PIDs stored in:   $PIDFILE_DIR/"
echo ""
echo "Run JMeter tests now, then ./scripts/teardown.sh when done."
