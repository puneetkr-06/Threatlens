#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Ensure venv exists
if [ -d "venv" ]; then
    source venv/bin/activate
elif [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Ensure .env exists
if [ ! -f ".env" ]; then
    echo "[!] .env not found. Creating from .env.example..."
    cp .env.example .env
    echo "[!] Please configure your API keys in .env"
fi

COMMAND=${1:-start}

case "$COMMAND" in
    init)
        echo "[+] Initializing Pinecone index and seeding signatures..."
        python scripts/init_vector_db.py
        ;;
    mock)
        echo "[+] Starting Protected Upstream Server on port 9000..."
        python tests/mock_upstream.py
        ;;
    waf)
        echo "[+] Starting Semantic WAF Reverse Proxy on port 8000..."
        python main.py
        ;;
    test)
        echo "[+] Running WAF automated security test suite..."
        python tests/test_waf_suite.py
        ;;
    start)
        echo "[+] Starting Protected Upstream Server in background (Port 9000)..."
        python tests/mock_upstream.py > upstream.log 2>&1 &
        UPSTREAM_PID=$!
        echo "[+] Upstream started with PID: $UPSTREAM_PID"

        trap "echo '[*] Stopping services...'; kill $UPSTREAM_PID 2>/dev/null || true; exit 0" INT TERM EXIT

        echo "[+] Starting Semantic WAF Reverse Proxy (Port 8000)..."
        python main.py
        ;;
    *)
        echo "Usage: ./run.sh {init|mock|waf|test|start}"
        exit 1
        ;;
esac
