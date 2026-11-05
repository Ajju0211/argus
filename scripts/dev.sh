#!/usr/bin/env bash
set -e

# Change to project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

echo "=========================================================="
echo "🛡️  Starting ARGUS Autonomous Security Platform (Dev Stack)"
echo "=========================================================="

# Ensure virtualenv exists
if [ ! -f ".venv/bin/uvicorn" ]; then
    echo "❌ Error: .venv/bin/uvicorn not found in $ROOT_DIR"
    exit 1
fi

# Ensure node_modules exist
if [ ! -d "apps/web/node_modules" ]; then
    echo "📦 Installing apps/web npm packages..."
    (cd apps/web && npm install)
fi

# Trap signals for graceful shutdown of both processes
cleanup() {
    echo ""
    echo "🛑 Shutting down ARGUS services..."
    kill $(jobs -p) 2>/dev/null || true
    wait $(jobs -p) 2>/dev/null || true
    echo "✓ All services stopped cleanly."
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 1. Launch FastAPI Backend
echo "🚀 [1/2] Starting FastAPI Backend on http://localhost:8000..."
.venv/bin/uvicorn apps.api.main:app --port 8000 --reload &
API_PID=$!

# Brief pause to let backend bind port
sleep 1.5

# 2. Launch Next.js Frontend
echo "⚡ [2/2] Starting Next.js Cyber Dashboard on http://localhost:3000..."
(cd apps/web && npm run dev) &
WEB_PID=$!

echo ""
echo "=========================================================="
echo "✅ Both services are running:"
echo "   • 🌐 Next.js Dashboard:    http://localhost:3000"
echo "   • 📚 API Swagger Docs:     http://localhost:8000/docs"
echo "   • 🩺 Healthcheck:          http://localhost:8000/healthz"
echo "=========================================================="
echo "Press [Ctrl+C] to stop both services."
echo ""

# Wait for background processes
wait

