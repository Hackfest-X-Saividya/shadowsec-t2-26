#!/usr/bin/env sh
# Starts the dashboard on the host. Every Simulate Attack / Apply Fix runs in its own throwaway Docker container.
# Usage: ./scripts/run-docker-sandbox.sh [port]
set -eu
cd "$(dirname "$0")/.."
IMAGE="${LD_SANDBOX_IMAGE:-zday-protocol-sandbox:latest}"
command -v docker >/dev/null 2>&1 || { echo "docker not found. Install Docker, then rerun." >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker is installed but the daemon is not reachable. Start Docker and rerun." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 (3.9+) not found." >&2; exit 1; }
echo "Building sandbox image $IMAGE ..."
docker build -q -f Dockerfile.sandbox -t "$IMAGE" .
export LD_SANDBOX=docker LD_SANDBOX_IMAGE="$IMAGE"
exec python3 server.py "$@"
