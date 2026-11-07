#!/usr/bin/env bash
# Bring the official, version-pinned ChirpStack stack up or down for the integration test.
# Usage: bash integration/setup_chirpstack.sh [up|down]   (default: up)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CSD="$HERE/.chirpstack-docker"
# chirpstack-docker has no version tags; its compose + configs track the default branch. The ChirpStack
# SERVER version is pinned to 4.19.2 by compose.override.yml, which is what the paper reads.

cmd="${1:-up}"

if [ ! -d "$CSD/.git" ]; then
  echo "Cloning chirpstack/chirpstack-docker into $CSD ..."
  git clone --depth 1 https://github.com/chirpstack/chirpstack-docker "$CSD"
fi
cp "$HERE/compose.override.yml" "$CSD/compose.override.yml"

cd "$CSD"
case "$cmd" in
  up)
    echo "Starting ChirpStack (server image pinned by compose.override.yml) ..."
    docker compose -f docker-compose.yml -f compose.override.yml up -d
    echo
    echo "Endpoints:  gRPC API  localhost:8080   gateway UDP  localhost:1700/udp   MQTT  localhost:1883"
    echo "Wait ~20 s for Postgres migrations, then: python3 integration/provision.py"
    ;;
  down)
    docker compose -f docker-compose.yml -f compose.override.yml down
    ;;
  *)
    echo "Usage: bash integration/setup_chirpstack.sh [up|down]" >&2; exit 2 ;;
esac
