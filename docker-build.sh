#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="rustpack"

# Build the Docker image if it doesn't exist or --rebuild is passed
if [[ "$1" == "--rebuild" ]]; then
    shift
    echo "[*] Rebuilding Docker image..."
    docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"
elif ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "[*] Docker image not found, building..."
    docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"
fi

if [[ $# -eq 0 ]]; then
    echo "Usage: ./docker-build.sh [--rebuild] <rustpack args...>"
    echo ""
    echo "Examples:"
    echo "  ./docker-build.sh --file /data/beacon.bin --output /data/packed.exe -a --environmentalhost DC01"
    echo "  ./docker-build.sh --rebuild --file /data/beacon.bin --output /data/packed.exe -a --environmentalhost DC01"
    echo ""
    echo "Your current directory is mounted as /data inside the container."
    echo "All --file and --output paths should use /data/ prefix."
    exit 1
fi

# Run rustpack in container
# Mount current directory as /data for input/output files
docker run --rm -i \
    -v "$(pwd):/data" \
    "$IMAGE_NAME" \
    "$@"
