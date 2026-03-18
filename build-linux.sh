#!/usr/bin/env bash
#
# build-linux.sh — Cross-compile hedonistic-keygen for Linux x86_64
#
# Options:
#   1. Docker (if available) — builds inside Alpine container, fully static musl binary
#   2. cargo-zigbuild (if zig installed) — uses Zig as linker
#   3. Native (if on Linux already) — just cargo build
#
# Output: target/x86_64-unknown-linux-musl/release/hedonistic-keygen
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARGET="x86_64-unknown-linux-musl"
BINARY="target/${TARGET}/release/hedonistic-keygen"

echo "=== Building hedonistic-keygen for Linux x86_64 ==="

# Option 1: Docker
if command -v docker &>/dev/null; then
    echo "Using Docker (Alpine + musl, fully static binary)..."

    docker run --rm \
        -v "$SCRIPT_DIR":/src \
        -w /src \
        rust:alpine \
        sh -c "
            apk add --no-cache musl-dev openssl perl make &&
            rustup target add x86_64-unknown-linux-musl &&
            cargo build --release --target x86_64-unknown-linux-musl
        "

    if [[ -f "$BINARY" ]]; then
        echo ""
        echo "SUCCESS: $BINARY"
        ls -lh "$BINARY"
        file "$BINARY"
        echo ""
        echo "This is a fully static binary. Copy it to a USB drive:"
        echo "  cp $BINARY /Volumes/YOUR_USB/hedonistic-keygen"
        exit 0
    fi
fi

# Option 2: Zig linker
if command -v zig &>/dev/null && command -v cargo-zigbuild &>/dev/null; then
    echo "Using cargo-zigbuild..."
    cargo zigbuild --release --target "$TARGET"

    if [[ -f "$BINARY" ]]; then
        echo ""
        echo "SUCCESS: $BINARY"
        ls -lh "$BINARY"
        exit 0
    fi
fi

# Option 3: Native Linux
if [[ "$(uname -s)" == "Linux" ]]; then
    echo "Building natively on Linux..."
    rustup target add "$TARGET" 2>/dev/null || true
    cargo build --release --target "$TARGET"

    if [[ -f "$BINARY" ]]; then
        echo ""
        echo "SUCCESS: $BINARY"
        ls -lh "$BINARY"
        exit 0
    fi
fi

# Fallback instructions
echo ""
echo "ERROR: No cross-compilation method available."
echo ""
echo "Options to build for Linux x86_64:"
echo ""
echo "  A) Install Docker Desktop, then re-run this script"
echo "     brew install --cask docker"
echo ""
echo "  B) Install Zig + cargo-zigbuild:"
echo "     brew install zig"
echo "     cargo install cargo-zigbuild"
echo "     Then re-run this script"
echo ""
echo "  C) Build on the airgapped Linux machine itself:"
echo "     1. Copy this entire keygen/ directory to a USB"
echo "     2. On the Linux machine:"
echo "        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
echo "        cd /path/to/keygen"
echo "        cargo build --release"
echo "        # Binary at: target/release/hedonistic-keygen"
echo ""
echo "  D) Use a CI/CD pipeline to build the Linux binary"
echo ""
exit 1
