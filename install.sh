#!/bin/sh
set -e

REPO="diana-random1st/secguard"
INSTALL_DIR="/usr/local/bin"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "${OS}" in
    linux)  TARGET="x86_64-unknown-linux-gnu" ;;
    darwin)
        case "${ARCH}" in
            arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
            x86_64)        TARGET="x86_64-apple-darwin" ;;
            *) echo "Unsupported architecture: ${ARCH}" >&2; exit 1 ;;
        esac
        ;;
    *) echo "Unsupported OS: ${OS}" >&2; exit 1 ;;
esac

echo "Platform: ${TARGET}"

# Get latest release tag
TAG=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)
if [ -z "${TAG}" ]; then
    echo "Failed to determine latest release" >&2
    exit 1
fi
echo "Release: ${TAG}"

# Download and extract
URL="https://github.com/${REPO}/releases/download/${TAG}/secguard-${TARGET}.tar.gz"
echo "Downloading ${URL}..."

TMP=$(mktemp -d)
curl -fL -# -o "${TMP}/secguard.tar.gz" "${URL}"
tar xzf "${TMP}/secguard.tar.gz" -C "${TMP}"

# Install
if [ -w "${INSTALL_DIR}" ]; then
    mv "${TMP}/secguard" "${INSTALL_DIR}/secguard"
else
    echo "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "${TMP}/secguard" "${INSTALL_DIR}/secguard"
fi
rm -rf "${TMP}"

echo "Installed secguard ${TAG} to ${INSTALL_DIR}/secguard"

# Setup
echo ""
echo "Run 'secguard init --global' to install Claude Code hooks."
echo "Run 'secguard model' to download the ML model (optional, 774MB)."
