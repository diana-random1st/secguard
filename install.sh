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

# Download, verify, and extract
ASSET="secguard-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${TAG}/checksums-sha256.txt"
echo "Downloading ${URL}..."

TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT
curl -fL -# -o "${TMP}/${ASSET}" "${URL}"
curl -fL -# -o "${TMP}/checksums-sha256.txt" "${CHECKSUM_URL}"

CHECKSUM_LINE=$(grep "  ${ASSET}$" "${TMP}/checksums-sha256.txt" || true)
if [ -z "${CHECKSUM_LINE}" ]; then
    echo "Checksum manifest does not include ${ASSET}" >&2
    exit 1
fi
printf '%s\n' "${CHECKSUM_LINE}" > "${TMP}/checksums-target.txt"

echo "Verifying SHA-256..."
(
    cd "${TMP}"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c checksums-target.txt
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c checksums-target.txt
    else
        echo "Neither sha256sum nor shasum is available for checksum verification" >&2
        exit 1
    fi
)

tar xzf "${TMP}/${ASSET}" -C "${TMP}"

# Install
if [ -w "${INSTALL_DIR}" ]; then
    mv "${TMP}/secguard" "${INSTALL_DIR}/secguard"
else
    echo "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "${TMP}/secguard" "${INSTALL_DIR}/secguard"
fi

echo "Installed secguard ${TAG} to ${INSTALL_DIR}/secguard"

echo ""
echo "Run 'secguard init --global' to install Claude Code hooks."
echo "Run 'secguard model' to download the ML model (optional, 774MB)."
