#!/bin/sh
# Aether Sniffer — One-line installer
# Usage: curl -sSL https://raw.githubusercontent.com/Fredrickighile/aether-sniffer/main/scripts/install.sh | sh

set -e

REPO="Fredrickighile/aether-sniffer"
BINARY="aether-sniffer"
INSTALL_DIR="/usr/local/bin"

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
PURPLE='\033[0;35m'
GRAY='\033[0;37m'
RESET='\033[0m'
BOLD='\033[1m'

echo ""
echo "  ${PURPLE}${BOLD}AETHER-SNIFFER${RESET} — Installer"
echo "  ${GRAY}──────────────────────────────${RESET}"
echo ""

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  armv7l)  ARCH="arm"   ;;
  *)
    echo "  ${RED}✗ Unsupported architecture: $ARCH${RESET}"
    exit 1
    ;;
esac

case "$OS" in
  linux)  EXT="tar.gz" ;;
  darwin) EXT="tar.gz" ;;
  *)
    echo "  ${RED}✗ Unsupported OS: $OS${RESET}"
    echo "  For Windows, download from:"
    echo "  https://github.com/$REPO/releases/latest"
    exit 1
    ;;
esac

# Get latest version
echo "  ${GRAY}[1/3]${RESET} Fetching latest version ..."
VERSION=$(curl -sSf "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)

if [ -z "$VERSION" ]; then
  echo "  ${RED}✗ Could not fetch latest version. Check your internet connection.${RESET}"
  exit 1
fi

echo "  ${GRAY}[2/3]${RESET} Downloading ${BINARY} ${VERSION} (${OS}/${ARCH}) ..."
URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}_${OS}_${ARCH}.${EXT}"

TMP_DIR=$(mktemp -d)
curl -sSfL "$URL" | tar -xz -C "$TMP_DIR"

if [ ! -f "$TMP_DIR/$BINARY" ]; then
  echo "  ${RED}✗ Binary not found in archive. Please report this issue.${RESET}"
  exit 1
fi

echo "  ${GRAY}[3/3]${RESET} Installing to ${INSTALL_DIR} ..."
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY"
  chmod +x "$INSTALL_DIR/$BINARY"
else
  sudo mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY"
  sudo chmod +x "$INSTALL_DIR/$BINARY"
fi

rm -rf "$TMP_DIR"

echo ""
echo "  ${GRAY}──────────────────────────────${RESET}"
echo "  ${GREEN}✔ Aether Sniffer ${VERSION} installed${RESET}"
echo ""
echo "  ${GRAY}Get started:${RESET}"
echo "  ${PURPLE}\$ aether-sniffer login${RESET}"
echo "  ${PURPLE}\$ aether-sniffer scan /path/to/project --sync${RESET}"
echo ""
