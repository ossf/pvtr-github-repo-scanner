#!/bin/sh

# This script is used in the ci.yaml workflow
# but can also be used locally to test the
# plugin against a real GitHub repository.
# Change lines 100-103 to test against a different repository.

set -x

STATUS=0

# Require gh CLI to be installed
if ! command -v gh >/dev/null 2>&1; then
  echo "ERROR: gh CLI is not installed"
  echo "Install it from https://cli.github.com/"
  exit 1
fi

# Require GITHUB_TOKEN to be set
if [ -z "$GITHUB_TOKEN" ]; then
  echo "ERROR: GITHUB_TOKEN environment variable is not set"
  echo "You can do the following to set it:"
  echo "  \`gh auth login\` and follow the prompts to authenticate with GitHub"
  echo "  export GITHUB_TOKEN=\$(gh auth token)"
  exit 1
fi

# Require plugin binary to be present in the current directory
if [ ! -f "./github-repo" ]; then
  echo "ERROR: github-repo binary is not present in the current directory"
  echo "You can do the following to build it:"
  echo "  make -B build"
  exit 1
fi

# Detect OS and architecture
OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
  Linux)  RELEASE_OS="Linux" ;;
  Darwin) RELEASE_OS="Darwin" ;;
  *)
    echo "ERROR: Unsupported OS: $OS"
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64)  RELEASE_ARCH="x86_64" ;;
  aarch64) RELEASE_ARCH="arm64" ;;
  arm64)   RELEASE_ARCH="arm64" ;;
  i386)    RELEASE_ARCH="i386" ;;
  i686)    RELEASE_ARCH="i386" ;;
  *)
    echo "ERROR: Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

# Darwin releases use "all" for architecture
if [ "$RELEASE_OS" = "Darwin" ]; then
  RELEASE_ARCH="all"
fi

ASSET_PATTERN="privateer_${RELEASE_OS}_${RELEASE_ARCH}.tar.gz"
PLUGIN_DIR="./tmp/plugins"
CONFIG_FILE="./tmp/test_config.yml"

# Ensure cleanup happens even on unexpected exits or signals
trap 'rm -rf "./tmp"' EXIT

# Set up plugin directory and copy the built plugin binary
mkdir -p "$PLUGIN_DIR"
cp github-repo "$PLUGIN_DIR/" || { echo "ERROR: Failed to copy plugin binary"; exit 1; }

# Download latest pvtr release
gh release download \
  --repo privateerproj/privateer \
  --pattern "$ASSET_PATTERN" \
  --dir /tmp \
  --clobber || { echo "ERROR: Failed to download pvtr release"; exit 1; }

tar xzf "/tmp/$ASSET_PATTERN" -C "./tmp" || { echo "ERROR: Failed to extract plugin"; exit 1; }

# Generate config for testing against the repo
cat > "$CONFIG_FILE" <<EOF
loglevel: trace
write-directory: evaluation_results
write: true
output: yaml
services:
  privateer:
    plugin: github-repo
    policy:
      catalogs:
        - osps-baseline
      applicability:
        - Maturity Level 1
    vars:
      owner: ossf
      repo: pvtr-github-repo-scanner
      token: ${GITHUB_TOKEN}
EOF

# Run pvtr with the plugin
./tmp/pvtr run -b "$PLUGIN_DIR" -c "$CONFIG_FILE" || STATUS=1

exit $STATUS
