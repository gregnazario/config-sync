#!/usr/bin/env bash
# scripts/install-native-deps.sh
# Install the native dependencies required to build config-sync from source
# on Debian/Ubuntu. CI calls this script and the README tells users to run
# it, so the package list only ever lives in one place.
set -eu

if ! command -v apt-get >/dev/null 2>&1; then
  echo "install-native-deps.sh: this helper only supports apt-based systems (Debian/Ubuntu)." >&2
  echo "See the README Install section for macOS and Windows prerequisites." >&2
  exit 1
fi

# Run privileged commands directly as root; otherwise require sudo.
as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    echo "install-native-deps.sh: not running as root and sudo is not installed; re-run as root." >&2
    exit 1
  fi
}

as_root apt-get update
# C toolchain + CMake + pkg-config for the liboqs-based PQ-crypto crates,
# libdbus for the default keyring backend, libclang for bindgen.
as_root apt-get install -y cmake build-essential pkg-config libdbus-1-dev libclang-dev
