#!/usr/bin/env bash
# scripts/install-native-deps.sh
# Install the native packages required to build config-sync from source:
#   - every build needs a C toolchain (rustc links via cc)
#   - Linux keyring additionally needs pkg-config + libdbus: keyring's
#     linux-native-sync-persistent backend compiles the libdbus-sys crate
#     (macOS/Windows use their native keychain backends, no libdbus there)
#   - the optional cloud backends additionally need CMake (rustls' aws-lc-sys
#     TLS provider compiles AWS-LC C code)
# No libclang: the dependency tree has no bindgen (the only *bindgen crates
# in Cargo.lock are wasm-bindgen/wit-bindgen, which are pure-Rust and
# wasm-target-only).
# CI calls this script and the README tells users to run it, so the package
# list only ever lives in one place.
set -eu

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

if command -v apt-get >/dev/null 2>&1; then
  as_root apt-get update
  as_root apt-get install -y build-essential cmake pkg-config libdbus-1-dev
elif command -v dnf >/dev/null 2>&1; then
  as_root dnf install -y gcc gcc-c++ make dbus-devel pkgconf-pkg-config cmake
elif command -v yum >/dev/null 2>&1; then
  as_root yum install -y gcc gcc-c++ make dbus-devel pkgconf-pkg-config cmake
elif command -v pacman >/dev/null 2>&1; then
  as_root pacman -S --needed --noconfirm base-devel dbus cmake
elif command -v apk >/dev/null 2>&1; then
  as_root apk add build-base dbus-dev pkgconf cmake
elif command -v zypper >/dev/null 2>&1; then
  as_root zypper install -y gcc gcc-c++ make dbus-1-devel pkg-config cmake
else
  echo "install-native-deps.sh: no supported package manager found (apt/dnf/yum/pacman/apk/zypper)." >&2
  echo "See the README Install section for per-OS prerequisites" >&2
  echo "(macOS, Windows, FreeBSD, and the Linux distributions above)." >&2
  exit 1
fi
