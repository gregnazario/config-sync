#!/bin/sh
# scripts/install-native-deps.sh
# POSIX sh (works under busybox ash on stock Alpine — no bash required).
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
# Pass --no-cmake to install only the default-build prerequisites (see README).
set -eu

# --no-cmake: install only what the default build needs (the optional cloud
#   backends will not build until CMake is available).
no_cmake=0
for arg in "$@"; do
  case $arg in
    --no-cmake) no_cmake=1 ;;
    *)
      echo "install-native-deps.sh: unknown option: $arg" >&2
      echo "usage: install-native-deps.sh [--no-cmake]" >&2
      exit 2
      ;;
  esac
done
cmake_pkg=cmake
if [ "$no_cmake" -eq 1 ]; then
  cmake_pkg=""
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

if command -v apt-get >/dev/null 2>&1; then
  as_root apt-get update
  as_root apt-get install -y build-essential pkg-config libdbus-1-dev $cmake_pkg
elif command -v dnf >/dev/null 2>&1; then
  as_root dnf install -y gcc gcc-c++ make dbus-devel pkgconf-pkg-config $cmake_pkg
elif command -v yum >/dev/null 2>&1; then
  # EL7/Amazon Linux 2 name the provider "pkgconfig"; "pkgconf-pkg-config" is EL8+/Fedora only.
  as_root yum install -y gcc gcc-c++ make dbus-devel pkgconfig $cmake_pkg
elif command -v pacman >/dev/null 2>&1; then
  as_root pacman -S --needed --noconfirm base-devel dbus $cmake_pkg
elif command -v apk >/dev/null 2>&1; then
  as_root apk add build-base dbus-dev pkgconf $cmake_pkg
elif command -v zypper >/dev/null 2>&1; then
  as_root zypper install -y gcc gcc-c++ make dbus-1-devel pkg-config $cmake_pkg
else
  echo "install-native-deps.sh: no supported package manager found (apt/dnf/yum/pacman/apk/zypper)." >&2
  echo "See the README Install section for per-OS prerequisites" >&2
  echo "(macOS, Windows, FreeBSD, and the Linux distributions above)." >&2
  exit 1
fi
