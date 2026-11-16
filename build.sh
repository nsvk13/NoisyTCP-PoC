#!/usr/bin/env bash
# Build helper. Uses the system compiler if present, otherwise falls back to
# nix-shell (NixOS). Produces ./noisytcp.
set -euo pipefail
cd "$(dirname "$0")"

if command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1; then
    make
elif command -v nix-shell >/dev/null 2>&1; then
    echo "[*] no system compiler; building via nix-shell -p gcc gnumake"
    nix-shell -p gcc gnumake --run "make"
else
    echo "error: need gcc/cc or nix-shell to build" >&2
    exit 1
fi

echo "[*] built ./noisytcp"
./noisytcp --selftest
