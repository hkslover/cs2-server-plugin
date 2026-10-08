#!/bin/sh
# Rebuild and run the offline radar-POV resolver validation harness against a
# client.dll file. Usage: tools/run-radar-resolver-check.sh [path-to-client.dll]
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DLL="${1:-$ROOT/dll/client.dll}"

c++ -std=c++17 -O2 -Wall -Wno-ignored-attributes \
    -DRADAR_POV_RESOLVER_STATIC_TEST \
    -I"$ROOT/cs2-server-plugin" \
    -I"$ROOT/cs2-server-plugin/radar_pov" \
    "$ROOT/tools/radar_resolver_static_check.cpp" \
    "$ROOT/cs2-server-plugin/mem_utils.cpp" \
    "$ROOT/cs2-server-plugin/radar_pov/radar_resolver.cpp" \
    -o /tmp/radar_resolver_check

exec /tmp/radar_resolver_check "$DLL"
