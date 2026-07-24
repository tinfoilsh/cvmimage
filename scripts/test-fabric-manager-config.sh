#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
config="$repo_root/image/rootfs/usr/share/nvidia/nvswitch/fabricmanager.cfg"

if [ ! -f "$config" ]; then
    echo "missing measured Fabric Manager config: $config" >&2
    exit 1
fi
if [ "$(grep -Fxc 'DAEMONIZE=1' "$config")" -ne 1 ]; then
    echo "Fabric Manager must daemonize exactly once" >&2
    exit 1
fi
if [ "$(grep -Ec '^[[:space:]]*LOG_FILE_NAME[[:space:]]*=' "$config")" -ne 1 ] ||
    [ "$(grep -Fxc 'LOG_FILE_NAME=/run/nvidia-fabricmanager/fabricmanager.log' "$config")" -ne 1 ]; then
    echo "Fabric Manager must log to its writable runtime directory" >&2
    exit 1
fi
if [ "$(grep -Ec '^[[:space:]]*FM_CMD_UNIX_SOCKET_PATH[[:space:]]*=' "$config")" -ne 1 ] ||
    [ "$(grep -Fxc 'FM_CMD_UNIX_SOCKET_PATH=/run/nvidia-fabricmanager/socket' "$config")" -ne 1 ]; then
    echo "Fabric Manager must use the fixed measured Unix socket" >&2
    exit 1
fi
