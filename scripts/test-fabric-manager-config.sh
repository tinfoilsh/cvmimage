#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

function_source=$(sed -n '/^pin_fabric_manager_config() {$/,/^}$/p' "$repo_root/mkosi.postinst.chroot")
if [[ -z "$function_source" ]]; then
    echo "Fabric Manager config function not found" >&2
    exit 1
fi
eval "$function_source"

config="$scratch/fabricmanager.cfg"
cat >"$config" <<'EOF'
DAEMONIZE=1
FM_CMD_UNIX_SOCKET_PATH=
EOF
pin_fabric_manager_config "$config"
[[ $(grep -Ec '^[[:space:]]*FM_CMD_UNIX_SOCKET_PATH[[:space:]]*=' "$config") -eq 1 ]]
[[ $(grep -Fxc 'FM_CMD_UNIX_SOCKET_PATH=/run/nvidia-fabricmanager/socket' "$config") -eq 1 ]]

for conflicting in 'FM_CMD_UNIX_SOCKET_PATH=/tmp/attacker' ' FM_CMD_UNIX_SOCKET_PATH = /tmp/attacker'; do
    cat >"$config" <<EOF
DAEMONIZE=1
FM_CMD_UNIX_SOCKET_PATH=
$conflicting
EOF
    if pin_fabric_manager_config "$config" >/dev/null 2>&1; then
        echo "duplicate Fabric Manager socket assignment accepted" >&2
        exit 1
    fi
done

mkdir "$scratch/bin"
cat >"$scratch/bin/sed" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
/usr/bin/sed "$@"
config=${!#}
printf '%s\n' 'FM_CMD_UNIX_SOCKET_PATH=/tmp/attacker' >>"$config"
EOF
chmod +x "$scratch/bin/sed"
cat >"$config" <<'EOF'
DAEMONIZE=1
FM_CMD_UNIX_SOCKET_PATH=
EOF
if PATH="$scratch/bin:$PATH" pin_fabric_manager_config "$config" >/dev/null 2>&1; then
    echo "post-rewrite duplicate Fabric Manager socket assignment accepted" >&2
    exit 1
fi
