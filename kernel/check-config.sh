#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 /path/to/resolved.config /path/to/policy.config [...]" >&2
    exit 2
fi

resolved_config=$1
shift
if [ ! -f "$resolved_config" ]; then
    echo "missing resolved kernel config: $resolved_config" >&2
    exit 2
fi

failures=0
checks=0

valid_config_key() {
    [[ "$1" =~ ^CONFIG_[A-Za-z0-9_]+$ ]]
}

actual_setting() {
    local key=$1
    local actual
    actual="$(grep -Em1 "^${key}=|^# ${key} is not set$" "$resolved_config" || true)"
    printf '%s\n' "${actual:-<absent>}"
}

fail_setting() {
    local policy=$1
    local line_number=$2
    local expected=$3
    local key=$4
    printf 'FAIL: %s:%d requested %s; resolved %s\n' \
        "$policy" "$line_number" "$expected" "$(actual_setting "$key")" >&2
    failures=$((failures + 1))
}

for policy in "$@"; do
    if [ ! -f "$policy" ]; then
        echo "missing kernel policy fragment: $policy" >&2
        exit 2
    fi

    line_number=0
    while IFS= read -r line || [ -n "$line" ]; do
        line_number=$((line_number + 1))
        case "$line" in
            CONFIG_*=*)
                key=${line%%=*}
                if ! valid_config_key "$key"; then
                    fail_setting "$policy" "$line_number" "$line" "$key"
                    continue
                fi
                checks=$((checks + 1))
                if ! grep -Fqx -- "$line" "$resolved_config"; then
                    fail_setting "$policy" "$line_number" "$line" "$key"
                fi
                ;;
            "# CONFIG_"*" is not set")
                key=${line#\# }
                key=${key% is not set}
                if ! valid_config_key "$key"; then
                    fail_setting "$policy" "$line_number" "$line" "$key"
                    continue
                fi
                checks=$((checks + 1))
                if grep -Eq "^${key}=" "$resolved_config"; then
                    fail_setting "$policy" "$line_number" "$line" "$key"
                fi
                ;;
            "# CONFIG_"*)
                printf 'FAIL: malformed disabled-symbol policy at %s:%d: %s\n' \
                    "$policy" "$line_number" "$line" >&2
                failures=$((failures + 1))
                ;;
            ""|\#*)
                ;;
            *)
                printf 'FAIL: unsupported policy syntax at %s:%d: %s\n' \
                    "$policy" "$line_number" "$line" >&2
                failures=$((failures + 1))
                ;;
        esac
    done < "$policy"
done

modules="$(grep -E '^CONFIG_[A-Za-z0-9_]+=m$' "$resolved_config" || true)"
if [ -n "$modules" ]; then
    echo "FAIL: in-tree modules remain configured:" >&2
    printf '%s\n' "$modules" >&2
    failures=$((failures + 1))
fi

if [ "$checks" -eq 0 ]; then
    echo "kernel config check found no policy settings" >&2
    exit 2
fi
if [ "$failures" -ne 0 ]; then
    echo "kernel config check failed with $failures issue(s)" >&2
    exit 1
fi

echo "kernel config check passed: $checks policy settings, no in-tree modules"
