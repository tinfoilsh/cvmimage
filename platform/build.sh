#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
python3 validate.py
jq -n --slurpfile measurements hardware-measurements.json --slurpfile machines machines.json --slurpfile policies policies.json '{
  format: "https://tinfoil.sh/predicate/platform-endorsements/v1",
  measurements: $measurements[0],
  machines: $machines[0],
  policies: $policies[0]
}' > platform-endorsements-classic.json

MINIMUM_RUNTIME_ABI_VERSION="1.51"
RUNTIME_PLATFORM_FORMAT="https://tinfoil.sh/predicate/platform-endorsements/v2"
jq --arg format "$RUNTIME_PLATFORM_FORMAT" --arg minimum_abi_version "$MINIMUM_RUNTIME_ABI_VERSION" '
  .format = $format |
  .measurements = {} |
  .policies |= with_entries(
    if .value.platform == "sev-snp" then
      .value.sev_snp |= (
        del(.host_data) |
        .minimum_abi_version = ([.minimum_abi_version, $minimum_abi_version] | max_by(split(".") | map(tonumber)))
      )
    elif .value.platform == "tdx" then
      .value.tdx |= del(.platform_measurements)
    else error("unsupported platform")
    end
  )
' platform-endorsements-classic.json > platform-endorsements.json
