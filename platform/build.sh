#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
python3 validate.py
jq -n --slurpfile machines machines.json --slurpfile policies policies.json '{
  format: "https://tinfoil.sh/predicate/platform-endorsements/v2",
  measurements: {},
  machines: $machines[0],
  policies: $policies[0]
}' > platform-endorsements.json
