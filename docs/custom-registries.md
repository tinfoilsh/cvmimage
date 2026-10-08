# Custom registry credentials

Harbor and other custom registries use standard Docker registry authentication.
The operator supplies one reserved `CUSTOM_REGISTRY_AUTH` secret in external
configuration. Its value is a JSON object with exactly three fields:

```json
{"host":"harbor.my-company.com","username":"robot$project+puller","token":"example-token"}
```

The hostname is data, not part of a secret name. Hyphens are preserved, and
`harbor.my-company.com` and `harbor.my.company.com` identify different registries.
Usernames and tokens are preserved verbatim, including Harbor's `robot$...+...`
account names. The host must be a lowercase DNS hostname without a scheme,
port, path, or IP literal. Hostnames are limited to 253 bytes, usernames to 1024
bytes, and tokens to 16 KiB. Empty credentials, control characters, and colons
in usernames are rejected. The JSON value is bounded at 64 KiB.

Boot validates the entire object and writes the exact-host credential to the
private Docker config (`private/docker-config/config.json`, mode 0600). The
container manager uses its existing Docker credential lookup; no Harbor-specific
pull client or token broker is involved. Credential files are not mounted into
ordinary workloads. Use digest-pinned images to select reproducible image content;
credentials only authorize access to it.

Absent custom credentials leave legacy provider authentication unchanged.
Present but malformed credentials fail boot with an error that does not include
credential values. If the same host is supplied through both the structured
secret and a legacy registry/GCloud secret, boot rejects the conflict rather than
choosing a password by iteration order. A new structured token replaces the
cached credential for that host when boot is rerun. Changing hosts does not revoke
the old token: revoke it at the registry and redeploy the guest when required.

ECR remains on its separate [`ECR_REGISTRY_AUTH` refresh path](ecr-registry.md).
GHCR, Docker Hub, GCR, and legacy `REGISTRY_<HOST>_USER/TOKEN` inputs keep their
existing format. This contract supports one custom registry, matching the
controlplane's one-connection-per-organization policy.

## Rollout

The producer is [controlplane #890](https://github.com/tinfoilsh/controlplane/pull/890).
Release this guest support before enabling structured delivery in the controlplane,
then pin that supporting CVM release in the workload configuration and rebuild its
measured release. Previously published images ignore this secret; a successful
controlplane credential check does not establish guest compatibility. The first
supporting version must be recorded from the actual published release, not inferred
from the next expected version number.
