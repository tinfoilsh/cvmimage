# tinfoil-config

Canonical Go types and validation for the measured Tinfoil workload YAML format.

## Go API

```go
cfg, err := tinfoilconfig.Decode(data, tinfoilconfig.Options{})
```

Use `HostDebugMode` for trusted debug-toolbox configuration. It permits the
reserved toolbox's runtime socket mounts; all other validation still applies.

## CLI

```sh
go run ./cmd/tinfoil-config config.yml
```

The command exits non-zero and prints the schema or policy violation for
invalid input.

## Model grants

`containers[].models` grants isolated named model mounts. Encrypted models
require an explicit grant; plaintext models without grants use shared mounts.

## Local attestation

`containers[].attestation: true` grants access to the local attestation socket.
Access defaults to false.

## CVM administration

`containers[].cvm_admin: true` grants administration of the entire CVM, including
other workloads and their secrets. The profile uses UID/GID 0, privileged
execution, and no-new-privileges disabled. The rootfs is writable unless
`read_only: true` is set. Admin access does not enable debug mode.

Admin containers use declared bridge `networks` and `ports`. Direct SSH requires
`cvm-network.inbound-ports` to include 22 and an admin container publishing
`22:22` on an attached network. `AdminSSH(cfg)` returns that mapping, or nil when
none is enabled. Other published ports remain private. Writable layers and
Docker state are ephemeral across CVM reboot; declared volumes provide
persistent storage.

## CVM source

`cvm-source` specifies the image release repository and HTTPS artifact URL:

```yaml
cvm-source:
  repo: tinfoilsh/cvmimage-sandbox
  artifacts: https://images.example.com/cvm
```

Both fields are required when the block is present. Without it,
`tinfoilsh/cvmimage` and `https://images.tinfoil.sh/cvm` apply.

## Attested boot keys

Declare keys and assign each to a container:

```yaml
attested-keys:
  - id: host-ssh
    key: ecdsa-p256
containers:
  - name: workspace
    keys: [host-ssh]
    # Image and other required configuration omitted.
```

Supported algorithms are `ecdsa-p256`, `ed25519`, and `x25519` (key agreement).
Up to 32 keys can be declared, each with exactly one container grant. IDs match
`^[a-z][a-z0-9-]{0,62}$`; `tls` and `hpke` are reserved. Optional numeric `uid`
and `gid` default to 0 and range from 0 to 65534.

Each grant provides read-only files at `/run/tinfoil/keys/<id>/`: owner-only
`private_key.pem` (PKCS#8) and `public_key.pem` (SPKI). A parent `/run` tmpfs is
allowed; mounts overlapping the key subtree are rejected. Keys last for one
CVM boot, surviving container and shim restarts. V3 attestation endorses their
public SPKI under the declared ID. Applications handle protocol-specific formats.
