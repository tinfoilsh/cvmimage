# AGENTS.md

## Building

- The only build interface is the named Nix outputs in
  [docs/build.md](docs/build.md), on x86_64 Linux with the Nix release that
  `nix/install.sh` installs. Always pass `-I .`, because that Nix runs with
  `restrict-eval`: `nix-build -I . -A shipping-image -o result`.
- `nix-build -I . -A checks` runs the Go tests and `go vet` that CI runs. Pass
  it before you push. `go test ./...` in `tinfoil/` is the fast loop; the Go
  packages build only on Linux.
- When `tinfoil/go.mod` or `go.sum` changes, set `vendorHash` in `nix/go.nix`
  to the hash the failed build reports.
- Any change to an image input (Go code, `image/rootfs/`, `nix/`, `kernel/`,
  `repart.d/`) changes the measurement that clients verify. Pushing a `v*` tag
  publishes a release, and a stable tag also opens `cvm-version` update PRs in
  every config repository. Do not tag without approval.

## Runtime invariants

- The root filesystem is read-only (dm-verity). Declare anything that must
  exist at runtime at build time: repository files in `image/rootfs/`, package
  paths in `nix/rootfs.nix`.
- `tinfoil/internal/boot/paths.go` is the single source of truth for runtime
  paths. Use its constants, not string literals.
- `/mnt/ramdisk/public` is mounted read-only into every container at
  `/tinfoil`. Keys, the external config, and other secrets stay under
  `/mnt/ramdisk/private`, which containers see only through explicit read-only
  grants.
- This code is the customer's audit surface. Put convenience validation,
  warnings, and typo checks in pre-deploy tooling (tinctl, tinfoild, CI), not in
  the image.

## Inside a running enclave

- The shipping image has no systemd and no shell. `tinfoil-pid1` supervises
  every service, and `tinfoil-boot` accepts no maintenance subcommands.
- Debug SSH lands in the `tinfoil-debug-toolbox` container, which controls the
  workload containers through `tindbg` and the Docker CLI. Its own `AGENTS.md`
  in `/run/root` explains how.
- The debug image (`-A debug-image`, launched with
  `tinctl dev-launch --debug-image`) adds a BusyBox shell on the serial console.
- `tinctl watch <id>` prints each boot stage's result.

[tinfoild's AGENTS.md](https://github.com/tinfoilsh/tinfoild/blob/main/AGENTS.md)
covers launching and reaching an enclave.

## End-to-end testing

Run the lightest level that exercises your change, and check the behavior your
diff touches rather than a generic checklist.

1. `nix-build -I . -A checks`: always.
2. Build the image: for any change outside Go.
3. Boot it on a dev host with `tinctl dev-launch` and confirm it reaches
   `ready`: for any non-trivial runtime change.
4. Boot it on a host with the TEE and GPU shape your change depends on. Ask
   which host first.
5. One boot per relevant platform: only when the user asks.

The axes are TEE (AMD SEV-SNP or Intel TDX), GPU type, and GPU count (none,
one, or several). A boot-path change needs one host per TEE; a GPU attestation,
model pack, or passthrough change needs each GPU shape it can reach. Find hosts
by `cpu_vendor` and `gpu_type` in infra's `inventory.yml`, and follow
[infra's AGENTS.md](https://github.com/tinfoilsh/infra/blob/main/AGENTS.md)
for which hosts you may use. If the fleet lacks a combination, say so instead of
claiming coverage.

Use the configs and verification scripts in
[infra-harness](https://github.com/tinfoilsh/infra-harness) rather than writing
new ones.
