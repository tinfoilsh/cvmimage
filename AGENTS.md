# AGENTS.md

## Building

- The only build interface is the named Nix outputs in
  [docs/build.md](docs/build.md), on x86_64 Linux with the Nix release that
  `nix/install.sh` installs. Always pass `-I .`, because that Nix runs with
  `restrict-eval`: `nix-build -I . -A shipping-image -o result`.
- `nix-build -I . -A checks` runs the Go tests and `go vet` that CI runs.
  `go test ./...` in `tinfoil/` is the fast loop; the Go packages build only on
  Linux.
- When `tinfoil/go.mod` or `go.sum` changes, set `vendorHash` in `nix/go.nix`
  to the hash the failed build reports.
- Any change to an image input (Go code, `image/rootfs/`, `nix/`, `kernel/`,
  `repart.d/`) changes the measurement that clients verify. Pushing a `v*` tag
  publishes a release, and a stable tag also opens `cvm-version` update PRs in
  the repositories with the `tinfoil-functions` topic. Do not tag without
  approval.

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
  warnings, and typo checks in pre-deploy tooling or CI, not in the image.

## Inside a running enclave

- The shipping image has no systemd and no shell. `tinfoil-pid1` supervises
  every service, and `tinfoil-boot` accepts no maintenance subcommands.
- Debug SSH lands in the `tinfoil-debug-toolbox` container, which controls the
  workload containers through `tindbg` and the Docker CLI. Its own `AGENTS.md`
  in `/run/root` explains how.
- The debug image (`-A debug-image`) adds a BusyBox shell on the serial
  console.

## Testing

Pass `checks` before you push, and build the image for any change outside Go.
Booting the image on AMD SEV-SNP or Intel TDX hardware needs Tinfoil host
access, so ask the user how to test a runtime change end to end.
