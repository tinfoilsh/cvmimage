# Locked-volume guard follow-up review

## Scope and assessment

Reviewed against original guest `35d94c85ad20e9f98cd4ddcf35dfe4574b5215fb`
and pre-follow-up guard `8bdb1099e7226be0c905d80d1268e49fe3788806`.
The only production change in this follow-up is the read-only remount flag
conversion in `tinfoil/internal/volume/volume.go:225-243` and its Linux statfs
constant. No unresolved security finding was identified within this scope.

The helper has one production caller, `volume.prepare`, reached by boot `Mount`
and runtime `Serve`. Inspection still precedes the read-only remount and returns
early for an unlocked mapping or an error. Mount failures still block worker
readiness and application startup. The write guard is not a security boundary
against a CVM administrator with mount privileges.

Line-by-line diff review confirms that HKDF inputs, authenticated encryption,
blank detection, formatter subprocess/rollback, runtime seal extension,
attestation, worker protocol, boot key resolution, and container `rslave` binds
are unchanged from the original guest. No new endpoint or key handling exists.

## Findings and dispositions

| Review thread | Assessment |
| --- | --- |
| `PRRT_kwDONcZqQc6mOWck` | Valid, medium: remount discarded inherited `nosymfollow`, allowing symlink traversal. Linux reports it as `ST_NOSYMFOLLOW=0x2000`, not `MS_NOSYMFOLLOW=0x100`; merely adding the mount bit to the mask does not fix it. Translate explicitly; the local named constant covers its absence in `x/sys/unix` v0.47.0. |
| Variant found during review | Valid, low: `ST_RELATIME` differs from `MS_RELATIME`; inherited `strictatime+nodiratime` became relatime. Translate relatime and explicitly select strictatime when neither noatime nor relatime is reported. The other retained per-mount bits have matching values. Superblock-only options are unaffected by a bind remount. |
| `PRRT_kwDONcZqQc6mOWci` | Not reachable in the supported lifecycle: `Serve` completes `prepare` before creating its control socket (`worker.go:49-57`), and PID 1 waits for that socket before starting applications (`cmd/pid1/main.go:285-295,604-607`). Boot mounts also finish before applications start. No application peer exists during the first remount; subsequent preparation sees either the protected placeholder or the unlocked filesystem. Making a mount shared does not itself create a peer. Keep startup and propagation ordering unchanged. |
| `PRRT_kwDONcZqQc6mOWcs` | Valid: enable `pipefail` in the Alpine shell packing pipeline. An injected `cpio` exit 42 incorrectly returned 0 before this change and returns 42 afterward. |
| `PRRT_kwDONcZqQc6mOWct` | Valid: named `vm_timeout` is 480 seconds, giving 180 seconds of boot/shutdown and host-load headroom beyond the sequential 60+240-second guest test limits. |
| `PRRT_kwDONcZqQc6mOWcw` | Valid: VM expectations require non-nil errors for both rejected and failed responses, and nil errors for successful/locked responses. |

## Runtime evidence

The README build, device-free mount, non-root unit, Apple Silicon suite/race/vet,
and baseline VM commands were run on Docker Desktop ARM64. The three x86 seccomp
groups excluded from syscall emulation passed on the QEMU AMD64 guest kernel.
The full documented suite/race/vet/debug command passed twice. No raw host
device, privileged container, production credential, release, or pin was used.

- The inherited symlink regression failed three times before the production edit:
  `symlink traversal = <nil>, want ELOOP`.
- Six access-time variants, each retaining `nosymfollow`, passed three repetitions
  after the edit (18 kernel-level cases). Locked writes returned `EROFS`; live
  unlocks stayed writable; rollback restored the guard; parent writes succeeded.
- Those same expanded tests failed against `8bdb109` in all three repetitions.
  `strictatime+nodiratime` reported flags `0x182f`, expected `0x282f`, demonstrating
  both lost `nosymfollow` and changed access-time semantics.
- The original `35d94c8` QEMU baseline reached all three locked-write assertions
  and failed with `readonly=false EROFS=false`, while initialization and live
  encrypted writes succeeded. This is an assertion reproduction, not a setup
  failure; the runner stopped after the failing first boot with exit 1.
- The rebuilt patched QEMU fixture passed initialize and reopen boots, each with
  `VOLUME_FIXTURE_RESULT=0`. Wrong-key runtime and boot unlocks and refused
  reinitialization left the entire disk SHA-256 unchanged:
  `85de15f4771e4eb1048fa0533c5af14e34c656b96f9703dc6c323b9049d519fe`.
  The original key recovered the original payload, SHA-256
  `967659bf87142168d69fea7e3f0f7ced78355ae37c4539a76f03b508505c3d5d`.
- `gofmt -d` and `git diff --check` were clean.

To repeat the inherited-flag baseline, build the README fixtures, then run from
the repository root (expected exit 1):

```sh
git archive 8bdb1099e7226be0c905d80d1268e49fe3788806 tinfoil/internal/volume/volume.go |
  docker run --rm -i --platform linux/amd64 --network none --cap-drop ALL \
    --cap-add SYS_ADMIN --cap-add DAC_OVERRIDE --security-opt no-new-privileges \
    --mount "type=bind,src=$PWD/tinfoil/internal/volume/mount_integration_test.go,dst=/src/tinfoil/internal/volume/mount_integration_test.go,readonly" \
    -e TINFOIL_VOLUME_MOUNT_TEST=1 -w /src/tinfoil cvmimage-volume-tests:guard sh -c '
      tar --no-same-owner -xf - -C /src &&
      CGO_ENABLED=0 go test -v -count=3 -timeout=60s \
        ./internal/volume/volume.go ./internal/volume/worker.go ./internal/volume/format.go \
        ./internal/volume/app_integration_test.go ./internal/volume/mount_integration_test.go
    '
```

The fixture pipeline failure is reproducible without capabilities or devices:

```sh
# Expected exit 42, not success.
docker run --rm --platform linux/amd64 --network none --cap-drop ALL \
  --security-opt no-new-privileges cvmimage-volume-tests:guard \
  sh -c 'cpio() { return 42; }; . /fixture/pack.sh'

# The original script incorrectly exits 0 for the same failure.
git show 8bdb109:tests/volume-vm/pack.sh |
  docker run --rm -i --platform linux/amd64 --network none --cap-drop ALL \
    --security-opt no-new-privileges cvmimage-volume-tests:guard \
    sh -c 'cpio() { return 42; }; . /dev/stdin'
```

Evidence level is local runtime plus source comparison, not a hardware
attestation or full production-CVM validation. These checks were run directly,
not through the automated post-patch-validation runner. Human review is still
required; the fixture does not establish release readiness or approve a new pin.
