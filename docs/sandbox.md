# Sandbox image

Build the CPU sandbox with `nix-build -A sandbox.shipping-image -o result-sandbox`.
The result contains `tinfoilcvm-sandbox.raw`, `.vmlinuz`, `.initrd`, and `.roothash`.
The existing `shipping-image` and `debug-image` outputs still select inference.
`sandbox.debug-image` adds the measured debug console.

The sandbox keeps the boot, shim, PID 1, and volume code in the `tinfoil` Go module.
It omits Docker, containerd, NVIDIA programs, NVIDIA modules, and nvattest from
its rootfs. Its additional runtime is OpenSSH. Enrollment calls
`internal/volume.OpenWorkspace` directly. A future storage service can replace
that call without changing `/enroll`, SSH, or the workspace paths.

Use `sandbox/tinfoil-config.yml` as the measured workload definition. It pins an
executable toolchain pack and declares one root-owned executable volume named
`workspace`. The first storage disk follows the model disks in the existing
fixed PCI layout. The volume has no `key-secret`; the client supplies its key at
enrollment. The launcher must attach the workspace before enrollment. A zeroed
disk is formatted; an existing disk must authenticate with the supplied key.

The toolchain pack supplies `nix/store` and `nix/var/nix/profiles/default`.
The shared volume library mounts a writable store overlay and exports the same
tree at `/workspace` and `/nix`. The SSH home is `/workspace/home`. The image's
shell links resolve through `/nix/var/nix/profiles/default/bin` after enrollment.

A client first verifies the enclave's release measurement and reads `/healthz`
over its attested channel. The response supplies a boot nonce and the ephemeral
SSH host-key fingerprint. The orchestrator signs an ES256 permit with issuer
`https://orchestrator.tinfoil.sh`, the sandbox domain as subject, that nonce as
audience, and an expiration. Its verifying key is compiled into the image.

`POST /enroll` takes `Authorization: Bearer <permit>` and a JSON object with
`key`, one SSH public-key line, and `volume`, base64 for the 64-byte workspace key.
After the authenticated disk, workspace layout, and exports are ready, the
volume library seals to SHA-384 of the canonical SSH key line, including its
newline. Enrollment claims that owner and starts OpenSSH. Success returns 204;
a repeat returns 409. A failed unlock leaves ownership unclaimed. If SSH startup
fails after sealing, enrollment returns 503 and keeps the owner claimed.

SSH accepts only the enrolled public key and binds to loopback port 22. Connect
through the shim's HTTP/2 CONNECT endpoint with authority `localhost:22`, checking
the SSH fingerprint against `/healthz`. The shim also allows the fixed development
ports in `tinfoil/cmd/sandbox-shim/main.go`. A sandbox process exit fails the boot;
PID 1 does not restart enrollment within the same boot.

After reboot, enroll again using a fresh permit and the same workspace key. The
nonce and SSH host key change; workspace files and store-overlay writes persist.
On TDX, verify the owner seal in RTMR3 in a fresh report. SNP and ordinary VMs do
not provide this register. This image retains the existing authenticated-volume
format; it does not migrate older, unauthenticated sandbox disks.

Run `nix-build -A checks` for unit tests, race checks, debug PID 1 tests, and vet.

Release CI builds and publishes separate `tinfoil-inference-<version>` and
`tinfoil-sandbox-<version>` artifacts, manifests, checksums, and provenance.
