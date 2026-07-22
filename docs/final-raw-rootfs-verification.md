# Final Raw Rootfs Verification

`scripts/verify-final-rootfs.py` verifies the produced raw disk artifact itself.
It does not accept build logs or intermediate extraction reports as evidence.

The verifier requires absolute, non-symlinked regular-file paths for the raw
image and canonical rootfs manifest. It validates the protective MBR and both
GPT copies directly, including CRCs, fixed 512-byte/128-entry geometry, aligned
first usable LBA 2048, and exactly one x86-64 root partition with GPT type
`4f68bce3-e8cd-4db1-96e7-fbcaf984b709`, label `root`, and only GPT attribute
bit 60 set to require read-only use.

After GPT validation it creates a private mount namespace, configures a
read-only/autoclear/partition-scanning loop device through the kernel ioctl,
checks the kernel partition geometry against the GPT entry, and mounts ext4
with `ro,nosuid,nodev,noexec,noload`. The mounted tree is inventoried by the
descriptor-relative `scripts/rootfs_manifest.py` implementation and compared
bidirectionally with the copied canonical manifest. All xattrs are retained;
there is no exception for `user.validatefs.*`.

The executable and both privileged Python boundaries use fixed
`/usr/bin/python3 -I` execution. The Make entry point and child manifest
processes additionally use an empty, minimal environment containing only the
trusted path and C locale settings.

Temporary manifests and the mountpoint live in a process-marker-owned directory
under `/run`. Signal and error cleanup unmounts the private mount and closes the
autoclear loop device before removing only that owned directory. There is no
caller-selected output path; verification succeeds or fails without publishing
an intermediate manifest as evidence.

Run the unprivileged adversarial suite with:

```sh
make test-final-rootfs-verifier
```

Verify a produced artifact with absolute paths:

```sh
make verify-final-rootfs \
  FINAL_ROOTFS_IMAGE=/absolute/path/to/image.raw \
  FINAL_ROOTFS_MANIFEST=/absolute/path/to/rootfs.tsv
```

The test suite only runs an end-to-end privileged check when
`FINAL_ROOTFS_PRIVILEGED_TEST=1`, `FINAL_ROOTFS_TEST_IMAGE`, and
`FINAL_ROOTFS_TEST_MANIFEST` are supplied explicitly.
