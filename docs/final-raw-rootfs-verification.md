# Final Raw Rootfs Verification

`scripts/verify-final-rootfs.py` verifies the produced raw disk artifact itself.
It does not accept build logs or intermediate extraction reports as evidence.

The verifier requires absolute, non-symlinked regular-file paths for the raw
image and canonical rootfs manifest. The raw image must be exactly
3,490,729,984 bytes. It validates the protective MBR and both
GPT copies directly, including CRCs, fixed 512-byte/128-entry geometry, aligned
first usable LBA 2048, and exactly two partitions with no extras. Entry 1 is
the x86-64 root partition with GPT type
`4f68bce3-e8cd-4db1-96e7-fbcaf984b709` and label `root`. Entry 2 is its
x86-64 verity hash partition with type
`2c7357ed-ebd2-46d9-aec1-23d437ec2bf5` and label
`root-x86-64-verity`. Both have only GPT attribute bit 60 set, use 4096-byte
aligned geometry, and are contiguous from LBA 2048. Their byte counts must
exactly match the fixed 3 GiB root and 256 MiB verity contracts compiled into
the verifier; there is no runtime configuration parser. The verity partition
ends at the largest 4096-byte boundary
allowed by the GPT last-usable LBA, leaving only the sub-block alignment tail
before the backup entry array.

All bytes outside the fixed GPT structures and partitions are authenticated as
zero: protective-MBR boot/reserved bytes, the space from the primary entry
array through LBA 2047, and the final alignment tail after the verity
partition. This rejects hidden payloads in otherwise unused raw-image space.
The protective entry's boot, CHS, and type prefix is exactly
`00 00 02 00 ee ff ff ff`. The GPT disk UUID is the deterministic
seed-derived `bd21aac6-0338-4a33-85d9-d14ccf6c5ea1`; arbitrary nonzero UUIDs
are rejected.

The required direct roothash is a separate, descriptor-opened regular file
containing exactly 64 lowercase hexadecimal bytes. Its two 128-bit halves must
equal the root and verity PARTUUIDs. Before the root filesystem is mounted, the
verifier opens both kernel partition nodes with no-follow descriptors,
validates their block major/minor numbers against sysfs, and retains those exact
objects. `/usr/sbin/veritysetup verify` authenticates every root data block
against the hash partition and supplied roothash through `/proc/self/fd/N`
arguments with only those descriptors passed to the child. The invocation
disables superblock parsing and pins format 1, SHA-256, 4096-byte data and hash
blocks, a 4096-byte hash offset, the GPT-derived data-block count, and the
measured build salt.
The verifier independently calculates every SHA-256 format-1 hash-tree level
at 128 digests per 4096-byte block. It requires the complete 4096-byte prefix
before the tree and every byte after the exact final tree block through the end
of the fixed verity partition to be zero.

After GPT validation it creates a private mount namespace, configures a
read-only/autoclear/partition-scanning loop device through the kernel ioctl,
checks the kernel partition geometry against the GPT entries, and mounts ext4
through the pinned root descriptor with `ro,nosuid,nodev,noexec,noload`. Both
partition objects are rechecked before and after privileged consumption, so
replacing either `/dev` node cannot redirect verity verification or mount. The
mounted tree is inventoried by the descriptor-relative
`scripts/rootfs_manifest.py` implementation and compared
bidirectionally with the copied canonical manifest. All xattrs are retained;
there is no exception for `user.validatefs.*`.

Both privileged Python boundaries use fixed `/usr/bin/python3 -I` execution
with an empty, minimal environment containing only the trusted path and C
locale settings.

Temporary manifests and the mountpoint live in a process-marker-owned directory
under `/run`. Signal and error cleanup unmounts the private mount and closes the
retained partition descriptors and autoclear loop device before removing only
that owned directory. There is no
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
  FINAL_ROOTFS_MANIFEST=/absolute/path/to/rootfs.tsv \
  FINAL_ROOTFS_ROOTHASH=/absolute/path/to/image.roothash
```

The test suite only runs an end-to-end privileged check when
`FINAL_ROOTFS_PRIVILEGED_TEST=1`, `FINAL_ROOTFS_TEST_IMAGE`, and
`FINAL_ROOTFS_TEST_MANIFEST`, and `FINAL_ROOTFS_TEST_ROOTHASH` are supplied
explicitly.
