# Release qualification and measurement promotion

Release qualification is a protected operational process. It is intentionally
outside pull-request and push CI, and it is not a custom image verifier. The
release worker, independent reproduction, protected approval, configuration
review, and runtime attestation form the integrity boundary.

Publishing a stable GitHub release through the protected
`cvm-release-publication` environment creates an **unpromoted candidate**. The tag
workflow records the exact source commit and SHA-256 values for the additive
rootfs tar, raw image, kernel, initrd, and direct roothash in the release
manifest. Publication alone must not change any expected measurement.

## Protected workflow

An operator manually dispatches `Qualify and Promote Release Measurement` with
the stable release tag, its exact 40-character source commit, and references to
the required external qualification records. The workflow has no `push` or
`pull_request` trigger.

The release and qualification process uses four protected environments:

1. `cvm-release-reproducibility` builds the selected commit twice in separate
   source, home, temporary, cache, and build roots. It runs ordinary
   `sha256sum` and `cmp` over `build/stage/bazel-rootfs.tar`, `tinfoilcvm.raw`,
   `tinfoilcvm.vmlinuz`, `tinfoilcvm.initrd`, and `tinfoilcvm.roothash`.
   `diffoscope` is used only when it is already available and a comparison
   fails. The qualified hashes must match the candidate release manifest and
   the versioned kernel, initrd, and raw-image bytes actually served from R2.
2. `cvm-release-hardware-qualification` requires a reviewer to inspect the
   separate-host reproduction and functional boot, workload, runtime
   attestation, H200, B300, and NVSwitch evidence. A hardware class may be
   marked not applicable only with a reason that the protected reviewer accepts.
3. `cvm-measurement-promotion` requires a separate approval before publishing
   content-addressed qualification evidence and opening configuration pull
   requests.

The evidence asset binds the release tag and source commit to the package and
artifact lock hashes, rootfs/raw/kernel/initrd hashes, direct roothash, release
manifest hash, workflow run, and all external qualification references. If an
asset with the same content-addressed name already exists, the workflow accepts
it only when `cmp` reports identical bytes; it never overwrites qualification
evidence. Its filename includes its SHA-256. Each generated configuration pull
request also commits `cvm-release-qualification.json` with that evidence digest
and all qualified hashes, so deleting or replacing a release asset cannot
silently change the measurement record approved in the configuration history.

## Protected repository configuration

Repository administrators must configure:

- required reviewers and deployment-branch restrictions for
  `cvm-release-publication`, `cvm-release-reproducibility`,
  `cvm-release-hardware-qualification`, and `cvm-measurement-promotion`;
- `CVM_CONFIG_REPOSITORIES` on `cvm-measurement-promotion` as a JSON array of
  fixed `owner/repository` names;
- `VERSION_UPDATER_APP_ID` and `VERSION_UPDATER_PRIVATE_KEY` as secrets on the
  promotion environment, with access limited to those repositories;
- branch protection and required review on each configuration repository so
  the generated pull request cannot merge without approval; and
- protected stable release tags plus ownership protection for the release and
  qualification workflow files.

The old release-published and standalone configuration updater is removed. The
protected workflow is the only repository-owned path that opens expected-
measurement promotion pull requests.

## Promotion boundary

The workflow does not directly weaken or bypass runtime policy. It opens a
reviewable change from `cvm-version` to the exact qualified release and commits
the exact source, input-lock, artifact, roothash, manifest, and evidence hashes
beside that change. The measurement becomes promoted only when that protected
configuration pull request is approved and merged. Runtime attestation remains
the enforcement point and must reject missing, malformed, incomplete, or
unpromoted measurements.

Build disruption and denial of service are acceptable in this process. A
failed, interrupted, mismatched, unapproved, or partially qualified run must
not update an expected measurement.

The closed #206-#211 branches remain historical reference only. This workflow
does not use, modify, or replace their custom verifier or archive-gate designs.
