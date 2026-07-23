# Kernel profiles

The custom Linux 7.0 build has three closed profiles:

- `release` is the default and is the only production profile. It keeps the
  existing `7.0.0-28-generic` release and `kernel/build` and `kernel/out`
  artifact paths. Kernel IBT is explicitly disabled until NVIDIA compatibility
  has been qualified.
- `qualification-ibt` enables only `CONFIG_X86_KERNEL_IBT` and uses the
  distinct `7.0.0-28-tinfoil-qualification-ibt` release under isolated
  profile build and output roots.
- `debug` currently changes only artifact identity. It reserves an isolated
  profile without enabling broad debug configuration.

Select a non-release profile explicitly:

```sh
TINFOIL_KERNEL_PROFILE=qualification-ibt make custom-kernel-artifacts
TINFOIL_KERNEL_PROFILE=debug make custom-kernel-artifacts
```

Unknown profiles fail closed. Non-release profiles cannot write the default
release roots, and the shipping target requires `kernel/out/profile` to contain
exactly `release`. Qualification and debug kernels are test evidence only and
must never be promoted, published, or used as production measurements.

NVIDIA modules are currently defined only for the release profile. The module
producer rejects qualification and debug profiles so a release-built module
cannot be mistaken for a profile-qualified artifact. IBT-aware NVIDIA module
production and hardware qualification are separate prerequisites before any
shipping IBT change.
