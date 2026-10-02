# A reproducible, static build of the compiler. rustc hands the final link to
# cc, so pkgs is taken from the caller to pin the whole toolchain; see
# docs/launch.md.
{ pkgs }:

let
  inherit (pkgs) lib;
  cargoToml = builtins.fromTOML (builtins.readFile ../compiler/Cargo.toml);
in
pkgs.pkgsStatic.rustPlatform.buildRustPackage {
  pname = "cvm-compiler";
  inherit (cargoToml.package) version;

  # Named files, not directories: lib.fileset ignores .gitignore, so a whole
  # directory would drag a local cargo target/ into the derivation's inputs.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../firmware/Cargo.toml
      ../firmware/build.rs
      ../firmware/src
      ../compiler/Cargo.toml
      ../compiler/src
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  # Stable cargo has no profile-level trim-paths, so remap the build paths by
  # hand rather than baking them into the binary.
  env.RUSTFLAGS = "--remap-path-prefix=/build/source=/cvm-compiler --remap-path-prefix=/build/cargo-vendor-dir=/cargo";

  # firmware/build.rs assembles the reset shims with as and objcopy.
  nativeBuildInputs = [
    pkgs.binutils
    pkgs.clippy
    pkgs.rustfmt
  ];

  preCheck = ''
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings
  '';

  meta = {
    description = "Compiles the Tinfoil firmware, kernel and initramfs into a measured CVM image";
    # The repository's LICENSE; the crates carry no separate notice.
    license = lib.licenses.agpl3Only;
    platforms = [ "x86_64-linux" ];
  };
}
