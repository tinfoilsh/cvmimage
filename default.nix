{
  system ? "x86_64-linux",
}:

assert system == "x86_64-linux";

let
  nixpkgsLock = builtins.fromJSON (builtins.readFile ./nixpkgs.lock.json);
  nixpkgs = builtins.fetchTarball {
    inherit (nixpkgsLock) url sha256;
  };
  pkgs = import nixpkgs {
    inherit system;
    config = { };
    overlays = [ ];
  };
  variants = {
    cpu = import ./nix/variant.nix { inherit pkgs; gpuSupport = false; };
    gpu = import ./nix/variant.nix { inherit pkgs; gpuSupport = true; };
  };
in
variants.cpu // {
  inherit variants;
  "release-upload-cli" = pkgs.awscli2;
  "cvm-compiler" = import ./nix/compiler.nix { inherit pkgs; };
}
