{
  pkgs,
  upstreamGo,
  tinfoilInitrd,
}:

let
  writer = pkgs.stdenvNoCC.mkDerivation {
    pname = "fixed-cpio-writer";
    version = "0";
    src = pkgs.lib.cleanSource ../image/initrd;
    nativeBuildInputs = [ upstreamGo ];
    allowedReferences = [ ];
    dontConfigure = true;

    buildPhase = ''
      runHook preBuild
      export GOCACHE="$TMPDIR/go-cache"
      export GOTOOLCHAIN=local
      GO111MODULE=off CGO_ENABLED=0 go test writer.go writer_test.go
      GO111MODULE=off CGO_ENABLED=0 go build \
        -trimpath \
        -buildvcs=false \
        -ldflags='-s -w -buildid=' \
        -o write-fixed-cpio \
        writer.go
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      install -D -m 0755 write-fixed-cpio "$out/bin/write-fixed-cpio"
      runHook postInstall
    '';
  };

  archive = pkgs.runCommand "initrd.cpio.zst" { allowedReferences = [ ]; } ''
    ${writer}/bin/write-fixed-cpio \
      ${tinfoilInitrd}/bin/tinfoil-initrd \
      ${pkgs.zstd}/bin/zstd \
      "$out"
  '';
in
{
  inherit writer archive;
}
