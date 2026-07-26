{ pkgs }:

let
  regorusRevision = "c7bf460bc160c96e38048296e5708943d2e43909";

  source = name: url: hash: pkgs.fetchzip {
    inherit url hash;
    name = "${name}-source";
  };

  attestationSdk = source "attestation-sdk"
    "https://github.com/NVIDIA/attestation-sdk/archive/9d12801cea8a198ea0f29640dfaf8a4017c841c5.tar.gz"
    "sha256-e41BjJV4C1tRqYtZ347AYzIjBiwtGEBOJ3FRWbWItsg=";
  cli11 = source "cli11"
    "https://github.com/CLIUtils/CLI11/archive/bfffd37e1f804ca4fae1caae106935791696b6a9.tar.gz"
    "sha256-q5q6TgSex0xjdWFf/4e6dhrN0qWPDjIgWBpdkCTlLys=";
  jwtCpp = source "jwt-cpp"
    "https://github.com/Thalhammer/jwt-cpp/archive/e71e0c2d584baff06925bbb3aad683f677e4d498.tar.gz"
    "sha256-neOCARLkeB1kCYGIkm5BKK+MWF1T830xRNzpdE0SSWM=";
  fmtSource = source "fmt"
    "https://github.com/fmtlib/fmt/archive/e69e5f977d458f2650bb346dadf2ad30c5320281.tar.gz"
    "sha256-pEltGLAHLZ3xypD/Ur4dWPWJ9BGVXwqQyKcDWVmC3co=";
  spdlogSource = source "spdlog"
    "https://github.com/gabime/spdlog/archive/27cb4c76708608465c413f6d0e6b8d99a4d84302.tar.gz"
    "sha256-F7khXbMilbh5b+eKnzcB0fPPWQqUHqAYPWJb83OnUKQ=";
  jsonSource = source "json"
    "https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz"
    "sha256-tOInM4YYi/cbHCWP2R0jlFzlaTN0ZVgHFMWagz9Wnvk=";
  opensslSource = source "openssl"
    "https://github.com/openssl/openssl/releases/download/openssl-3.6.1/openssl-3.6.1.tar.gz"
    "sha256-pj8ekUqkZPEnevY3i+42uF//cWyr1tgWSaSn0V+DjjU=";
  xmlsecSource = source "xmlsec"
    "https://github.com/lsh123/xmlsec/releases/download/xmlsec-1_2_39/xmlsec1-1.2.39.tar.gz"
    "sha256-v4gbjei20nkgCLOUyOvEkx9vT3TcfaVfHQ7wbVQx56A=";
  curlSource = source "curl"
    "https://github.com/curl/curl/releases/download/curl-7_88_1/curl-7.88.1.tar.gz"
    "sha256-A+ig2Cjyu4QE5gh9X5yvvHPjYMRT9jo45QmPAOBpgpA=";
  regorusSource = pkgs.fetchzip {
    url = "https://github.com/microsoft/regorus/archive/${regorusRevision}.tar.gz";
    hash = "sha256-bb4rCGFItwXQB+JlIObzkVOfEi8y+PFR3xMufTwB94U=";
  };

  regorusFfi = pkgs.rustPlatform.buildRustPackage {
    pname = "regorus-ffi";
    version = "0.2.2";
    src = regorusSource;
    cargoRoot = "bindings/ffi";
    buildAndTestSubdir = "bindings/ffi";
    cargoLock.lockFile = ../builder/nvattest/regorus.Cargo.lock;
    env.CARGO_INCREMENTAL = "0";
    patches = [ ./patches/regorus-pinned-revision.patch ];
    postPatch = ''
      cp ${../builder/nvattest/regorus.Cargo.lock} bindings/ffi/Cargo.lock
      substituteInPlace build.rs \
        --replace-fail '@REGORUS_REVISION@' '${regorusRevision}'
    '';
    preBuild = ''
      export NIX_BUILD_CORES=1
      export RUSTFLAGS="--remap-path-prefix=$NIX_BUILD_TOP=/usr/src/regorus -C target-cpu=x86-64 -C codegen-units=1"
    '';
    buildFeatures = [ "regorus/semver" ];
    doCheck = false;
    installPhase = ''
      runHook preInstall
      install -Dm0644 target/x86_64-unknown-linux-gnu/release/libregorus_ffi.a \
        "$out/lib/libregorus_ffi.a"
      install -Dm0644 bindings/ffi/regorus.h "$out/include/regorus.h"
      install -Dm0644 bindings/ffi/regorus.ffi.hpp "$out/include/regorus.ffi.hpp"
      runHook postInstall
    '';
  };

  nvattestBuilt = pkgs.stdenv.mkDerivation {
    pname = "nvattest";
    version = "1.2.2";
    src = attestationSdk;
    patches = [
      ./patches/nvattest-pinned-sources.patch
      ./patches/nvattest-ca-bundle.patch
      ./patches/nvattest-explicit-runtime-links.patch
    ];
    postPatch = ''
      substituteInPlace nv-attestation-sdk-cpp/CMakeLists.txt \
        --replace-fail '@REGORUS_LIBRARY@' '${regorusFfi}/lib/libregorus_ffi.a' \
        --replace-fail '@REGORUS_INCLUDE@' '${regorusFfi}/include' \
        --replace-fail '@OPENSSL_SOURCE@' '${opensslSource}' \
        --replace-fail '@OPENSSL_PATCH@' '${./patches/openssl-reproducible-buildinfo.patch}' \
        --replace-fail '@PERL@' '${pkgs.perl}/bin/perl' \
        --replace-fail '@XMLSEC_SOURCE@' '${xmlsecSource}' \
        --replace-fail '@CURL_SOURCE@' '${curlSource}'
    '';
    nativeBuildInputs = [
      pkgs.cmake
      pkgs.perl
      pkgs.pkg-config
      pkgs.patchelf
    ];
    buildInputs = [
      pkgs.libxml2
      pkgs.zlib
    ];
    cmakeDir = "../nv-attestation-cli";
    cmakeFlags = [
      "-DBUILD_TESTING=OFF"
      "-DBUILD_EXAMPLES=OFF"
      "-DFETCHCONTENT_FULLY_DISCONNECTED=ON"
      "-DFETCHCONTENT_SOURCE_DIR_CLI11=${cli11}"
      "-DFETCHCONTENT_SOURCE_DIR_JSON=${jsonSource}"
      "-DFETCHCONTENT_SOURCE_DIR_JWT-CPP=${jwtCpp}"
      "-DFETCHCONTENT_SOURCE_DIR_FMT=${fmtSource}"
      "-DFETCHCONTENT_SOURCE_DIR_SPDLOG=${spdlogSource}"
      "-DCMAKE_INSTALL_PREFIX=/usr"
      "-DCMAKE_INSTALL_BINDIR=bin"
      "-DCMAKE_INSTALL_LIBDIR=lib"
      "-DCMAKE_INSTALL_INCLUDEDIR=include"
      "-DCMAKE_SKIP_RPATH=ON"
      "-DCMAKE_EXE_LINKER_FLAGS=-Wl,--build-id=none"
      "-DCMAKE_SHARED_LINKER_FLAGS=-Wl,--build-id=none"
    ];
    enableParallelBuilding = false;
    dontPatchELF = true;
    env.SOURCE_DATE_EPOCH = "0";
    preConfigure = ''
      prefixMap="-ffile-prefix-map=$NIX_BUILD_TOP=/usr/src/nvattest -fmacro-prefix-map=$NIX_BUILD_TOP=/usr/src/nvattest -fdebug-prefix-map=$NIX_BUILD_TOP=/usr/src/nvattest"
      export CFLAGS="''${CFLAGS:-} $prefixMap -march=x86-64 -mtune=generic"
      export CXXFLAGS="''${CXXFLAGS:-} $prefixMap -march=x86-64 -mtune=generic"
      export NIX_CFLAGS_COMPILE="''${NIX_CFLAGS_COMPILE:-} $prefixMap -march=x86-64 -mtune=generic"
    '';
    buildPhase = ''
      runHook preBuild
      cmake --build . --target xmlsec_external curl_external --parallel 1
      finalLdflags=()
      skipNext=false
      for flag in $NIX_LDFLAGS; do
        if $skipNext; then
          skipNext=false
          continue
        fi
        case "$flag" in
          -rpath) skipNext=true ;;
          -rpath=*) ;;
          *) finalLdflags+=("$flag") ;;
        esac
      done
      NIX_DONT_SET_RPATH=1 NIX_LDFLAGS="''${finalLdflags[*]}" \
        cmake --build . --target nvattest --parallel 1
      runHook postBuild
    '';
    installPhase = ''
      runHook preInstall
      install -Dm0755 nvattest "$out/usr/bin/nvattest"
      install -Dm0644 nv-attestation-sdk-build/libnvat.so.1.2.2 \
        "$out/usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2"
      strip --strip-unneeded \
        "$out/usr/bin/nvattest" \
        "$out/usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2"
      patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 \
        --remove-rpath "$out/usr/bin/nvattest"
      patchelf --remove-rpath \
        "$out/usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2"
      runHook postInstall
    '';
    doCheck = false;
  };
in
{
  regorus-ffi = regorusFfi;
  nvattest = nvattestBuilt;
}
