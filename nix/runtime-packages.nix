{ pkgs, gpuSupport }:

let
  packageUrlPrefix = "https://snapshot.ubuntu.com/ubuntu/20261027T000000Z";

  packageIndex =
    {
      timestamp,
      pocket,
      component,
      sha256,
    }:
    pkgs.fetchurl {
      name = "${timestamp}-${pocket}-${component}-Packages.xz";
      url = "https://snapshot.ubuntu.com/ubuntu/${timestamp}T000000Z/dists/${pocket}/${component}/binary-amd64/Packages.xz";
      inherit sha256;
    };

  packageIndexes = [
    (packageIndex {
      timestamp = "20261027";
      pocket = "resolute";
      component = "main";
      sha256 = "ed9ac41cb263efaecc5a06a0742dc56570e2fb5ff94c4f2e4b2fbdcddd73cf24";
    })
    (packageIndex {
      timestamp = "20261027";
      pocket = "resolute";
      component = "restricted";
      sha256 = "147c90b597ef6c1d1480f9cfe44f49201e9c2c0a1071f3ebec9e4de51690ccbd";
    })
    (packageIndex {
      timestamp = "20261027";
      pocket = "resolute";
      component = "universe";
      sha256 = "1587be86d66d38542325215e0e109f75bd695c8f24d793ace2762038a6ad581e";
    })
    (packageIndex {
      timestamp = "20261027";
      pocket = "resolute";
      component = "multiverse";
      sha256 = "649e6c37f2c1fa6b2d5081bc7714c9e2ad66083005bb80fab34c3c537781a1c9";
    })
    (packageIndex {
      timestamp = "20261027";
      pocket = "resolute-updates";
      component = "main";
      sha256 = "019596d758fb9d5f4097dd123a1c9977a029197d88e6e651d90d165237dfc23e";
    })
    (packageIndex {
      timestamp = "20261027";
      pocket = "resolute-updates";
      component = "restricted";
      sha256 = "83536ea9e9e608a10210a197d0acc31d5bd40a41c10759177716074c7a703b24";
    })
    (packageIndex {
      timestamp = "20261027";
      pocket = "resolute-updates";
      component = "universe";
      sha256 = "709a9a568b5fa73230685e7a0acd376aab21afa6bf1626229948a27d98ef5759";
    })
    (packageIndex {
      timestamp = "20261027";
      pocket = "resolute-updates";
      component = "multiverse";
      sha256 = "badafaf56a17a0e36cd156e6dadbd156942c78c044674c6f43c0e0889cc33eed";
    })
    (packageIndex {
      timestamp = "20261027";
      pocket = "resolute-security";
      component = "main";
      sha256 = "7810a08ea76f8601a1431449b4422b667fd1e88998a2c4b2a7768a2f7c155a09";
    })
    (packageIndex {
      timestamp = "20261027";
      pocket = "resolute-security";
      component = "restricted";
      sha256 = "62d2c6c804fe06fe344bffefd84eaad74f5aba06f5f974aad29224f6e0393a02";
    })
    (packageIndex {
      timestamp = "20261027";
      pocket = "resolute-security";
      component = "universe";
      sha256 = "eb49764b59f6a8086f992e0c2bb98e6c211913a500a073b04a6c2798bba24773";
    })
    (packageIndex {
      timestamp = "20261027";
      pocket = "resolute-security";
      component = "multiverse";
      sha256 = "94870f8cc13dd7606dab2d8ec411b0a3bda858454594a11404a0413c06c00b40";
    })
  ];

  packageNames = [
    "ca-certificates"
    "e2fsprogs"
    "iproute2"
    "nftables"
    "libc6"
    "libc-bin"
    "libcap2"
    "libgcc-s1"
    "zlib1g"
    "libseccomp2"
  ] ++ pkgs.lib.optionals gpuSupport [
    "libxml2-16"
    "libstdc++6"
    "libtirpc3t64"
    "libtirpc-common"
  ];
in
{
  lock = pkgs.vmTools.debClosureGenerator {
    name = "cvmimage-runtime-packages-lock";
    packagesLists = packageIndexes;
    urlPrefix = packageUrlPrefix;
    packages = packageNames;
  };

  packages = pkgs.lib.flatten (import (if gpuSupport then ./runtime-packages-gpu-lock.nix else ./runtime-packages-lock.nix) { inherit (pkgs) fetchurl; });
}
