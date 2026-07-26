{ pkgs }:

let
  packageUrlPrefix = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z";

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
      timestamp = "20260721";
      pocket = "resolute";
      component = "main";
      sha256 = "ed9ac41cb263efaecc5a06a0742dc56570e2fb5ff94c4f2e4b2fbdcddd73cf24";
    })
    (packageIndex {
      timestamp = "20260721";
      pocket = "resolute";
      component = "restricted";
      sha256 = "147c90b597ef6c1d1480f9cfe44f49201e9c2c0a1071f3ebec9e4de51690ccbd";
    })
    (packageIndex {
      timestamp = "20260721";
      pocket = "resolute";
      component = "universe";
      sha256 = "1587be86d66d38542325215e0e109f75bd695c8f24d793ace2762038a6ad581e";
    })
    (packageIndex {
      timestamp = "20260721";
      pocket = "resolute";
      component = "multiverse";
      sha256 = "649e6c37f2c1fa6b2d5081bc7714c9e2ad66083005bb80fab34c3c537781a1c9";
    })
    (packageIndex {
      timestamp = "20260615";
      pocket = "resolute-security";
      component = "main";
      sha256 = "63d7fad5a61519948c6d47682e300b7d2f66038d42bcea8137c4d3477ed4aa09";
    })
  ];

  packageNames = [
    "ca-certificates"
    "iproute2"
    "nftables"
    "libc6"
    "libc-bin"
    "libcap2"
    "libxml2-16"
    "libstdc++6"
    "libgcc-s1"
    "zlib1g"
    "libtirpc3t64"
    "libtirpc-common"
    "libseccomp2"
  ];
in
{
  lock = pkgs.vmTools.debClosureGenerator {
    name = "cvmimage-runtime-packages-lock";
    packagesLists = packageIndexes;
    urlPrefix = packageUrlPrefix;
    packages = packageNames;
  };

  packages = pkgs.lib.flatten (import ./runtime-packages-lock.nix { inherit (pkgs) fetchurl; });
}
