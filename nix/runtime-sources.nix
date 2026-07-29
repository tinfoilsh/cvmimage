{
  busybox = {
    name = "busybox-static";
    url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/b/busybox/busybox-static_1.37.0-7ubuntu1_amd64.deb";
    sha256 = "fd605342f62268753076aa7d9321ff098b36ba53e47434145a9aedc28fd141a4";
  };

  docker = {
    name = "docker-29.5.3-static";
    url = "https://download.docker.com/linux/static/stable/x86_64/docker-29.5.3.tgz";
    sha256 = "34eea64e9c3435f5af1b760827a56a561cd67fc2d6e9cd1813b8bb1e3ff7930b";
  };

  nvidiaDebs = [
    { name = "libnvidia-cfg1"; url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/libnvidia-cfg1_595.71.05-1ubuntu1_amd64.deb"; sha256 = "dc18f61a73350cb4c19a775172c3090d794aae93eba5e0413a559b2337dff092"; }
    { name = "libnvidia-compute"; url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/libnvidia-compute_595.71.05-1ubuntu1_amd64.deb"; sha256 = "6e934848e693668ee678bd5346d7688774925700a0a35d943a2adfff2c8b4076"; }
    { name = "libnvidia-gpucomp"; url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/libnvidia-gpucomp_595.71.05-1ubuntu1_amd64.deb"; sha256 = "c541c308a25773471a5826897e8025d1fcf9cb742e0da566de19d4ca15f6050e"; }
    { name = "libnvidia-nscq"; url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/libnvidia-nscq_595.71.05-1ubuntu1_amd64.deb"; sha256 = "d02d606e3ab10db7ae5c7abd9c4dc803365d19de75261e1424f5af723992ea0f"; }
    { name = "nvidia-container-toolkit-base"; url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/nvidia-container-toolkit-base_1.19.1-1_amd64.deb"; sha256 = "3ee2a9202294fdd27cd79e23f35b7a1f24ea0fa934ab03229f25c89b3245defe"; }
    { name = "nvidia-fabricmanager"; url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/nvidia-fabricmanager_595.71.05-1ubuntu1_amd64.deb"; sha256 = "480d185ebb109cc3f1ebe73a6c5cff4a072a1b0ddde08017fd2f1bf9048afe66"; }
    { name = "nvidia-firmware"; url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/nvidia-firmware_595.71.05-1ubuntu1_amd64.deb"; sha256 = "105ceeae7c20cce66109a636f5a9bcd4bb4a820e0937f7407b91945dceaa5086"; }
    { name = "nvidia-persistenced"; url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/nvidia-persistenced_595.71.05-1ubuntu1_amd64.deb"; sha256 = "6c4c02e6a9f596fa95ff036d87ff7d0c9040faf3e7f51ad8fdc8f6e6bf938f65"; }
  ];
}
