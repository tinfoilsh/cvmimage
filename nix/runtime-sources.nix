let
  nvidiaCompute = {
    name = "libnvidia-compute";
    url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/libnvidia-compute_595.91.07-1ubuntu1_amd64.deb";
    sha256 = "d54a8aac6a48416158b8421ffdbb0821da3b94e9379593d1cb2aeb3f41758c3f";
  };
in
{
  busybox = {
    name = "busybox-static";
    url = "https://snapshot.ubuntu.com/ubuntu/20261021T000000Z/pool/main/b/busybox/busybox-static_1.37.0-7ubuntu1_amd64.deb";
    sha256 = "fd605342f62268753076aa7d9321ff098b36ba53e47434145a9aedc28fd141a4";
  };

  docker = {
    name = "docker-29.6.2-static";
    url = "https://download.docker.com/linux/static/stable/x86_64/docker-29.6.2.tgz";
    sha256 = "sha256-1iBK6pIjjiRT1URciFudLl64+CkVVo7FDt+dvhKjrHQ=";
  };

  nvidiaDebs = [
    { name = "libnvidia-cfg1"; url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/libnvidia-cfg1_595.91.07-1ubuntu1_amd64.deb"; sha256 = "b7218305ad120cef0cce07c96ea1cc08580a447c88ffc2d6fe3dfa2e6851c66a"; }
    nvidiaCompute
    { name = "libnvidia-gpucomp"; url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/libnvidia-gpucomp_595.91.07-1ubuntu1_amd64.deb"; sha256 = "9629cddcbed951c4e94c6a5d024aea6e4ee9745298f1185a5d4fe89dbf8b47d8"; }
    { name = "libnvidia-nscq"; url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/libnvidia-nscq_595.91.07-1ubuntu1_amd64.deb"; sha256 = "589139f4f3292e6ac248444ec059829f0a7832881e960d4fe3ea1425b37c6ea2"; }
    { name = "nvidia-container-toolkit-base"; url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/nvidia-container-toolkit-base_1.19.1-1_amd64.deb"; sha256 = "3ee2a9202294fdd27cd79e23f35b7a1f24ea0fa934ab03229f25c89b3245defe"; }
    { name = "nvidia-fabricmanager"; url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/nvidia-fabricmanager_595.91.07-1ubuntu1_amd64.deb"; sha256 = "a048a5f14ed6a72a0ace7259b5ff9921865646ea0ace1d06d2b3cc7cd80cb875"; }
    { name = "nvidia-firmware"; url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/nvidia-firmware_595.91.07-1ubuntu1_amd64.deb"; sha256 = "813d76a46e8e191c02711faa4284573fa0f46db70f50f532f97d5563f3b8d0ee"; }
    { name = "nvidia-persistenced"; url = "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2604/x86_64/nvidia-persistenced_595.91.07-1ubuntu1_amd64.deb"; sha256 = "594c00e05780d1ddd90c6278764ba6d7f4761bbe85180a8e5871730cd894666d"; }
  ];

  inherit nvidiaCompute;
}
