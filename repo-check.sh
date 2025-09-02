#!/bin/bash

# Fetch NVIDIA package repository data
nvidia_packages=$(curl -sL https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/Packages.gz | gunzip -)

nvidia_pkgs_in_conf=$(grep -E "^\s*(nvidia-|cuda-)" mkosi.conf | sed 's/^\s*//' | grep -v "^#" | grep "=")

for pkg_line in $nvidia_pkgs_in_conf; do
    pkg_name=$(echo "$pkg_line" | cut -d'=' -f1)
    expected_version=$(echo "$pkg_line" | cut -d'=' -f2)
    echo "$pkg_name want $expected_version"
    
    available_versions=$(echo "$nvidia_packages" | grep -A 1 "^Package: $pkg_name$" | grep -v "^Package:" | grep -v "^--$" | sed 's/^Version: //')
    echo "$available_versions" | sed 's/^/    /'

    if echo "$available_versions" | grep -q "$expected_version"; then
        echo "    [+] Version found"
    else
        echo "    [!] Version not found"
    fi

    echo ""
done
