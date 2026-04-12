#!/bin/bash
# Check available versions for packages from all repos
# Reads packages from mkosi.conf and looks them up in Ubuntu + third-party repos

set -euo pipefail

UBUNTU_CODENAME="resolute"     # Ubuntu release codename (resolute, noble, jammy, etc.)
UBUNTU_VERSION="ubuntu2604"    # For NVIDIA repos (ubuntu2604, ubuntu2404, etc.)
ARCH="amd64"                   # Target architecture

MKOSI_CONF="${1:-mkosi.conf}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Compare versions: returns 0 if $1 < $2
version_lt() {
    [ "$(echo -e "$1\n$2" | sort -V | head -1)" = "$1" ] && [ "$1" != "$2" ]
}

# Create temp directory for package lists
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "=== Fetching package lists for $UBUNTU_CODENAME ($UBUNTU_VERSION) ==="
echo ""

# Fetch Ubuntu repos to temp files (covered by snapshot)
echo -n "Fetching Ubuntu repos..."
curl -sL "https://archive.ubuntu.com/ubuntu/dists/${UBUNTU_CODENAME}/main/binary-${ARCH}/Packages.gz" | gunzip - >> "$TMPDIR/ubuntu" 2>/dev/null || true
curl -sL "https://archive.ubuntu.com/ubuntu/dists/${UBUNTU_CODENAME}/restricted/binary-${ARCH}/Packages.gz" | gunzip - >> "$TMPDIR/ubuntu" 2>/dev/null || true
curl -sL "https://archive.ubuntu.com/ubuntu/dists/${UBUNTU_CODENAME}/universe/binary-${ARCH}/Packages.gz" | gunzip - >> "$TMPDIR/ubuntu" 2>/dev/null || true
curl -sL "https://archive.ubuntu.com/ubuntu/dists/${UBUNTU_CODENAME}-updates/main/binary-${ARCH}/Packages.gz" | gunzip - >> "$TMPDIR/ubuntu" 2>/dev/null || true
curl -sL "https://archive.ubuntu.com/ubuntu/dists/${UBUNTU_CODENAME}-updates/restricted/binary-${ARCH}/Packages.gz" | gunzip - >> "$TMPDIR/ubuntu" 2>/dev/null || true
curl -sL "https://archive.ubuntu.com/ubuntu/dists/${UBUNTU_CODENAME}-updates/universe/binary-${ARCH}/Packages.gz" | gunzip - >> "$TMPDIR/ubuntu" 2>/dev/null || true
echo " done"

# Fetch third-party repos to temp files (NOT covered by snapshot)
echo -n "Fetching NVIDIA CUDA repo..."
curl -sL "https://developer.download.nvidia.com/compute/cuda/repos/${UBUNTU_VERSION}/x86_64/Packages.gz" | gunzip - > "$TMPDIR/nvidia_cuda"
echo " done"

echo -n "Fetching Docker repo..."
curl -sL "https://download.docker.com/linux/ubuntu/dists/${UBUNTU_CODENAME}/stable/binary-${ARCH}/Packages" > "$TMPDIR/docker"
echo " done"

echo -n "Fetching NVIDIA Container Toolkit repo..."
curl -sL "https://nvidia.github.io/libnvidia-container/stable/deb/${ARCH}/Packages" > "$TMPDIR/nvidia_container"
echo " done"

echo ""

# Helper function to get versions from Packages file (reads from temp file)
get_versions() {
    local file="$1"
    local pkg_name="$2"
    awk -v pkg="$pkg_name" '
        /^Package: / { current_pkg = $2 }
        /^Version: / && current_pkg == pkg { print $2 }
    ' "$file" | sort -V | uniq
}

# Check package in all repos and report
lookup_package() {
    local pkg_name="$1"
    local current_version="$2"
    
    # Check if this is a third-party package (by name pattern)
    local is_third_party=false
    if [[ "$pkg_name" =~ ^(cuda-|nvidia-|libnvidia-|nvattest|libnvat) ]]; then
        is_third_party=true
    elif [[ "$pkg_name" =~ ^(docker-|containerd) ]]; then
        is_third_party=true
    fi
    
    # Only treat as Ubuntu snapshot if NOT a third-party package
    if [ "$is_third_party" = false ] && [[ "$current_version" =~ ubuntu ]]; then
        echo -e "  ${GREEN}$pkg_name=$current_version${NC} (Ubuntu - covered by snapshot)"
        return 0
    fi
    
    # Check Ubuntu repos (only for non-third-party packages)
    if [ "$is_third_party" = false ]; then
        ubuntu_versions=$(get_versions "$TMPDIR/ubuntu" "$pkg_name")
        if [ -n "$ubuntu_versions" ]; then
            latest=$(echo "$ubuntu_versions" | tail -1)
            if [ -n "$current_version" ]; then
                if echo "$ubuntu_versions" | grep -qx "$current_version"; then
                    echo -e "  ${GREEN}$pkg_name=$current_version${NC} (Ubuntu - covered by snapshot)"
                else
                    echo -e "  ${RED}$pkg_name=$current_version${NC} (Ubuntu - version NOT FOUND)"
                    echo "    Available: $(echo "$ubuntu_versions" | tr '\n' ' ')"
                fi
            else
                echo -e "  ${GREEN}$pkg_name${NC} (Ubuntu - covered by snapshot)"
            fi
            return 0
        fi
    fi
    
    # Check all third-party repos, try each until we find the package
    local versions=""
    local repo=""
    
    local -a repo_names=("NVIDIA CUDA" "NVIDIA Container" "Docker")
    local -a repo_files=("$TMPDIR/nvidia_cuda" "$TMPDIR/nvidia_container" "$TMPDIR/docker")
    
    for i in "${!repo_names[@]}"; do
        versions=$(get_versions "${repo_files[$i]}" "$pkg_name")
        if [ -n "$versions" ]; then
            repo="${repo_names[$i]}"
            break
        fi
    done
    
    if [ -z "$versions" ]; then
        echo -e "  ${RED}$pkg_name${NC} (NOT FOUND in any repo)"
        return 0
    fi
    
    latest=$(echo "$versions" | tail -1)
    
    if [ -n "$current_version" ]; then
        if echo "$versions" | grep -qx "$current_version"; then
            # For NVIDIA, only compare within same driver series (e.g., 580.x.x)
            local compare_latest="$latest"
            if [[ "$repo" =~ ^NVIDIA ]] && [[ "$current_version" =~ ^([0-9]+)\. ]]; then
                local series="${BASH_REMATCH[1]}"
                local series_versions=$(echo "$versions" | grep "^${series}\." || true)
                if [ -n "$series_versions" ]; then
                    compare_latest=$(echo "$series_versions" | tail -1)
                fi
            fi
            # Check if newer version available
            if version_lt "$current_version" "$compare_latest"; then
                echo -e "  ${YELLOW}$pkg_name=$current_version${NC} ($repo - newer available: $compare_latest)"
            else
                echo -e "  ${GREEN}$pkg_name=$current_version${NC} ($repo - pinned)"
            fi
        else
            echo -e "  ${RED}$pkg_name=$current_version${NC} ($repo - version NOT FOUND)"
            echo "    Available: $(echo "$versions" | tr '\n' ' ')"
        fi
    else
        echo -e "  ${RED}$pkg_name${NC} ($repo - UNPINNED, pin to: $latest)"
    fi
}

echo "=== Checking packages from $MKOSI_CONF ==="
echo ""

# Extract packages from mkosi.conf (in Packages= section)
in_packages=false
while IFS= read -r line; do
    if [[ "$line" =~ ^Packages= ]]; then
        in_packages=true
        continue
    fi
    
    if [[ "$line" =~ ^\[.*\] ]]; then
        in_packages=false
        continue
    fi
    
    if [ "$in_packages" = false ]; then
        continue
    fi
    
    line=$(echo "$line" | sed 's/^\s*//' | sed 's/\s*$//')
    if [ -z "$line" ] || [[ "$line" =~ ^# ]]; then
        continue
    fi
    
    if [[ "$line" =~ = ]]; then
        pkg_name=$(echo "$line" | cut -d'=' -f1)
        pkg_version=$(echo "$line" | cut -d'=' -f2)
    else
        pkg_name="$line"
        pkg_version=""
    fi
    
    lookup_package "$pkg_name" "$pkg_version" 2>/dev/null || true
    
done < "$MKOSI_CONF"

echo ""
echo "=== Done ==="
