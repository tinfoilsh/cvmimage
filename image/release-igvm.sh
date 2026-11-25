#!/usr/bin/env bash
set -Eeuo pipefail

version="$1"
output="$2"
cpu_image="$3"
gpu_image="$4"
compiler="$5"
manifest_format=1
compiler_manifest_format=4
variants=(cpu gpu)
platforms=(snp tdx)

# A launch file with this flag on its measured command line boots the guest in
# debug mode. Its launch measurement differs from the production one, so a
# debug guest never verifies as the released runtime.
debug_flag="tinfoil-debug=on"

mkdir "$output"
sha256() { sha256sum "$1" | awk '{print $1}'; }

# compile builds one launch file from $image and checks the measurement the
# compiler claims for it.
compile() {
  local platform="$1" cmdline="$2" igvm="$3" claimed actual
  "$compiler" build --platform "$platform" \
    --kernel "$image/tinfoilcvm.vmlinuz" \
    --initramfs "$image/tinfoilcvm.initrd" \
    --cmdline "$cmdline" --output "$igvm"
  jq -e --argjson format "$compiler_manifest_format" \
    '.format_version == $format' "$igvm.manifest.json" > /dev/null
  if [ "$platform" = snp ]; then
    claimed="$(jq -er '.expected_snp_measurement' "$igvm.manifest.json")"
    jq -e '.launch.measurement == .expected_snp_measurement and .launch.policy == .guest_policy' \
      "$igvm.manifest.json" > /dev/null
  else
    claimed="$(jq -er '.expected_mrtd' "$igvm.manifest.json")"
    jq -e '.launch.mrtd == .expected_mrtd' "$igvm.manifest.json" > /dev/null
  fi
  actual="$("$compiler" measure "$igvm" | awk -F': ' 'NR==2 {print $2}')"
  if [[ ! "$claimed" =~ ^[0-9a-f]{96}$ ]] || [ "$claimed" != "$actual" ]; then
    echo "$igvm launch measurement mismatch" >&2
    exit 1
  fi
}

# measured_cmdline prints the command line cvmc measured into both platforms'
# launch files. cvmc appends no5lvl; publish what it actually measured.
measured_cmdline() {
  local snp="$1" tdx="$2" roothash="$3" cmdline
  cmdline="$(jq -er '.command_line' "$snp.manifest.json")" || exit 1
  if [ "$cmdline" != "$(jq -er '.command_line' "$tdx.manifest.json")" ]; then
    echo "$snp and $tdx measured different command lines" >&2
    exit 1
  fi
  case " $cmdline " in
    *" roothash=$roothash "*) ;;
    *) echo "$snp measured command line is missing its root hash" >&2; exit 1 ;;
  esac
  printf '%s' "$cmdline"
}

for variant in "${variants[@]}"; do
  image="$cpu_image"
  artifact_version="$version"
  if [ "$variant" = gpu ]; then
    image="$gpu_image"
    artifact_version="${version}+gpu"
  fi
  roothash="$(tr -d '\n' < "$image/tinfoilcvm.roothash")"
  cmdline="root=/dev/mapper/root roothash=$roothash pci=nocrs pcie_ports=compat"
  for platform in "${platforms[@]}"; do
    compile "$platform" "$cmdline" "$output/tinfoil-${platform}-${artifact_version}.igvm"
    compile "$platform" "$cmdline $debug_flag" "$output/tinfoil-${platform}-${artifact_version}-debug.igvm"
  done

  snp="$output/tinfoil-snp-${artifact_version}.igvm"
  tdx="$output/tinfoil-tdx-${artifact_version}.igvm"
  snp_debug="$output/tinfoil-snp-${artifact_version}-debug.igvm"
  tdx_debug="$output/tinfoil-tdx-${artifact_version}-debug.igvm"
  release_cmdline="$(measured_cmdline "$snp" "$tdx" "$roothash")"
  debug_cmdline="$(measured_cmdline "$snp_debug" "$tdx_debug" "$roothash")"
  case " $release_cmdline " in
    *" $debug_flag "*) echo "$variant release command line enables debug mode" >&2; exit 1 ;;
  esac
  case " $debug_cmdline " in
    *" $debug_flag "*) ;;
    *) echo "$variant debug command line does not enable debug mode" >&2; exit 1 ;;
  esac

  jq -n \
    --arg version "$artifact_version" --argjson format "$manifest_format" \
    --arg root "$roothash" \
    --arg initrd "$(sha256 "$image/tinfoilcvm.initrd")" \
    --arg kernel "$(sha256 "$image/tinfoilcvm.vmlinuz")" \
    --arg raw "$(sha256 "$image/tinfoilcvm.raw")" \
    --arg snp "$(sha256 "$snp")" --arg tdx "$(sha256 "$tdx")" \
    --arg cmdline "$release_cmdline" \
    --argjson snp_launch "$(jq -c '.launch | {measurement}' "$snp.manifest.json")" \
    --argjson tdx_launch "$(jq -c '.launch | {mrtd, rtmr0, rtmr1, rtmr2, rtmr3}' "$tdx.manifest.json")" \
    --arg snp_debug "$(sha256 "$snp_debug")" --arg tdx_debug "$(sha256 "$tdx_debug")" \
    --arg debug_cmdline "$debug_cmdline" \
    --argjson snp_debug_launch "$(jq -c '.launch | {measurement}' "$snp_debug.manifest.json")" \
    --argjson tdx_debug_launch "$(jq -c '.launch | {mrtd, rtmr0, rtmr1, rtmr2, rtmr3}' "$tdx_debug.manifest.json")" \
    '{version: $version, root: $root, initrd: $initrd, kernel: $kernel, raw: $raw,
      igvm: {format_version: $format, snp: $snp, tdx: $tdx,
        snp_launch: $snp_launch, tdx_launch: $tdx_launch, cmdline: $cmdline,
        debug: {snp: $snp_debug, tdx: $tdx_debug,
          snp_launch: $snp_debug_launch, tdx_launch: $tdx_debug_launch, cmdline: $debug_cmdline}}}' \
    > "$output/tinfoil-inference-${artifact_version}-manifest.json"
  for extension in initrd vmlinuz raw; do
    cp "$image/tinfoilcvm.$extension" "$output/tinfoil-inference-${artifact_version}.$extension"
  done
done

cp "$compiler" "$output/cvmc-${version}"
(cd "$output" && sha256sum ./* > "tinfoil-inference-${version}-checksums.sha256")
