#!/bin/sh
set -eu
command -v qemu-system-x86_64 >/dev/null || { echo 'SKIP: qemu-system-x86_64 unavailable'; exit 77; }
scratch=$(mktemp -d /tmp/tinfoil-volume-vm.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
disk="$scratch/owned-scratch.raw"
disk_size=256M
vm_memory=1024
vm_timeout=300
truncate -s "$disk_size" "$disk"
for stage in initialize reopen; do
    echo "Starting isolated TCG VM: $stage"
    timeout "$vm_timeout" qemu-system-x86_64 \
        -machine q35 -accel tcg -cpu max -m "$vm_memory" -smp 2 \
        -nodefaults -no-reboot -display none -serial stdio -monitor none -nic none \
        -kernel /fixture/vmlinuz -initrd /fixture/initramfs.gz \
        -append "console=ttyS0 quiet panic=-1 tinfoil-volume-fixture=1 volume_stage=$stage" \
        -blockdev "driver=file,node-name=scratch-file,filename=$disk" \
        -blockdev driver=raw,node-name=scratch,file=scratch-file \
        -device virtio-blk-pci,drive=scratch,disable-legacy=on,addr=0x7,serial=tinfoil-volume1 \
        > "$scratch/$stage.log" 2>&1 || { cat "$scratch/$stage.log"; exit 1; }
    cat "$scratch/$stage.log"
    if grep -q '^VOLUME_FIXTURE_RESULT=77' "$scratch/$stage.log"; then exit 77; fi
    grep -q '^VOLUME_FIXTURE_RESULT=0' "$scratch/$stage.log"
    grep -q '^--- PASS: TestVolumeVM' "$scratch/$stage.log"
    sha256sum "$disk"
done
