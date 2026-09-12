#!/usr/bin/env python3
"""Run real encrypted-volume tests in a disposable VM using temporary disk files."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--legacy-worker', help='optional static volumeworker binary from ../cvmimage')
parser.add_argument('--kernel', required=True, help='kernel with the shared storage fragment enabled')
parser.add_argument('--qemu', default='qemu-system-x86_64')
parser.add_argument('--go', default='go')
parser.add_argument('--mkfs-ext4', default='mkfs.ext4')
parser.add_argument('--rootfs-archive', help='use mkfs and its libraries from a built guest rootfs tar')
parser.add_argument('--mkfs-erofs', default='mkfs.erofs')
parser.add_argument('--veritysetup', default='veritysetup')
parser.add_argument('--sgdisk', default='sgdisk')
args = parser.parse_args()
repo = Path(__file__).resolve().parent.parent

def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)

def copy_binary(binary, root):
    binary = Path(shutil.which(binary) or binary).resolve()
    paths = {str(binary)}
    result = subprocess.run(['ldd', str(binary)], capture_output=True, text=True)
    paths.update(re.findall(r'(/[^\s()]+)', result.stdout))
    for path in paths:
        destination = root / path.lstrip('/')
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
    return binary

def copy_guest_formatter(archive, root):
    exact = {'etc/mke2fs.conf', 'usr/sbin/mke2fs', 'usr/sbin/mkfs.ext4', 'lib64'}
    with tarfile.open(archive) as source:
        for member in source:
            name = member.name.removeprefix('./')
            library = any(name.startswith(prefix) and '/' not in name[len(prefix):]
                          for prefix in ('usr/lib/x86_64-linux-gnu/', 'usr/lib64/'))
            if name not in exact and not (library and '.so' in Path(name).name):
                continue
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                target.symlink_to(member.linkname)
            elif member.isfile() or member.islnk():
                with source.extractfile(member) as data:
                    target.write_bytes(data.read())
                target.chmod(member.mode)

with tempfile.TemporaryDirectory(prefix='tinfoil-storage-vm-') as temp:
    temp = Path(temp)
    root = temp / 'initramfs'
    for directory in ['bin', 'dev', 'proc', 'sys', 'tmp', 'run', 'usr/bin', 'usr/sbin', 'etc']:
        (root / directory).mkdir(parents=True, exist_ok=True)
    if args.legacy_worker:
        shutil.copy2(args.legacy_worker, root / 'legacy-worker')
    if args.rootfs_archive:
        copy_guest_formatter(args.rootfs_archive, root)
    else:
        ext4 = copy_binary(args.mkfs_ext4, root)
        (root / 'usr/sbin/mkfs.ext4').symlink_to(ext4)
    run([args.go, 'test', '-c', '-tags=storageintegration', '-o', str(root / 'init'), './internal/volume'],
        cwd=repo / 'tinfoil', env={**os.environ, 'GOWORK': 'off', 'CGO_ENABLED': '0'})
    run([args.go, 'build', '-o', str(root / 'usr/bin/tinfoil-volumes'), './cmd/volumes'],
        cwd=repo / 'tinfoil', env={**os.environ, 'GOWORK': 'off', 'CGO_ENABLED': '0'})
    # The modelwrap packer builds both fixtures with the supplied host tools.
    tool_dir = temp / 'tools'
    tool_dir.mkdir()
    for name, binary in [('mkfs.erofs', args.mkfs_erofs), ('veritysetup', args.veritysetup), ('sgdisk', args.sgdisk)]:
        (tool_dir / name).symlink_to(Path(shutil.which(binary) or binary).resolve())
    run([str(root / 'init'), '--make-test-packs', str(temp)],
        env={**os.environ, 'PATH': str(tool_dir) + os.pathsep + os.environ.get('PATH', '')})
    packs = json.loads((root / 'packs.json').read_text())
    # Build newc directly, without requiring host cpio or special device nodes.
    import stat
    with (temp / 'initrd').open('wb') as archive:
        def entry(name, mode, contents, inode, major=0, minor=0):
            fields = [inode, mode, 0, 0, 1, 0, len(contents), 0, 0, major, minor, len(name.encode()) + 1, 0]
            header = b'070701' + ''.join(f'{v:08x}' for v in fields).encode()
            record = header + name.encode() + b'\0'
            archive.write(record + b'\0' * (-len(record) % 4))
            archive.write(contents + b'\0' * (-len(contents) % 4))
        for inode, path in enumerate(sorted(root.rglob('*')), 1):
            mode = path.lstat().st_mode
            data = os.readlink(path).encode() if stat.S_ISLNK(mode) else path.read_bytes() if path.is_file() else b''
            entry(str(path.relative_to(root)), mode, data, inode)
        entry('dev/console', stat.S_IFCHR | 0o600, b'', 1000000, 5, 1)
        entry('TRAILER!!!', 0, b'', 0)
    with (temp / 'state.raw').open('wb') as disk:
        disk.truncate(256 * 1024 * 1024)
    with (temp / 'legacy.raw').open('wb') as disk:
        disk.truncate(256 * 1024 * 1024)
    result = run([args.qemu, '-machine', 'q35,accel=kvm', '-cpu', 'host', '-m', '512', '-smp', '2',
                  '-nographic', '-no-reboot', '-nodefaults', '-serial', 'none', '-monitor', 'none',
                  '-chardev', 'stdio,id=console', '-device', 'virtio-serial-pci', '-device', 'virtconsole,chardev=console',
                  '-kernel', args.kernel, '-initrd', str(temp / 'initrd'),
                  '-append', 'console=hvc0 panic=-1 tinfoil.storage-test=1',
                  '-drive', f'file={packs[0]["Image"]},format=raw,if=none,id=lower,readonly=on',
                  '-device', 'virtio-blk-pci,drive=lower,addr=0x7,disable-legacy=on,serial=tinfoil-modelwrap1',
                  '-drive', f'file={packs[1]["Image"]},format=raw,if=none,id=encrypted,readonly=on',
                  '-device', 'virtio-blk-pci,drive=encrypted,addr=0x8,disable-legacy=on,serial=tinfoil-modelwrap2',
                  '-drive', f'file={temp}/state.raw,format=raw,if=none,id=state',
                  '-device', 'virtio-blk-pci,drive=state,addr=0x9,disable-legacy=on,serial=tinfoil-volume1',
                  '-drive', f'file={temp}/legacy.raw,format=raw,if=none,id=legacy',
                  '-device', 'virtio-blk-pci,drive=legacy,addr=0xa,disable-legacy=on,serial=tinfoil-volume2'],
                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
    print(result.stdout)
    if 'STORAGE_TEST_EXIT=0' not in result.stdout or '--- PASS: TestStorageVM' not in result.stdout:
        raise SystemExit('storage VM tests failed')
