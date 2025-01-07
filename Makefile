all: clean build

clean:
	sudo rm -rf tinfoilcvm*

build:
	mkosi
	rm -f tinfoilcvm

run:
	sudo ~/AMDSEV-fork/usr/local/bin/qemu-system-x86_64 \
		-enable-kvm \
		-cpu EPYC-v4 \
		-machine q35 -smp 32,maxcpus=32 \
		-m 4096M,slots=5,maxmem=12288M \
		-no-reboot \
		-bios ~/edk2/Build/AmdSev/DEBUG_GCC5/FV/OVMF.fd \
		-drive file=./tinfoilcvm.raw,if=none,id=disk0,format=raw \
		-device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true \
		-device scsi-hd,drive=disk0 -machine memory-encryption=sev0,vmport=off \
		-object memory-backend-memfd,id=ram1,size=4096M,share=true,prealloc=false \
		-machine memory-backend=ram1 -object sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=5,kernel-hashes=on \
		-kernel ./tinfoilcvm.vmlinuz \
		-append "console=ttyS0 earlyprintk=serial root=/dev/sda2 tinfoil-image=llama3.2:1b" \
		-initrd ./tinfoilcvm.initrd \
		-netdev tap,id=net0,ifname=tap0,script=no,downscript=no -device virtio-net-pci,netdev=net0 \
		-nographic -monitor pty -monitor unix:monitor,server,nowait

measure:
	@MEASUREMENT=$$(sev-snp-measure \
		--mode snp \
		--vcpus=12 \
		--vcpu-type=EPYC-v4 \
		--ovmf ~/edk2/Build/AmdSev/DEBUG_GCC5/FV/OVMF.fd \
		--kernel tinfoilcvm.vmlinuz \
		--initrd tinfoilcvm.initrd) && \
	echo "{ \"measurement\": \"$$MEASUREMENT\" }"

build-ovmf:
	git clone https://github.com/tianocore/edk2 && cd edk2

	git checkout edk2-stable202411

	git apply edk2sev.patch

	git rm -rf UnitTestFrameworkPkg
	touch OvmfPkg/AmdSev/Grub/grub.efi

	git submodule update --init --recursive
	make -C BaseTools
	. ./edksetup.sh --reconfig
	nice build -q --cmd-len=64436 -DDEBUG_ON_SERIAL_PORT=TRUE -n 32 -t GCC5 -a X64 -p OvmfPkg/AmdSev/AmdSevX64.dsc

	ls -lah Build/AmdSev/DEBUG_GCC5/FV/OVMF.fd
