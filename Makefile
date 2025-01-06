all: clean build

clean:
	sudo rm -rf tinfoilcvm*

build:
	mkosi
	rm -f tinfoilcvm

run-plain:
	sudo ./launch-qemu.sh \
		-sev-snp \
		-kernel ../cvmimage/tinfoilcvm.vmlinuz \
		-initrd ../cvmimage/tinfoilcvm.initrd \
		-hda ../cvmimage/tinfoilcvm.raw \
		-mem 2048 \
		-append "console=ttyS0 root=/dev/sda2"

run-local:
	sudo ~/AMDSEV-fork/usr/local/bin/qemu-system-x86_64 \
		-enable-kvm \
		-smp 4 \
		-m 8G,slots=5,maxmem=10G \
		-cpu EPYC-v4 \
		-machine q35,confidential-guest-support=sev0,memory-backend=ram1 \
		-no-reboot \
		-bios ~/ovmf/Build/AmdSev/DEBUG_GCC5/FV/OVMF.fd \
		-drive file=./tinfoilcvm.raw,if=none,id=disk0,format=raw \
		-device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true \
		-device scsi-hd,drive=disk0 \
		-object memory-backend-memfd,id=ram1,size=8G,share=true,prealloc=false \
		-object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 \
		-nographic \
		-monitor pty \
		-monitor unix:monitor,server,nowait

measure:
	@MEASUREMENT=$$(sev-snp-measure \
		--mode snp \
		--vcpus=12 \
		--vcpu-type=EPYC-v4 \
		--ovmf OVMF.fd \
		--kernel tinfoilcvm.vmlinuz \
		--initrd tinfoilcvm.initrd) && \
	echo "{ \"measurement\": \"$$MEASUREMENT\" }"

build-ovmf:
	git clone https://github.com/tianocore/edk2 && cd edk2

	git checkout edk2-stable202411

	git rm -rf UnitTestFrameworkPkg
	touch OvmfPkg/AmdSev/Grub/grub.efi

	git submodule update --init --recursive
	make -C BaseTools
	. ./edksetup.sh --reconfig
	nice build -q --cmd-len=64436 -DDEBUG_ON_SERIAL_PORT=TRUE -n 32 -t GCC5 -a X64 -p OvmfPkg/AmdSev/AmdSevX64.dsc

	ls -lah Build/AmdSev/DEBUG_GCC5/FV/OVMF.fd
