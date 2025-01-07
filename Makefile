all: clean build

clean:
	sudo rm -rf tinfoilcvm*

build:
	mkosi
	rm -f tinfoilcvm

run:
	stty intr ^]
	sudo ~/AMDSEV-fork/usr/local/bin/qemu-system-x86_64 \
		-enable-kvm \
		-cpu EPYC-v4 \
		-machine q35 -smp 32,maxcpus=32 \
		-m 4096M,slots=5,maxmem=12288M \
		-no-reboot \
		-bios ~/OVMF.fd \
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
	stty intr ^c

measure:
	@MEASUREMENT=$$(sev-snp-measure \
		--mode snp \
		--vcpus=32 \
		--vcpu-type=EPYC-v4 \
		--append="console=ttyS0 earlyprintk=serial root=/dev/sda2 tinfoil-image=llama3.2:1b" \
		--ovmf ~/OVMF.fd \
		--kernel tinfoilcvm.vmlinuz \
		--initrd tinfoilcvm.initrd) && \
	echo "{ \"measurement\": \"$$MEASUREMENT\" }"
