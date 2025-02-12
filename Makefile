cmdline = "readonly=on console=ttyS0 earlyprintk=serial root=/dev/sda2 tinfoil-debug=on tinfoil-config-hash=$(shell sha256sum config.yml | cut -d ' ' -f 1)"

memory = 2048M

all: clean build

hash:
	objcopy -O binary --only-section .cmdline tinfoilcvm.efi /dev/stdout

clean:
	sudo rm -rf tinfoilcvm.*

build:
	mkosi
	rm -f tinfoilcvm

run:
	stty intr ^]
	sudo ~/qemu/build/qemu-system-x86_64 \
		-enable-kvm \
		-cpu EPYC-v4 \
		-machine q35 -smp 32,maxcpus=32 \
		-m $(memory) \
		-no-reboot \
		-bios /home/ubuntu/cvmimage/OVMF.fd \
		-kernel ./tinfoilcvm.vmlinuz \
		-initrd ./tinfoilcvm.initrd \
		-append $(cmdline) \
		-drive file=./tinfoilcvm.raw,if=none,id=disk0,format=raw,readonly=on \
		-device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true \
		-device scsi-hd,drive=disk0 \
		-machine memory-encryption=sev0,vmport=off \
		-object memory-backend-memfd,id=ram1,size=$(memory),share=true,prealloc=false \
		-machine memory-backend=ram1 -object sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=5,kernel-hashes=on \
		-net nic,model=e1000 -net user,hostfwd=tcp::8444-:443 \
		-nographic -monitor pty -monitor unix:monitor,server,nowait
	stty intr ^c

measure:
	@MEASUREMENT=$$(sev-snp-measure \
		--mode snp \
		--vcpus=32 \
		--vcpu-type=EPYC-v4 \
		--append=$(cmdline) \
		--ovmf ./OVMF.fd \
		--kernel tinfoilcvm.vmlinuz \
		--initrd tinfoilcvm.initrd) && \
	echo "{ \"measurement\": \"$$MEASUREMENT\" }"
