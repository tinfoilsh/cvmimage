cmdline = "readonly=on console=ttyS0 earlyprintk=serial root=/dev/sda2 tinfoil-debug=on tinfoil-config-hash=$(shell sha256sum config.yml | cut -d ' ' -f 1)"

memory = 4096M
cpus = 32

# Default profile (can be overridden: make build PROFILE=single-gpu)
PROFILE ?= multi-gpu
OUTPUT_NAME = tinfoilcvm-$(PROFILE)

all: clean build

hash:
	objcopy -O binary --only-section .cmdline $(OUTPUT_NAME).efi /dev/stdout

clean:
	sudo rm -rf tinfoilcvm-*.* tinfoilcvm.*

build:
	mkosi --profile=$(PROFILE)
	rm -f tinfoilcvm tinfoilcvm-*[!.]*[!a-z]

build-single-gpu:
	$(MAKE) build PROFILE=single-gpu

build-multi-gpu:
	$(MAKE) build PROFILE=multi-gpu

run:
	stty intr ^]
	sudo ~/qemu/build/qemu-system-x86_64 \
		-enable-kvm \
		-cpu EPYC-v4 \
		-machine q35 -smp $(cpus),maxcpus=$(cpus) \
		-m $(memory) \
		-no-reboot \
		-bios /home/ubuntu/cvmimage/OVMF.fd \
		-kernel ./$(OUTPUT_NAME).vmlinuz \
		-initrd ./$(OUTPUT_NAME).initrd \
		-append $(cmdline) \
		-drive file=./$(OUTPUT_NAME).raw,if=none,id=disk0,format=raw,readonly=on \
		-device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true \
		-device scsi-hd,drive=disk0 \
		-drive file=config.yml,if=none,id=disk1,format=raw,readonly=on \
		-device virtio-scsi-pci,id=scsi1,disable-legacy=on,iommu_platform=true \
		-device scsi-hd,drive=disk1 \
		-machine memory-encryption=sev0,vmport=off \
		-object memory-backend-memfd,id=ram1,size=$(memory),share=true,prealloc=false \
		-machine memory-backend=ram1 -object sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=5,kernel-hashes=on \
		-net nic,model=e1000 -net user,hostfwd=tcp::8444-:443 \
		-nographic -monitor pty -monitor unix:monitor,server,nowait
	stty intr ^c

# -drive file=~/models/qwen-0.5b.mpk,if=none,id=disk2,format=raw,readonly=on \
# -device virtio-scsi-pci,id=scsi2,disable-legacy=on,iommu_platform=true \
# -device scsi-hd,drive=disk2 \
# -machine memory-encryption=sev0,vmport=off \

measure:
	@MEASUREMENT=$$(sev-snp-measure \
		--mode snp \
		--vcpus=$(cpus) \
		--vcpu-type=EPYC-v4 \
		--append=$(cmdline) \
		--ovmf ./OVMF.fd \
		--kernel $(OUTPUT_NAME).vmlinuz \
		--initrd $(OUTPUT_NAME).initrd) && \
	echo "{ \"measurement\": \"$$MEASUREMENT\" }"
