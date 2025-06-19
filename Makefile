cmdline = "readonly=on console=ttyS0 earlyprintk=serial root=/dev/sda2 tinfoil-debug=on tinfoil-config-hash=$(shell sha256sum config.yml | cut -d ' ' -f 1)"

memory = 96536M
cpus = 4
# gpu = e1:00.0

all: clean build

hash:
	objcopy -O binary --only-section .cmdline tinfoilcvm.efi /dev/stdout

clean:
	sudo rm -rf tinfoilcvm.*

build:
	mkosi
	rm -f tinfoilcvm

run:
	# sudo python3 /shared/nvtrust/host_tools/python/gpu-admin-tools/nvidia_gpu_tools.py --gpu-bdf $(gpu) --set-cc-mode=on --reset-after-cc-mode-switch
	stty intr ^]
	sudo ~/qemu/build/qemu-system-x86_64 \
		-enable-kvm \
		-cpu EPYC-v4 \
		-machine q35 -smp $(cpus),maxcpus=$(cpus) \
		-m $(memory) \
		-no-reboot \
		-bios /opt/tinfoil/images/ovmf-v0.0.2.fd \
		-kernel ./tinfoilcvm.vmlinuz \
		-initrd ./tinfoilcvm.initrd \
		-append $(cmdline) \
		-drive file=./tinfoilcvm.raw,if=none,id=disk0,format=raw,readonly=on \
		-device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true \
		-device scsi-hd,drive=disk0 \
		-drive file=./config.yml,if=none,id=disk1,format=raw,readonly=on \
		-device virtio-scsi-pci,id=scsi1,disable-legacy=on,iommu_platform=true \
		-device scsi-hd,drive=disk1 \
		-machine memory-encryption=sev0,vmport=off \
		-object memory-backend-memfd,id=ram1,size=$(memory),share=true,prealloc=false \
		-machine memory-backend=ram1 -object sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=5,kernel-hashes=on \
		-net nic,model=e1000 -net user,hostfwd=tcp::8777-:443 \
		-nographic -monitor pty -monitor unix:monitor,server,nowait \
		-device pcie-root-port,id=pci.1,bus=pcie.0 \
		-device vfio-pci,host=$(gpu),bus=pci.1 \
		-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=262144

		
	stty intr ^c

		# 	-drive file=/opt/tinfoil/hfmodels/casperhansen/llama-3.3-70b-instruct-awq/64d255621f40b42adaf6d1f32a47e1d4534c0f14.mpk,if=none,id=disk2,format=raw,readonly=on \
		# -device virtio-scsi-pci,id=scsi2,disable-legacy=on,iommu_platform=true \
		# -device scsi-hd,drive=disk2 \


run-cpu:
	stty intr ^]
	sudo ~/qemu/build/qemu-system-x86_64 \
		-enable-kvm \
		-cpu EPYC-v4 \
		-machine q35 -smp $(cpus),maxcpus=$(cpus) \
		-m $(memory) \
		-no-reboot \
		-bios /opt/tinfoil/images/ovmf-v0.0.2.fd \
		-kernel ./tinfoilcvm.vmlinuz \
		-initrd ./tinfoilcvm.initrd \
		-append $(cmdline) \`
		-drive file=./tinfoilcvm.raw,if=none,id=disk0,format=raw,readonly=on \
		-device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true \
		-device scsi-hd,drive=disk0 \
		-drive file=./config.yml,if=none,id=disk1,format=raw,readonly=on \
		-device virtio-scsi-pci,id=scsi1,disable-legacy=on,iommu_platform=true \
		-device scsi-hd,drive=disk1 \
		-machine memory-encryption=sev0,vmport=off \
		-object memory-backend-memfd,id=ram1,size=$(memory),share=true,prealloc=false \
		-machine memory-backend=ram1 -object sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=5,kernel-hashes=on \
		-net nic,model=e1000 -net user,hostfwd=tcp::8777-:443 \
		-nographic -monitor pty -monitor unix:monitor,server,nowait
	stty intr ^c

measure:
	@MEASUREMENT=$$(sev-snp-measure \
		--mode snp \
		--vcpus=$(cpus) \
		--vcpu-type=EPYC-v4 \
		--append=$(cmdline) \
		--ovmf ./OVMF.fd \
		--kernel tinfoilcvm.vmlinuz \
		--initrd tinfoilcvm.initrd) && \
	echo "{ \"measurement\": \"$$MEASUREMENT\" }"


acpi-measure:
	sudo ~/qemu/build/qemu-system-x86_64 \
		-enable-kvm \
		-cpu EPYC-v4 \
		-machine q35 -smp $(cpus),maxcpus=$(cpus) \
		-m $(memory) \
		-no-reboot \
		-bios /opt/tinfoil/images/ovmf-v0.0.2.fd \
		-kernel ./tinfoilcvm.vmlinuz \
		-initrd ./tinfoilcvm.initrd \
		-append "init=/bin/bash acpi.debug_level=0x10" \
		-drive file=./tinfoilcvm.raw,if=none,id=disk0,format=raw,readonly=on \
		-device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true \
		-device scsi-hd,drive=disk0 \
		-drive file=./config.yml,if=none,id=disk1,format=raw,readonly=on \
		-device virtio-scsi-pci,id=scsi1,disable-legacy=on,iommu_platform=true \
		-device scsi-hd,drive=disk1 \
		-machine memory-encryption=sev0,vmport=off \
		-object memory-backend-memfd,id=ram1,size=$(memory),share=true,prealloc=false \
		-machine memory-backend=ram1 -object sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=5,kernel-hashes=on \
		-net nic,model=e1000 -net user,hostfwd=tcp::8777-:443 \
		-nographic -monitor pty -monitor unix:monitor,server,nowait \
		-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=262144
