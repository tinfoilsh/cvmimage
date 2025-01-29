cmdline = "console=ttyS0 root=/dev/sda2 earlyprintk=serial tinfoil-model=deepseek-r1:70b tinfoil-domain=six.delta.tinfoil.sh"
gpu = "01:00.0"
memory = 66000M

all: clean build

clean:
	sudo rm -rf tinfoilcvm.*

build:
	mkosi
	rm -f tinfoilcvm

run:
	sudo python3 /shared/nvtrust/host_tools/python/gpu-admin-tools/nvidia_gpu_tools.py --gpu-bdf $(gpu) --set-cc-mode=on --reset-after-cc-mode-switch
	sudo python3 /shared/nvtrust/host_tools/python/gpu-admin-tools/nvidia_gpu_tools.py --gpu-bdf $(gpu) --query-cc-mode
	stty intr ^]
	sudo ~/qemu/build/qemu-system-x86_64 \
		-enable-kvm \
		-cpu EPYC-v4 \
		-machine q35 -smp 32,maxcpus=32 \
		-m $(memory) \
		-no-reboot \
		-bios ./OVMF.fd \
		-drive file=./tinfoilcvm.raw,if=none,id=disk0,format=raw \
		-device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true \
		-device scsi-hd,drive=disk0 -machine memory-encryption=sev0,vmport=off \
		-object memory-backend-memfd,id=ram1,size=$(memory),share=true,prealloc=false \
		-machine memory-backend=ram1 -object sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=5,kernel-hashes=on \
		-kernel ./tinfoilcvm.vmlinuz \
		-initrd ./tinfoilcvm.initrd \
		-append $(cmdline) \
		-net nic,model=e1000 -net user,hostfwd=tcp::2222-:22,hostfwd=tcp::8443-:443 \
		-nographic -monitor pty -monitor unix:monitor,server,nowait \
		-device pcie-root-port,id=pci.1,bus=pcie.0 \
		-device vfio-pci,host=$(gpu),bus=pci.1 \
		-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=262144
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
