deps:
	sudo apt install -y ovmf qemu-system-x86 qemu-utils

run:
	qemu-system-x86_64 \
		-m 512 \
		-smp 2 \
		-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
		-drive if=pflash,format=raw,file=/usr/share/OVMF/OVMF_VARS.fd \
		-drive format=raw,file=image.raw \
		-cpu host \
		-device virtio-net-pci,netdev=net0 \
		-netdev user,id=net0,hostfwd=tcp::2222-:22 \
		-nographic
