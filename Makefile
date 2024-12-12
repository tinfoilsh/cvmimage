deps:
	sudo apt install -y ovmf qemu-system-x86 qemu-utils

run:
	sudo qemu-system-x86_64 \
		-m 512 \
		-smp 2 \
		-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
		-drive if=pflash,format=raw,file=/usr/share/OVMF/OVMF_VARS.fd \
		-drive format=raw,file=image.raw \
		-device virtio-net-pci,netdev=net0 \
		-netdev user,id=net0,hostfwd=tcp::2222-:22 \
		-nographic

all:
	sudo mkosi -f --autologin --qemu-mem=1G qemu

run-uki:
	sudo qemu-system-x86_64 \
		-machine type=q35,accel=tcg,smm=off \
		-smp 2 \
		-m 1G \
		-object rng-random,filename=/dev/urandom,id=rng0 \
		-device virtio-rng-pci,rng=rng0,id=rng-device0 \
		-vga virtio \
		-drive if=none,id=hd,file=image.raw,format=raw \
		-device virtio-scsi-pci,id=scsi \
		-device scsi-hd,drive=hd,bootindex=1 \
		-nographic
