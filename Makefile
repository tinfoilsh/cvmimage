clean:
	rm -f tinfoilcvm*

build: clean
	mkosi

console:
	sudo qemu-system-x86_64 \
		-m 2G \
		-drive file=tinfoilcvm,format=raw \
		-bios /usr/share/ovmf/OVMF.fd \
		-nographic
