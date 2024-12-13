clean:
	rm -f tinfoilcvm*

build: clean
	mkosi

console-bios:
	sudo qemu-system-x86_64 \
		-m 2G \
		-drive file=tinfoilcvm,format=raw \
		-bios /usr/share/ovmf/OVMF.fd \
		-nographic

measure:
	@MEASUREMENT=$$(sev-snp-measure \
		--mode snp \
		--vcpus=12 \
		--vcpu-type=EPYC-v4 \
		--ovmf OVMF.fd \
		--kernel tinfoilcvm.vmlinuz \
		--initrd tinfoilcvm.initrd) && \
	echo "{ \"measurement\": \"$$MEASUREMENT\" }"
