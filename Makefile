all: clean build

clean:
	sudo rm -rf tinfoilcvm*

build:
	mkosi
	rm -f tinfoilcvm

run-full:
	sudo ./launch-qemu.sh \
		-sev-snp \
		-kernel ../cvmimage/tinfoilcvm.vmlinuz \
		-initrd ../cvmimage/tinfoilcvm.initrd \
		-hda ../cvmimage/tinfoilcvm.raw \
		-mem 2048 \
		-append "console=ttyS0 root=/dev/sda2"

run-rd:
	sudo ./launch-qemu.sh \
		-sev-snp \
		-kernel ../cvmimage/tinfoilcvm.vmlinuz \
		-initrd ../cvmimage/tinfoilcvm.initrd \
		-append console=ttyS0 \
		-mem 2048

measure:
	@MEASUREMENT=$$(sev-snp-measure \
		--mode snp \
		--vcpus=12 \
		--vcpu-type=EPYC-v4 \
		--ovmf OVMF.fd \
		--kernel tinfoilcvm.vmlinuz \
		--initrd tinfoilcvm.initrd) && \
	echo "{ \"measurement\": \"$$MEASUREMENT\" }"
