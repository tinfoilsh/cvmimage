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

ovmf:
	rm -rf amdsev && git clone https://github.com/amdese/amdsev -b snp-latest

	sudo ln -s /usr/bin/python3 /usr/bin/python || true

	sed -i 's/OvmfPkgX64.dsc/AmdSev\/AmdSevX64.dsc/' amdsev/common.sh
	sed -i 's/.*run_cmd cp -f Build\/OvmfX64\/DEBUG_.*//g' amdsev/common.sh

	sed -i '/git submodule update --init --recursive/i\git rm -rf UnitTestFrameworkPkg' amdsev/common.sh

	# https://github.com/kata-containers/kata-containers/blob/CCv0/tools/packaging/static-build/ovmf/build-ovmf.sh#L54
	sed -i '/git submodule update --init --recursive/i\touch OvmfPkg/AmdSev/Grub/grub.efi' amdsev/common.sh

	cd amdsev && ./build.sh ovmf

	mv amdsev/ovmf/Build/AmdSev/DEBUG_GCC5/FV/OVMF.fd .

measure:
	@MEASUREMENT=$$(sev-snp-measure \
		--mode snp \
		--vcpus=12 \
		--vcpu-type=EPYC-v4 \
		--ovmf OVMF.fd \
		--kernel tinfoilcvm.vmlinuz \
		--initrd tinfoilcvm.initrd) && \
	echo "{ \"amd-sev-snp-measurement\": \"$$MEASUREMENT\" }"
