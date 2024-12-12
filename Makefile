clean:
	rm -f tinfoilcvm*

build: clean
	mkosi

deps:
	sudo apt install -y ovmf qemu-system-x86 qemu-utils

gallery:
	az sig create \
		--resource-group TEST-CC \
		--gallery-name tinfoil_cvm_gallery \
		--location eastus2 \
		--publisher-uri https://tinfoil.sh \
		--publisher-email contact@tinfoil.sh \
		--public-name-prefix tinfoilcvm \
		--eula https://tinfoil.sh/terms-of-service \
		--permissions Community

console:
	sudo qemu-system-x86_64 \
		-m 2G \
		-drive file=tinfoilcvm,format=raw \
		-bios /usr/share/ovmf/OVMF.fd \
		-nographic
