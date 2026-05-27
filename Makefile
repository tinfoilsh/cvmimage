all: build

MKOSI = sudo env PATH="/root/.local/bin:$$PATH" mkosi

.PHONY: all build rebuild clean deepclean hash nvattest go-binaries

# tinfoilcvm.hash is written as an artifact of `build`; read it from there if
# present, otherwise extract the dm-verity roothash from the UKI's .cmdline
# section. grep -aoE finds the roothash= token regardless of position so the
# command stays correct even if mkosi adds other kv pairs to the cmdline.
hash:
	@if [ -f tinfoilcvm.hash ]; then \
	    cat tinfoilcvm.hash; \
	else \
	    objcopy -O binary --only-section .cmdline tinfoilcvm.efi /dev/stdout | grep -aoE 'roothash=[a-f0-9]+' | cut -d= -f2; \
	fi

clean:
	sudo rm -rf tinfoilcvm.*
	sudo rm -rf initrd
	sudo rm -rf initrd.cpio.zst

deepclean:
	$(MKOSI) clean
	sudo rm -rf mkosi.cache/*
	sudo rm -f packages/nvattest_*.deb packages/libnvat_*.deb

go-binaries:
	mkdir -p mkosi.extra/usr/bin
	cd tinfoil && go build -ldflags="-s -w" -o ../mkosi.extra/usr/bin/tinfoil-boot ./cmd/boot
	cd tinfoil && go build -ldflags="-s -w" -o ../mkosi.extra/usr/bin/tinfoil-egress ./cmd/egress
	cd tinfoil && go build -ldflags="-s -w" -o ../mkosi.extra/usr/bin/tinfoil-shim ./cmd/shim

# First build populates mkosi.cache; later builds reuse it for fast iteration.
rebuild: go-binaries
	mkdir -p mkosi.cache packages
	$(MKOSI) --force
	rm -f tinfoilcvm
	objcopy -O binary --only-section .cmdline tinfoilcvm.efi /dev/stdout | grep -aoE 'roothash=[a-f0-9]+' | cut -d= -f2 > tinfoilcvm.hash
	@echo "image hash: $$(cat tinfoilcvm.hash)"

build: nvattest rebuild

# TEMPORARY: drop once cuda-ubuntu2604 ships nvattest. See build-nvattest.sh.
nvattest: packages/nvattest_1.2.0.1772475102-1_amd64.deb

packages/nvattest_1.2.0.1772475102-1_amd64.deb: build-nvattest.sh
	docker run --rm \
		-v "$(CURDIR)":/workspace -w /workspace \
		-v nvattest-apt-cache:/var/cache/apt \
		-e DEBIAN_FRONTEND=noninteractive \
		-e HOST_UID="$${SUDO_UID:-$$(id -u)}" \
		-e HOST_GID="$${SUDO_GID:-$$(id -g)}" \
		ubuntu@sha256:5e275723f82c67e387ba9e3c24baa0abdcb268917f276a0561c97bef9450d0b4 \
		bash -c './build-nvattest.sh'

python-lockfile:
	pip-compile --generate-hashes --allow-unsafe --output-file=mkosi.extra/opt/venv-requirements.txt python-requirements.in
