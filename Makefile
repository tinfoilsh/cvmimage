all: build

MKOSI = sudo env PATH="/root/.local/bin:$$PATH" mkosi

.PHONY: all build rebuild clean deepclean hash go-binaries

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

go-binaries:
	mkdir -p mkosi.extra/usr/bin
	cd tinfoil && go build -ldflags="-s -w" -o ../mkosi.extra/usr/bin/tinfoil-boot ./cmd/boot
	cd tinfoil && go build -ldflags="-s -w" -o ../mkosi.extra/usr/bin/tinfoil-container-status ./cmd/container-status
	cd tinfoil && go build -ldflags="-s -w" -o ../mkosi.extra/usr/bin/tinfoil-egress ./cmd/egress
	cd tinfoil && go build -ldflags="-s -w" -o ../mkosi.extra/usr/bin/tinfoil-shim ./cmd/shim

# First build populates mkosi.cache; later builds reuse it for fast iteration.
rebuild: go-binaries
	mkdir -p mkosi.cache packages
	$(MKOSI) --force
	rm -f tinfoilcvm
	objcopy -O binary --only-section .cmdline tinfoilcvm.efi /dev/stdout | grep -aoE 'roothash=[a-f0-9]+' | cut -d= -f2 > tinfoilcvm.hash
	@echo "image hash: $$(cat tinfoilcvm.hash)"

build: rebuild

python-lockfile:
	pip-compile --generate-hashes --allow-unsafe --output-file=mkosi.extra/opt/venv-requirements.txt python-requirements.in
