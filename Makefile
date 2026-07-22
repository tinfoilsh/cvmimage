all: build

MKOSI ?= sudo env PATH="$$PATH" mkosi

NVATTEST_VERSION = 1.2.2.1780962352-1
NVATTEST_DEBS = packages/nvattest_$(NVATTEST_VERSION)_amd64.deb \
                packages/libnvat_$(NVATTEST_VERSION)_amd64.deb
# Pinned ubuntu:26.04 (resolute) builder image. This is the single source of
# truth for the digest; rotate via `docker buildx imagetools inspect ubuntu:26.04`.
NVATTEST_BUILDER = ubuntu@sha256:5e275723f82c67e387ba9e3c24baa0abdcb268917f276a0561c97bef9450d0b4

.PHONY: all build rebuild clean deepclean hash nvattest go-binaries \
	builder-initrd additive-initrd verify-additive-initrd \
	test-additive-initrd reproducible-additive-initrd

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
	sudo rm -rf build/stage build/artifacts

deepclean:
	$(MKOSI) clean
	sudo rm -rf mkosi.cache/*
	sudo rm -f packages/nvattest_*.deb packages/libnvat_*.deb

go-binaries:
	mkdir -p mkosi.extra/usr/bin
	cd tinfoil && go build -ldflags="-s -w" -o ../mkosi.extra/usr/bin/tinfoil-boot ./cmd/boot
	cd tinfoil && go build -ldflags="-s -w" -o ../mkosi.extra/usr/bin/tinfoil-container-status ./cmd/container-status
	cd tinfoil && go build -ldflags="-s -w" -o ../mkosi.extra/usr/bin/tinfoil-egress ./cmd/egress
	cd tinfoil && go build -ldflags="-s -w" -o ../mkosi.extra/usr/bin/tinfoil-shim ./cmd/shim

builder-initrd:
	@version="$$( $(MKOSI) --version)"; \
	if [ "$$version" != "mkosi 26" ]; then \
	    echo "builder-initrd requires mkosi 26, found: $${version:-unknown}" >&2; \
	    exit 1; \
	fi
	mkdir -p build/builder-work build/builder-cache build/builder-pkgcache build/builder-workspace
	$(MKOSI) -C builder --force build
	sudo chown -R "$$(id -u):$$(id -g)" build/builder-work/output

additive-initrd: builder-initrd
	sudo env PATH="$$PATH" TINFOIL_BUILDER_OUTPUT="$(CURDIR)/build/builder-work/output" ./scripts/build-additive-initrd.sh
	sudo chown "$$(id -u):$$(id -g)" initrd.cpio.zst

verify-additive-initrd:
	./scripts/initrd_manifest.py verify-archive \
		--manifest image/initrd/manifest.tsv \
		--artifacts build/builder-work/output/artifacts.tsv \
		--artifact-lock image/manifests/artifacts.lock.tsv \
		--archive initrd.cpio.zst

test-additive-initrd: verify-additive-initrd
	./scripts/test-additive-initrd.sh

reproducible-additive-initrd:
	./scripts/reproduce-additive-initrd.sh

# First build populates mkosi.cache; later builds reuse it for fast iteration.
rebuild: go-binaries
	mkdir -p mkosi.cache packages
	$(MKOSI) --force
	rm -f tinfoilcvm
	objcopy -O binary --only-section .cmdline tinfoilcvm.efi /dev/stdout | grep -aoE 'roothash=[a-f0-9]+' | cut -d= -f2 > tinfoilcvm.hash
	@echo "image hash: $$(cat tinfoilcvm.hash)"

build: nvattest rebuild

# The CUDA repo's nvattest links libxml2.so.2; resolute ships libxml2.so.16, so
# we build from source against the system lib. See build-nvattest.sh.
nvattest: $(NVATTEST_DEBS)

# Grouped target (&:): a single build-nvattest.sh run produces both the nvattest
# and libnvat debs, so make won't consider the build up-to-date when only one of
# them is present.
$(NVATTEST_DEBS) &: build-nvattest.sh
	docker run --rm \
		-v "$(CURDIR)":/workspace -w /workspace \
		-v nvattest-apt-cache:/var/cache/apt \
		-e DEBIAN_FRONTEND=noninteractive \
		-e HOST_UID="$${SUDO_UID:-$$(id -u)}" \
		-e HOST_GID="$${SUDO_GID:-$$(id -g)}" \
		$(NVATTEST_BUILDER) \
		bash -c './build-nvattest.sh'

python-lockfile:
	pip-compile --generate-hashes --allow-unsafe --output-file=mkosi.extra/opt/venv-requirements.txt python-requirements.in
