all: build

TRUSTED_PATH := /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MKOSI ?= sudo env PATH="$(TRUSTED_PATH)" mkosi
BAZEL ?= bazel

NVATTEST_VERSION = 1.2.2.1780962352-1
NVATTEST_DEBS = packages/nvattest_$(NVATTEST_VERSION)_amd64.deb \
                packages/libnvat_$(NVATTEST_VERSION)_amd64.deb
NVATTEST_RUNTIME_OUTPUTS = build/rootfs-artifacts/nvattest/usr/bin/nvattest \
                           build/rootfs-artifacts/nvattest/usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2

.PHONY: all build rebuild clean deepclean hash nvattest go-binaries \
	runtime-builder builder-initrd bazel-rootfs additive-initrd verify-additive-initrd \
	test-go-producer test-runtime-builder-contract test-additive-initrd reproducible-additive-initrd test-roothash-artifacts \
	test-runtime-locks \
	verify-runtime-sources update-runtime-locks \
	test-nvattest-artifacts reproducible-nvattest custom-kernel-artifacts \
	nvidia-module-artifacts test-nvidia-module-producer reproducible-nvidia-modules \
	reproducible-runtime-artifacts

# tinfoilcvm.hash is the compatibility copy written by `rebuild`; mkosi's
# direct roothash split artifact is the source contract.
hash:
	@if [ ! -f tinfoilcvm.roothash ]; then \
	    echo "missing authoritative tinfoilcvm.roothash" >&2; \
	    exit 1; \
	fi; \
	if [ "$$(wc -c < tinfoilcvm.roothash)" -ne 64 ] || ! grep -Eq '^[a-f0-9]{64}$$' tinfoilcvm.roothash; then \
	    echo "invalid roothash artifact tinfoilcvm.roothash" >&2; \
	    exit 1; \
	fi; \
	if [ -f tinfoilcvm.hash ]; then \
	    if [ "$$(wc -c < tinfoilcvm.hash)" -ne 64 ] || ! grep -Eq '^[a-f0-9]{64}$$' tinfoilcvm.hash; then \
	        echo "invalid compatibility artifact tinfoilcvm.hash" >&2; \
	        exit 1; \
	    fi; \
	    if ! cmp -s tinfoilcvm.roothash tinfoilcvm.hash; then \
	        echo "tinfoilcvm.hash differs from authoritative tinfoilcvm.roothash" >&2; \
	        exit 1; \
	    fi; \
	fi; \
	cat tinfoilcvm.roothash

test-roothash-artifacts:
	./scripts/test-roothash-artifacts.sh

clean:
	sudo env PATH="$(TRUSTED_PATH)" rm -rf tinfoilcvm.*
	sudo env PATH="$(TRUSTED_PATH)" rm -rf initrd
	sudo env PATH="$(TRUSTED_PATH)" rm -rf initrd.cpio.zst
	sudo env PATH="$(TRUSTED_PATH)" rm -rf build/stage build/artifacts

deepclean:
	$(MKOSI) clean
	sudo env PATH="$(TRUSTED_PATH)" rm -rf mkosi.cache/*
	sudo env PATH="$(TRUSTED_PATH)" rm -f packages/nvattest_*.deb packages/libnvat_*.deb

go-binaries: builder-initrd
	mkdir -p mkosi.extra/usr/bin
	install -m 0755 build/builder-work/output/artifacts/tinfoil-boot mkosi.extra/usr/bin/tinfoil-boot
	install -m 0755 build/builder-work/output/artifacts/tinfoil-container-status mkosi.extra/usr/bin/tinfoil-container-status
	install -m 0755 build/builder-work/output/artifacts/tinfoil-egress mkosi.extra/usr/bin/tinfoil-egress
	install -m 0755 build/builder-work/output/artifacts/tinfoil-init mkosi.extra/usr/bin/tinfoil-init
	install -m 0755 build/builder-work/output/artifacts/tinfoil-shim mkosi.extra/usr/bin/tinfoil-shim

runtime-builder:
	./scripts/build-runtime-builder.sh

builder-initrd: runtime-builder
	./scripts/run-runtime-builder.sh initrd

test-go-producer:
	./scripts/test-go-producer.sh

test-runtime-builder-contract:
	./scripts/test-runtime-builder-contract.sh

bazel-rootfs: builder-initrd nvattest nvidia-module-artifacts
	$(BAZEL) build --lockfile_mode=error //image:rootfs
	mkdir -p build/stage
	install -m 0644 bazel-bin/image/bazel-rootfs.tar build/stage/bazel-rootfs.tar

custom-kernel-artifacts: runtime-builder
	./scripts/run-runtime-builder.sh kernel

nvidia-module-artifacts: custom-kernel-artifacts
	./scripts/run-runtime-builder.sh nvidia

test-nvidia-module-producer:
	./scripts/test-nvidia-module-producer.sh

additive-initrd: builder-initrd
	TINFOIL_BUILDER_OUTPUT="$(CURDIR)/build/builder-work/output" ./scripts/build-additive-initrd.sh

verify-additive-initrd: additive-initrd
	./scripts/initrd_manifest.py verify-archive \
		--manifest image/initrd/manifest.tsv \
		--binary build/builder-work/output/artifacts/tinfoil-initrd \
		--archive initrd.cpio.zst

test-additive-initrd:
	./scripts/test-additive-initrd.sh

reproducible-additive-initrd:
	./scripts/reproduce-additive-initrd.sh

reproducible-nvidia-modules:
	./scripts/reproduce-nvidia-modules.sh

reproducible-runtime-artifacts: reproducible-additive-initrd reproducible-nvattest reproducible-nvidia-modules

test-runtime-locks:
	./scripts/test-update-runtime-locks.sh
	$(BAZEL) --output_base=/tmp/cvmimage-bazel-runtime-lock-test test \
		--symlink_prefix=/tmp/cvmimage-bazel-runtime-lock-test- \
		//image:runtime-package-lock-test
	$(BAZEL) --output_base=/tmp/cvmimage-bazel-runtime-lock-graph \
		mod deps --lockfile_mode=error >/dev/null

verify-runtime-sources:
	BAZEL="$(BAZEL)" ./scripts/update-runtime-locks.sh --check

update-runtime-locks:
	BAZEL="$(BAZEL)" ./scripts/update-runtime-locks.sh

# First build populates mkosi.cache; later builds reuse it for fast iteration.
rebuild: go-binaries
	mkdir -p mkosi.cache packages
	$(MKOSI) --force
	rm -f tinfoilcvm
	test "$$(wc -c < tinfoilcvm.roothash)" -eq 64
	grep -Eq '^[a-f0-9]{64}$$' tinfoilcvm.roothash
	cp tinfoilcvm.roothash tinfoilcvm.hash
	@echo "image hash: $$(cat tinfoilcvm.hash)"

build: nvattest rebuild

# The CUDA repo's nvattest links libxml2.so.2; resolute ships libxml2.so.16, so
# we build from source against the system lib. See build-nvattest.sh.
nvattest: $(NVATTEST_DEBS) $(NVATTEST_RUNTIME_OUTPUTS)

# Grouped target (&:): a single build-nvattest.sh run produces both the nvattest
# and libnvat debs, so make won't consider the build up-to-date when only one of
# them is present.
$(NVATTEST_DEBS) $(NVATTEST_RUNTIME_OUTPUTS) &: \
		build-nvattest.sh \
		builder/Dockerfile \
		builder/build-initrd.sh \
		scripts/nvattest-artifacts.sh \
		scripts/nvattest-regorus-Cargo.lock \
		scripts/build-runtime-builder.sh \
		scripts/run-runtime-builder.sh \
		scripts/runtime-builder-base-image.txt \
		scripts/runtime-builder-snapshot.txt | runtime-builder
	./scripts/run-runtime-builder.sh nvattest

test-nvattest-artifacts:
	./scripts/test-nvattest-artifacts.sh

reproducible-nvattest:
	./scripts/reproduce-nvattest.sh

python-lockfile:
	pip-compile --generate-hashes --allow-unsafe --output-file=mkosi.extra/opt/venv-requirements.txt python-requirements.in
