all: build

TRUSTED_PATH := /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MKOSI ?= sudo env PATH="$(TRUSTED_PATH)" mkosi
BAZEL ?= bazel
SHIPPING_KERNEL = kernel/out/tinfoil-custom.vmlinuz
SHIPPING_INITRD = initrd.cpio.zst

NVATTEST_CACHE ?= $(if $(strip $(XDG_CACHE_HOME)),$(XDG_CACHE_HOME),$(HOME)/.cache)/cvmimage-hardening/nvattest
NVATTEST_RUNTIME_OUTPUT = build/rootfs-artifacts/nvattest

.PHONY: all build rebuild shipping-image clean deepclean hash nvattest regenerate-nvattest release-nvattest-cache \
	runtime-builder builder-initrd bazel-rootfs additive-initrd verify-additive-initrd \
	builder-debug-init bazel-debug-layer debug-image test-debug-image-contract \
	test-go-producer test-runtime-builder-contract test-additive-initrd reproducible-additive-initrd test-roothash-artifacts \
	test-runtime-locks \
	verify-runtime-sources update-runtime-locks \
	test-nvattest-artifacts reproducible-nvattest custom-kernel-artifacts \
	nvidia-module-artifacts test-nvidia-module-producer reproducible-nvidia-modules \
	reproducible-runtime-artifacts

# tinfoilcvm.hash is the compatibility copy written by `shipping-image`; mkosi's
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
	sudo env PATH="$(TRUSTED_PATH)" rm -rf tinfoilcvm-debug tinfoilcvm-debug.*
	sudo env PATH="$(TRUSTED_PATH)" rm -rf initrd
	sudo env PATH="$(TRUSTED_PATH)" rm -rf initrd.cpio.zst
	sudo env PATH="$(TRUSTED_PATH)" rm -rf build/stage build/artifacts

deepclean:
	$(MKOSI) clean
	sudo env PATH="$(TRUSTED_PATH)" rm -f packages/nvattest_*.deb packages/libnvat_*.deb

runtime-builder:
	./scripts/build-runtime-builder.sh

builder-initrd: runtime-builder
	./scripts/run-runtime-builder.sh initrd

builder-debug-init: runtime-builder
	./scripts/run-runtime-builder.sh debug-init

test-go-producer:
	./scripts/test-go-producer.sh

test-runtime-builder-contract:
	./scripts/test-runtime-builder-contract.sh

bazel-rootfs: builder-initrd nvattest nvidia-module-artifacts
	$(BAZEL) build --lockfile_mode=error //image:rootfs
	mkdir -p build/stage
	install -m 0644 bazel-bin/image/bazel-rootfs.tar build/stage/bazel-rootfs.tar

bazel-debug-layer: builder-debug-init
	$(BAZEL) build --lockfile_mode=error //image:debug-layer
	mkdir -p build/stage
	install -m 0644 bazel-bin/image/bazel-debug-layer.tar build/stage/bazel-debug-layer.tar


test-debug-image-contract:
	@test -s build/stage/bazel-rootfs.tar -a -s build/stage/bazel-debug-layer.tar || { \
		echo 'missing staged rootfs layers; run make bazel-rootfs bazel-debug-layer explicitly' >&2; \
		exit 1; \
	}
	./scripts/test-debug-image-contract.sh \
		build/stage/bazel-rootfs.tar \
		build/stage/bazel-debug-layer.tar

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

shipping-image: bazel-rootfs additive-initrd
	./scripts/test-debug-image-contract.sh build/stage/bazel-rootfs.tar
	rm -f tinfoilcvm tinfoilcvm.raw tinfoilcvm.roothash tinfoilcvm.hash \
		tinfoilcvm.vmlinuz tinfoilcvm.initrd
	$(MKOSI) --force
	sudo env PATH="$(TRUSTED_PATH)" chmod 0644 tinfoilcvm.raw tinfoilcvm.roothash
	sudo env PATH="$(TRUSTED_PATH)" chown "$$(id -u):$$(id -g)" tinfoilcvm.raw tinfoilcvm.roothash
	install -m 0644 "$(SHIPPING_KERNEL)" tinfoilcvm.vmlinuz
	install -m 0644 "$(SHIPPING_INITRD)" tinfoilcvm.initrd
	test -s tinfoilcvm.raw
	test -s tinfoilcvm.vmlinuz
	test -s tinfoilcvm.initrd
	test "$$(wc -c < tinfoilcvm.roothash)" -eq 64
	grep -Eq '^[a-f0-9]{64}$$' tinfoilcvm.roothash
	cp tinfoilcvm.roothash tinfoilcvm.hash
	@echo "image hash: $$(cat tinfoilcvm.hash)"

debug-image: bazel-rootfs bazel-debug-layer additive-initrd custom-kernel-artifacts
	./scripts/test-debug-image-contract.sh \
		build/stage/bazel-rootfs.tar \
		build/stage/bazel-debug-layer.tar
	rm -f tinfoilcvm-debug tinfoilcvm-debug.raw tinfoilcvm-debug.roothash \
		tinfoilcvm-debug.hash tinfoilcvm-debug.vmlinuz tinfoilcvm-debug.initrd
	$(MKOSI) --force --output=tinfoilcvm-debug \
		--base-tree="$(CURDIR)/build/stage/bazel-debug-layer.tar"
	sudo env PATH="$(TRUSTED_PATH)" chmod 0644 tinfoilcvm-debug.raw tinfoilcvm-debug.roothash
	sudo env PATH="$(TRUSTED_PATH)" chown "$$(id -u):$$(id -g)" \
		tinfoilcvm-debug.raw tinfoilcvm-debug.roothash
	install -m 0644 "$(SHIPPING_KERNEL)" tinfoilcvm-debug.vmlinuz
	install -m 0644 "$(SHIPPING_INITRD)" tinfoilcvm-debug.initrd
	cmp -s "$(SHIPPING_KERNEL)" tinfoilcvm-debug.vmlinuz
	cmp -s "$(SHIPPING_INITRD)" tinfoilcvm-debug.initrd
	test -s tinfoilcvm-debug.raw
	test -s tinfoilcvm-debug.vmlinuz
	test -s tinfoilcvm-debug.initrd
	test "$$(wc -c < tinfoilcvm-debug.roothash)" -eq 64
	grep -Eq '^[a-f0-9]{64}$$' tinfoilcvm-debug.roothash
	cp tinfoilcvm-debug.roothash tinfoilcvm-debug.hash
	@echo "debug image hash: $$(cat tinfoilcvm-debug.hash)"

rebuild: shipping-image

build: shipping-image

# Normal image builds consume only the two fixed, content-addressed nvattest
# runtime artifacts from a durable local cache. They never invoke the source
# producer implicitly.
nvattest:
	./scripts/stage-nvattest-cache.sh \
		"$(NVATTEST_CACHE)" \
		"$(abspath $(NVATTEST_RUNTIME_OUTPUT))"

# Source regeneration is deliberately explicit. It verifies the fixed producer
# hashes before publishing artifacts into the local content-addressed cache.
regenerate-nvattest: runtime-builder
	./scripts/regenerate-nvattest-cache.sh "$(NVATTEST_CACHE)"

# Release qualification rebuilds nvattest twice, verifies the reviewed hashes,
# and publishes the verified result into the local cache for shipping-image.
release-nvattest-cache:
	./scripts/reproduce-nvattest.sh \
		--publish-cache "$(NVATTEST_CACHE)"

test-nvattest-artifacts:
	./scripts/test-nvattest-artifacts.sh

reproducible-nvattest:
	./scripts/reproduce-nvattest.sh
