TRUSTED_PATH := /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MKOSI ?= sudo env PATH="$(TRUSTED_PATH)" mkosi
BAZEL ?= bazel
BUILDER_IMAGE := cvmimage-runtime-builder
SHIPPING_KERNEL := kernel/out/tinfoil-custom.vmlinuz
SHIPPING_INITRD := bazel-bin/image/initrd/initrd.cpio.zst
NVATTEST_OUTPUT := build/rootfs-artifacts/nvattest
NVATTEST_BINARY := $(NVATTEST_OUTPUT)/usr/bin/nvattest
NVATTEST_LIBRARY := $(NVATTEST_OUTPUT)/usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2

.PHONY: rootfs shipping-image debug-image test regenerate-nvattest clean

rootfs:
	docker build --pull --file builder/Dockerfile --tag $(BUILDER_IMAGE) builder
	./builder/run.sh runtime-go
	@test -x "$(NVATTEST_BINARY)" || { \
		echo "missing nvattest runtime binary; run 'make regenerate-nvattest'" >&2; \
		exit 1; \
	}
	@test -f "$(NVATTEST_LIBRARY)" || { \
		echo "missing libnvat runtime library; run 'make regenerate-nvattest'" >&2; \
		exit 1; \
	}
	./builder/run.sh kernel
	./builder/run.sh nvidia
	$(BAZEL) build --lockfile_mode=error //image:rootfs
	mkdir -p build/stage
	install -m 0644 bazel-bin/image/bazel-rootfs.tar build/stage/bazel-rootfs.tar

shipping-image: rootfs
	$(BAZEL) build -c opt --lockfile_mode=error //image/initrd:initrd
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

debug-image: rootfs
	./builder/run.sh debug-init
	$(BAZEL) build --lockfile_mode=error //image:debug-layer
	mkdir -p build/stage
	install -m 0644 bazel-bin/image/bazel-debug-layer.tar build/stage/bazel-debug-layer.tar
	$(BAZEL) build -c opt --lockfile_mode=error //image/initrd:initrd
	rm -f tinfoilcvm-debug tinfoilcvm-debug.raw tinfoilcvm-debug.roothash \
		tinfoilcvm-debug.hash tinfoilcvm-debug.vmlinuz tinfoilcvm-debug.initrd
	$(MKOSI) --force --output=tinfoilcvm-debug \
		--base-tree="$(CURDIR)/build/stage/bazel-debug-layer.tar"
	sudo env PATH="$(TRUSTED_PATH)" chmod 0644 tinfoilcvm-debug.raw tinfoilcvm-debug.roothash
	sudo env PATH="$(TRUSTED_PATH)" chown "$$(id -u):$$(id -g)" \
		tinfoilcvm-debug.raw tinfoilcvm-debug.roothash
	install -m 0644 "$(SHIPPING_KERNEL)" tinfoilcvm-debug.vmlinuz
	install -m 0644 "$(SHIPPING_INITRD)" tinfoilcvm-debug.initrd
	test -s tinfoilcvm-debug.raw
	test -s tinfoilcvm-debug.vmlinuz
	test -s tinfoilcvm-debug.initrd
	test "$$(wc -c < tinfoilcvm-debug.roothash)" -eq 64
	grep -Eq '^[a-f0-9]{64}$$' tinfoilcvm-debug.roothash
	cp tinfoilcvm-debug.roothash tinfoilcvm-debug.hash
	@echo "debug image hash: $$(cat tinfoilcvm-debug.hash)"

test:
	cd tinfoil && go test ./...
	cd tinfoil && go test -race ./cmd/init ./internal/boot/...
	cd tinfoil && go test -tags=tinfoil_debug_image ./cmd/init
	cd tinfoil && go vet ./...
	$(BAZEL) test -c opt --lockfile_mode=error //tinfoil/... //image/initrd:writer_test
	$(BAZEL) build -c opt --lockfile_mode=error //image/initrd:initrd

regenerate-nvattest:
	docker build --pull --file builder/Dockerfile --tag $(BUILDER_IMAGE) builder
	rm -rf "$(NVATTEST_OUTPUT)"
	./builder/run.sh nvattest
	test -x "$(NVATTEST_BINARY)"
	test -f "$(NVATTEST_LIBRARY)"

clean:
	sudo env PATH="$(TRUSTED_PATH)" rm -rf tinfoilcvm.*
	sudo env PATH="$(TRUSTED_PATH)" rm -rf tinfoilcvm-debug tinfoilcvm-debug.*
	sudo env PATH="$(TRUSTED_PATH)" rm -rf build/stage build/artifacts
