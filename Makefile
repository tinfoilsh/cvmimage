NIX_BUILD ?= nix-build
NIX_FLAGS := --no-out-link --option sandbox true

.PHONY: rootfs shipping-image debug-image test clean

rootfs:
	@set -eu; \
		mkdir -p build; \
		rootfs="$$($(NIX_BUILD) default.nix -A rootfs-archive $(NIX_FLAGS))"; \
		install -m 0644 "$$rootfs" build/rootfs.tar

shipping-image:
	@set -eu; \
		inputs="$$($(NIX_BUILD) default.nix -A image-inputs $(NIX_FLAGS))"; \
		mkosi="$$($(NIX_BUILD) default.nix -A mkosi $(NIX_FLAGS))/bin/mkosi"; \
		rm -f tinfoilcvm tinfoilcvm.raw tinfoilcvm.roothash tinfoilcvm.hash \
			tinfoilcvm.vmlinuz tinfoilcvm.initrd; \
		sudo "$$mkosi" --force \
			--base-tree="$$inputs/rootfs.tar"; \
		sudo chmod 0644 tinfoilcvm.raw tinfoilcvm.roothash; \
		sudo chown "$$(id -u):$$(id -g)" \
			tinfoilcvm.raw tinfoilcvm.roothash; \
		install -m 0644 "$$inputs/tinfoil-custom.vmlinuz" tinfoilcvm.vmlinuz; \
		install -m 0644 "$$inputs/initrd.cpio.zst" tinfoilcvm.initrd; \
		test -s tinfoilcvm.raw; \
		test -s tinfoilcvm.vmlinuz; \
		test -s tinfoilcvm.initrd; \
		test "$$(wc -c < tinfoilcvm.roothash)" -eq 64; \
		grep -Eq '^[a-f0-9]{64}$$' tinfoilcvm.roothash; \
		cp tinfoilcvm.roothash tinfoilcvm.hash; \
		echo "image hash: $$(cat tinfoilcvm.hash)"

debug-image:
	@set -eu; \
		inputs="$$($(NIX_BUILD) default.nix -A image-inputs $(NIX_FLAGS))"; \
		mkosi="$$($(NIX_BUILD) default.nix -A mkosi $(NIX_FLAGS))/bin/mkosi"; \
		rm -f tinfoilcvm-debug tinfoilcvm-debug.raw tinfoilcvm-debug.roothash \
			tinfoilcvm-debug.hash tinfoilcvm-debug.vmlinuz tinfoilcvm-debug.initrd; \
		sudo "$$mkosi" --force \
			--output=tinfoilcvm-debug \
			--base-tree="$$inputs/rootfs.tar" \
			--base-tree="$$inputs/debug-rootfs-layer.tar"; \
		sudo chmod 0644 \
			tinfoilcvm-debug.raw tinfoilcvm-debug.roothash; \
		sudo chown "$$(id -u):$$(id -g)" \
			tinfoilcvm-debug.raw tinfoilcvm-debug.roothash; \
		install -m 0644 "$$inputs/tinfoil-custom.vmlinuz" tinfoilcvm-debug.vmlinuz; \
		install -m 0644 "$$inputs/initrd.cpio.zst" tinfoilcvm-debug.initrd; \
		test -s tinfoilcvm-debug.raw; \
		test -s tinfoilcvm-debug.vmlinuz; \
		test -s tinfoilcvm-debug.initrd; \
		test "$$(wc -c < tinfoilcvm-debug.roothash)" -eq 64; \
		grep -Eq '^[a-f0-9]{64}$$' tinfoilcvm-debug.roothash; \
		cp tinfoilcvm-debug.roothash tinfoilcvm-debug.hash; \
		echo "debug image hash: $$(cat tinfoilcvm-debug.hash)"

test:
	cd tinfoil && go test ./...
	cd tinfoil && go test -race ./cmd/init ./internal/boot/...
	cd tinfoil && go test -tags=tinfoil_debug_image ./cmd/init
	cd tinfoil && go vet ./...
	$(NIX_BUILD) default.nix -A initrd $(NIX_FLAGS)

clean:
	sudo rm -rf tinfoilcvm tinfoilcvm.*
	sudo rm -rf tinfoilcvm-debug tinfoilcvm-debug.*
	rm -rf build
