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
		image="$$($(NIX_BUILD) default.nix -A shipping-image $(NIX_FLAGS))"; \
		rm -f tinfoilcvm tinfoilcvm.raw tinfoilcvm.roothash tinfoilcvm.hash \
			tinfoilcvm.vmlinuz tinfoilcvm.initrd; \
		for artifact in raw roothash vmlinuz initrd; do \
			install -m 0644 "$$image/tinfoilcvm.$$artifact" \
				"tinfoilcvm.$$artifact"; \
		done; \
		test -s tinfoilcvm.raw; \
		test -s tinfoilcvm.vmlinuz; \
		test -s tinfoilcvm.initrd; \
		test "$$(wc -c < tinfoilcvm.roothash)" -eq 64; \
		grep -Eq '^[a-f0-9]{64}$$' tinfoilcvm.roothash; \
		cp tinfoilcvm.roothash tinfoilcvm.hash; \
		echo "image hash: $$(cat tinfoilcvm.hash)"

debug-image:
	@set -eu; \
		image="$$($(NIX_BUILD) default.nix -A debug-image $(NIX_FLAGS))"; \
		rm -f tinfoilcvm-debug tinfoilcvm-debug.raw tinfoilcvm-debug.roothash \
			tinfoilcvm-debug.hash tinfoilcvm-debug.vmlinuz tinfoilcvm-debug.initrd; \
		for artifact in raw roothash vmlinuz initrd; do \
			install -m 0644 "$$image/tinfoilcvm-debug.$$artifact" \
				"tinfoilcvm-debug.$$artifact"; \
		done; \
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
	rm -rf tinfoilcvm tinfoilcvm.*
	rm -rf tinfoilcvm-debug tinfoilcvm-debug.*
	rm -rf build
