all: build

TRUSTED_PATH := /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MKOSI ?= sudo env PATH="$(TRUSTED_PATH)" mkosi
BAZEL ?= bazel

NVATTEST_VERSION = 1.2.2.1780962352-1
NVATTEST_DEBS = packages/nvattest_$(NVATTEST_VERSION)_amd64.deb \
                packages/libnvat_$(NVATTEST_VERSION)_amd64.deb
# Pinned ubuntu:26.04 (resolute) builder image. This is the single source of
# truth for the digest; rotate via `docker buildx imagetools inspect ubuntu:26.04`.
NVATTEST_BUILDER = ubuntu@sha256:5e275723f82c67e387ba9e3c24baa0abdcb268917f276a0561c97bef9450d0b4

.PHONY: all build rebuild clean deepclean hash nvattest go-binaries \
	builder-initrd additive-initrd verify-additive-initrd \
	test-additive-initrd reproducible-additive-initrd test-roothash-artifacts \
	test-rootfs-policy test-rootfs-manifest test-rootfs-manifest-policy \
	verify-final-rootfs test-final-rootfs-verifier test-runtime-locks \
	verify-runtime-sources update-runtime-locks test-runtime-archives

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

go-binaries:
	mkdir -p mkosi.extra/usr/bin
	cd tinfoil && go build -ldflags="-s -w" -o ../mkosi.extra/usr/bin/tinfoil-boot ./cmd/boot
	cd tinfoil && go build -ldflags="-s -w" -o ../mkosi.extra/usr/bin/tinfoil-container-status ./cmd/container-status
	cd tinfoil && go build -ldflags="-s -w" -o ../mkosi.extra/usr/bin/tinfoil-egress ./cmd/egress
	cd tinfoil && go build -ldflags="-s -w" -o ../mkosi.extra/usr/bin/tinfoil-shim ./cmd/shim

builder-initrd:
	@source_status="$$(git status --porcelain=v1 --untracked-files=all --ignored=matching -- tinfoil)"; \
	if [ -n "$$source_status" ]; then \
	    printf 'builder-initrd: refusing uncommitted or ignored tinfoil source:\n%s\n' "$$source_status" >&2; \
	    exit 1; \
	fi; \
	source_revision="tinfoil-tree:$$(git rev-parse HEAD:tinfoil)"; \
	version="$$( $(MKOSI) --version)"; \
	if [ "$$version" != "mkosi 26" ]; then \
	    echo "builder-initrd requires mkosi 26, found: $${version:-unknown}" >&2; \
	    exit 1; \
	fi; \
	mkdir -p build/builder-work build/builder-cache build/builder-pkgcache build/builder-workspace; \
	$(MKOSI) -C builder --environment=TINFOIL_SOURCE_REVISION="$$source_revision" --force build
	sudo env PATH="$(TRUSTED_PATH)" chown -R "$$(id -u):$$(id -g)" build/builder-work/output

additive-initrd: builder-initrd
	sudo env PATH="$(TRUSTED_PATH)" TINFOIL_BUILDER_OUTPUT="$(CURDIR)/build/builder-work/output" ./scripts/build-additive-initrd.sh
	sudo env PATH="$(TRUSTED_PATH)" chown "$$(id -u):$$(id -g)" initrd.cpio.zst

verify-additive-initrd: additive-initrd
	./scripts/initrd_manifest.py verify-archive \
		--manifest image/initrd/manifest.tsv \
		--artifacts build/builder-work/output/artifacts.tsv \
		--artifact-lock image/manifests/artifacts.lock.tsv \
		--archive initrd.cpio.zst

test-additive-initrd: verify-additive-initrd
	./scripts/test-additive-initrd.sh

reproducible-additive-initrd:
	./scripts/reproduce-additive-initrd.sh

test-rootfs-policy:
	./scripts/test-rootfs-policy-adversarial.sh

test-rootfs-manifest: test-rootfs-manifest-policy
	./scripts/test-rootfs-manifest.sh

test-rootfs-manifest-policy:
	./scripts/test-rootfs-manifest-policy.py

verify-final-rootfs:
	@test -n "$(FINAL_ROOTFS_IMAGE)" -a -n "$(FINAL_ROOTFS_MANIFEST)" \
		-a -n "$(FINAL_ROOTFS_ROOTHASH)" || { \
		echo "set absolute FINAL_ROOTFS_IMAGE, FINAL_ROOTFS_MANIFEST, and FINAL_ROOTFS_ROOTHASH paths" >&2; exit 2; }
	sudo env -i PATH="$(TRUSTED_PATH)" LC_ALL=C LANG=C \
		/usr/bin/python3 -I ./scripts/verify-final-rootfs.py \
		--image "$(FINAL_ROOTFS_IMAGE)" --manifest "$(FINAL_ROOTFS_MANIFEST)" \
		--roothash "$(FINAL_ROOTFS_ROOTHASH)"

test-final-rootfs-verifier:
	./scripts/test-final-rootfs-verifier.sh

test-runtime-locks:
	./scripts/test-runtime-source-lock.sh
	$(BAZEL) --output_base=/tmp/cvmimage-bazel-runtime-lock-test test \
		//image:runtime-package-lock-test //scripts:runtime-source-lock-test
	$(BAZEL) --output_base=/tmp/cvmimage-bazel-runtime-lock-graph mod graph >/dev/null

test-runtime-archives:
	$(BAZEL) --output_base=/tmp/cvmimage-bazel-runtime-archive-test test \
		--symlink_prefix=/tmp/cvmimage-bazel-runtime-archive-test- \
		//scripts:runtime-archive-test
	@set -eu; \
	for suffix in a b; do \
		base="/tmp/cvmimage-bazel-runtime-archive-build-$$suffix"; \
		hashes="/tmp/cvmimage-bazel-runtime-archive-build-$$suffix.sha256"; \
		$(BAZEL) --output_base="$$base" build \
			--symlink_prefix="$$base-" \
			//image:runtime-source-member-archives; \
		bin="$$( $(BAZEL) --output_base="$$base" info bazel-bin )"; \
		find "$$bin/image" -maxdepth 1 -type f -name '*-members.tar' -printf '%f\n' | sort | \
			while read -r name; do sha256sum "$$bin/image/$$name"; done | \
			sed "s#  $$bin/image/#  #" > "$$hashes"; \
		test "$$(wc -l < "$$hashes")" -eq 12; \
	done; \
	cmp /tmp/cvmimage-bazel-runtime-archive-build-a.sha256 \
		/tmp/cvmimage-bazel-runtime-archive-build-b.sha256

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
