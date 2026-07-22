ARG RUNTIME_BUILDER_BASE_IMAGE
FROM ${RUNTIME_BUILDER_BASE_IMAGE}

ARG APT_SNAPSHOT_DATE

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C.UTF-8 \
    SOURCE_DATE_EPOCH=0 \
    TZ=UTC

RUN set -eux; \
    rm -f /etc/apt/apt.conf.d/docker-clean; \
    rm -f /etc/apt/sources.list.d/*; \
    printf '%s\n' \
        'Types: deb' \
        "URIs: https://snapshot.ubuntu.com/ubuntu/${APT_SNAPSHOT_DATE}" \
        'Suites: resolute resolute-updates resolute-security' \
        'Components: main universe restricted multiverse' \
        'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
        'Check-Valid-Until: no' \
        > /etc/apt/sources.list.d/ubuntu.sources; \
    printf '%s\n' 'Acquire::https::Verify-Peer "false";' \
        > /etc/apt/apt.conf.d/00-bootstrap-no-ca; \
    apt-get update -q; \
    apt-get install -y --no-install-recommends ca-certificates=20260223; \
    rm -f /etc/apt/apt.conf.d/00-bootstrap-no-ca; \
    apt-get update -q; \
    apt-get install -y --no-install-recommends \
        bc=1.07.1-4build1 \
        binutils=2.46-3ubuntu2 \
        bison=2:3.8.2+dfsg-1build4 \
        build-essential=12.12ubuntu2.26.04.2 \
        cargo=1.93.1ubuntu1 \
        cmake=4.2.3-2ubuntu2 \
        cpio=2.15+dfsg-2.1 \
        curl=8.18.0-1ubuntu2.3 \
        dpkg-dev=1.23.7ubuntu1 \
        dwarves=1.31-2ubuntu1 \
        flex=2.6.4-8.2build2 \
        gawk=1:5.3.2-1ubuntu1 \
        gcc=4:15.2.0-5ubuntu1 \
        git=1:2.53.0-1ubuntu1 \
        golang-1.25-go=1.25.7-2 \
        kmod=34.2-2ubuntu2 \
        libdw-dev=0.194-4 \
        libelf-dev=0.194-4 \
        libncurses-dev=6.6+20251231-1 \
        libssl-dev=3.5.5-1ubuntu3.2 \
        libxml2-dev=2.15.2+dfsg-0.1ubuntu0.1 \
        patch=2.8-2build1 \
        perl=5.40.1-7ubuntu0.1 \
        pkg-config=2.5.1-4 \
        python3=3.14.3-0ubuntu2 \
        rsync=3.4.1+ds1-7ubuntu0.3 \
        rustc=1.93.1ubuntu1 \
        util-linux=2.41.3-3ubuntu2 \
        xz-utils=5.8.3-1 \
        zstd=1.5.7+dfsg-3; \
    mkdir -p /opt/tinfoil-builder/packages /tmp/kernel-source-package; \
    cd /tmp/kernel-source-package; \
    apt-get download linux-source-7.0.0=7.0.0-28.28; \
    printf '%s  %s\n' \
        dd5994b199a1cb06b1f336bb086c5c23a9258fdcfdcbb7dcc8d3afa9a5d92e13 \
        linux-source-7.0.0_7.0.0-28.28_all.deb | sha256sum -c --strict -; \
    install -m 0444 linux-source-7.0.0_7.0.0-28.28_all.deb \
        /opt/tinfoil-builder/packages/; \
    cd /; \
    rm -rf /tmp/kernel-source-package; \
    test ! -e /etc/apt/apt.conf.d/00-bootstrap-no-ca; \
    test "$(/usr/lib/go-1.25/bin/go version | awk '{print $3}')" = go1.25.7; \
    test "$(dpkg-query -W -f='${Version}' gcc)" = 4:15.2.0-5ubuntu1; \
    test "$(dpkg-query -W -f='${Version}' binutils)" = 2.46-3ubuntu2; \
    test "$(dpkg-query -W -f='${Version}' dwarves)" = 1.31-2ubuntu1; \
    test "$(dpkg-query -W -f='${Version}' kmod)" = 34.2-2ubuntu2; \
    test "$(sha256sum /opt/tinfoil-builder/packages/linux-source-7.0.0_7.0.0-28.28_all.deb | awk '{print $1}')" = dd5994b199a1cb06b1f336bb086c5c23a9258fdcfdcbb7dcc8d3afa9a5d92e13; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

COPY build-initrd.sh /usr/local/bin/build-initrd

WORKDIR /workspace

ARG RUNTIME_BUILDER_BASE_IMAGE
ARG RUNTIME_BUILDER_RECIPE_SHA256
LABEL org.tinfoil.runtime-builder.base=${RUNTIME_BUILDER_BASE_IMAGE} \
      org.tinfoil.runtime-builder.snapshot=${APT_SNAPSHOT_DATE} \
      org.tinfoil.runtime-builder.recipe=${RUNTIME_BUILDER_RECIPE_SHA256}
