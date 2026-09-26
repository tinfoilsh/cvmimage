FROM --platform=linux/amd64 golang:1.26-alpine AS guest
RUN test "$(uname -m)" = x86_64 && apk add --no-cache linux-lts e2fsprogs kmod cpio build-base
WORKDIR /src/tinfoil
COPY tinfoil/go.mod tinfoil/go.sum ./
RUN go mod download
COPY tinfoil/ ./
RUN CGO_ENABLED=0 go test -c -o /volume.test ./internal/volume && \
    CGO_ENABLED=0 go test -c -o /hardening.test ./internal/pid1/hardening && \
    CGO_ENABLED=0 go build -o /tinfoil-volume-worker ./cmd/volumeworker
COPY tests/volume-vm/ /fixture/
RUN sh /fixture/pack.sh

FROM alpine:3.23
RUN apk add --no-cache qemu-system-x86_64 coreutils
COPY --from=guest /boot/vmlinuz-lts /fixture/vmlinuz
COPY --from=guest /fixture/initramfs.gz /fixture/initramfs.gz
COPY tests/volume-vm/run.sh /fixture/run.sh
USER 65534:65534
ENTRYPOINT ["sh", "/fixture/run.sh"]
