# Writable volume I/O

Writable authenticated volumes use dm-crypt with `no_read_workqueue` and
`no_write_workqueue`. These bypass dm-crypt's internal workqueues and its
separate write-submission thread. The updated runtime applies the flags when
it creates or reopens a volume mapping.

The benchmark profile uses four fio jobs, each at queue depth 32, for a total
queue depth of 128. Job count describes application concurrency; it is not a
dm-crypt worker-count option.

## Reproducing the workload

On an initialized, disposable block mapping with at least 8 GiB available, run:

```sh
fio benchmarks/volume-randwrite.fio \
  --filename=/dev/mapper/scratch-volume \
  --output-format=json --output=volume-randwrite.json
```

This overwrites the first 8 GiB of the scratch volume. The four jobs share that
range. The profile uses direct 4 KiB random writes, a three-second warm-up, a
15-second measurement, and a final flush. It does not request durability after
every write. Authenticated data and tags must be initialized before testing.

## inf17 measurements, October 13, 2026

The disposable SEV-SNP guest had 8 vCPUs and 16 GiB RAM, Linux 7.0.0-28-generic,
and QEMU 10.1.0. Its raw virtio disk was backed by a file on the host's ext4
filesystem over eight NVMe drives in RAID5. The kernel selected
`xts-aes-vaes-avx512`. Each row below averages two runs using the four-job profile.

| Stack | IOPS | Whole-guest CPU busy |
| --- | ---: | ---: |
| Plain CVM disk | 92,358 | 6.2% |
| AES-XTS, default workqueues | 91,313 | 32.0% |
| AES-XTS, workqueue bypass | 92,347 | 11.9% |
| AES-XTS + HMAC-SHA256 + dm-integrity D, workqueue bypass | 87,063 | 18.4% |

The authenticated stack uses 4096-byte sectors, 48 bytes of tag/IV metadata,
and the default 64 KiB integrity metadata buffers. An earlier two-run sample
with default workqueues reached 87,849 IOPS with four jobs; total guest CPU was
not captured in that sample. These results do not establish a four-job
throughput improvement for authenticated volumes. The direct CPU comparison
above is for AES-XTS without authentication.

In the follow-up, retaining encryption workers and adding only
`submit_from_crypt_cpus` reached 82,641 IOPS and 35.2% guest CPU for the
authenticated stack. Adding `same_cpu_crypt` reached 86,248 IOPS and 19.6% CPU.
Full bypass gave the best four-job throughput and CPU use among those tested
authenticated settings.

CPU percentages include guest kernel workers and interrupts; 100% means all
eight vCPUs are busy. Host QEMU work is excluded. The host remained in service,
and these were short tests with cached integrity metadata. Small throughput
differences are inconclusive, and results depend on concurrency and flush rate.

See the kernel documentation for [dm-crypt workqueue controls](https://docs.kernel.org/admin-guide/device-mapper/dm-crypt.html).
