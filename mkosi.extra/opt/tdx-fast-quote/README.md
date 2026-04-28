# Fast-quote TDX patch

Drops the TDX `GetQuote` poll interval from 1s to 10ms (total timeout unchanged).

- `tdx-guest.c` — verbatim Linux **v7.0** `drivers/virt/coco/tdx-guest/tdx-guest.c`.
  SHA256: `93202ca4be1700c9e95fbd1093714ecf24da5da533e6cef8af05e73cd3308f2a`
- `fast-quote.patch` — the 2-line diff applied on top.

Both are checked at every image build by `mkosi.postinst.chroot`
(`sha256sum -c` on the .c, `patch` on the diff).

## Verify

```sh
sha256sum tdx-guest.c
# or against upstream:
diff -q <(curl -fsSL https://raw.githubusercontent.com/torvalds/linux/v7.0/drivers/virt/coco/tdx-guest/tdx-guest.c) tdx-guest.c
```

## Update for a new kernel

1. `EXPECTED_KERNEL_MAJOR` + `STOCK_SHA256` in `mkosi.postinst.chroot`.
2. Replace `tdx-guest.c` with the new kernel's stock file; update SHA here.
3. `sudo make build`. If the patch rejects, regenerate `fast-quote.patch`
   by hand against the new stock and rebuild.
