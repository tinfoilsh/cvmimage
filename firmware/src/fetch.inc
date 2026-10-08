# The kernel and initramfs, fetched rather than measured. An SEV-SNP launch
# measures every page an image places through one AMD Secure Processor command
# a page, about 1.4 ms each, so nine megabytes of kernel and initramfs cost
# three seconds of every boot before the guest runs an instruction. The image
# measures their SHA-256 instead, in the shim's data block, and the shim reads
# the bytes from QEMU's fw_cfg device: into a shared bounce buffer, then copied
# into private memory, and only the private copy is hashed -- the host can
# rewrite the bounce buffer whenever it likes, and the copy it cannot.
#
# Nothing the host says is believed. The directory it serves only says where to
# look; the file must be exactly as long as the image states, and must hash to
# what the image states, or the shim terminates before Linux is ever entered.
#
#   \fail      where a device that will not serve the file terminates
#   \mismatch  where bytes that do not hash to the measured digest terminate
#   \exit      the VMGEXIT, as in psc.inc
#   \accept    accepts [%r12, %r13) as private memory, as map.inc's does
#
# Runs with the block shared, before the accept walk, which is what takes the
# bounce buffer back as private RAM afterwards.

.macro fetch_code fail, mismatch, exit, accept

# Both files, in place and checked. Preserves %r8, the top of guest RAM.
fetch_all:
    push %r8
    # The host is told the bounce buffer is shared before it is asked to write
    # it, as Linux does before a DMA into decrypted memory.
    mov $FETCH_BOUNCE, %r9
    mov $(FETCH_BOUNCE + FETCH_BOUNCE_SIZE), %r10
    mov $PSC_ENTRY_SHARED, %ebx
    call psc_range
    lea shim_data+SHIM_DATA_FETCH(%rip), %rbp
    call fetch_one
    add $FETCH_LEN, %rbp
    call fetch_one
    pop %r8
    ret

# The file the entry at %rbp states.
# Clobbers every general register but %rbp and %rsp.
fetch_one:
    mov FETCH_DEST(%rbp), %r12
    mov FETCH_SIZE(%rbp), %r13
    add %r12, %r13
    add $(PAGE - 1), %r13
    and $-PAGE, %r13
    call \accept
    mov $(FWCFG_DMA_SELECT | FWCFG_DMA_READ | FWCFG_FILE_DIR << 16), %eax
    mov $FETCH_DIR_LEN, %ecx
    mov $FETCH_BOUNCE, %edx
    call fwcfg_dma
    lea FETCH_NAME(%rbp), %rsi
    mov $FETCH_BOUNCE_ALIAS, %rdi
    mov (%rdi), %ecx
    bswap %ecx                      # the directory's count, big-endian
    cmp $FETCH_DIR_ENTRIES, %ecx
    ja \fail                        # more than was read: refused, not searched in part
    add $4, %rdi
1:  test %ecx, %ecx
    jz \fail                        # no file of this name
    push %rsi
    push %rdi
    push %rcx
    add $FWCFG_FILE_NAME, %rdi
    mov $FETCH_NAME_LEN, %ecx
    repe cmpsb
    pop %rcx
    pop %rdi
    pop %rsi
    je 2f
    add $FWCFG_FILE_LEN, %rdi
    dec %ecx
    jmp 1b
    # Exactly as long as the file this image was built from: a shorter one
    # would leave zeros where the kernel was, which the digest catches anyway,
    # but a longer one is a different file and is refused as one.
2:  mov (%rdi), %eax
    bswap %eax
    mov FETCH_SKIP(%rbp), %rdx
    add FETCH_SIZE(%rbp), %rdx
    cmp %rdx, %rax
    jne \fail
    movzwl FWCFG_FILE_SELECT(%rdi), %eax
    xchg %al, %ah
    shl $16, %eax
    or $(FWCFG_DMA_SELECT | FWCFG_DMA_SKIP), %eax
    mov FETCH_SKIP(%rbp), %ecx
    xor %edx, %edx
    call fwcfg_dma
    mov FETCH_DEST(%rbp), %r12      # where the next piece goes
    mov FETCH_SIZE(%rbp), %r13      # how much is left
3:  test %r13, %r13
    jz 4f
    mov $FETCH_BOUNCE_SIZE, %ecx
    cmp %rcx, %r13
    cmovb %r13, %rcx
    push %rcx
    mov $FWCFG_DMA_READ, %eax
    mov $FETCH_BOUNCE, %edx
    call fwcfg_dma
    pop %rcx
    mov $FETCH_BOUNCE_ALIAS, %rsi
    mov %r12, %rdi
    add %rcx, %r12
    sub %rcx, %r13
    rep movsb
    jmp 3b
    # The private copy, never the shared one, is what is held to the digest.
4:  mov FETCH_DEST(%rbp), %rsi
    mov FETCH_SIZE(%rbp), %rcx
    sub $32, %rsp
    mov %rsp, %rdi
    call sha256
    mov %rsp, %rsi
    lea FETCH_DIGEST(%rbp), %rdi
    mov $32, %ecx
    repe cmpsb
    lea 32(%rsp), %rsp
    jne \mismatch
    ret

# One fw_cfg DMA access: control %eax, length %ecx, address %rdx. The access is
# written big-endian through the alias, its GPA handed to the device a half at
# a time, and the device clears the control word once the transfer is done.
# Clobbers rax, rcx, rdx and rdi.
fwcfg_dma:
    mov $FWCFG_DMA, %rdi
    bswap %eax
    mov %eax, (%rdi)
    bswap %ecx
    mov %ecx, 4(%rdi)
    bswap %rdx
    mov %rdx, 8(%rdi)
    xor %eax, %eax                  # the high half of the GPA, which is zero
    mov $FWCFG_PORT_DMA, %edx
    call ioio_out
    mov $FWCFG_DMA_GPA_BE, %eax
    mov $(FWCFG_PORT_DMA + 4), %edx
    call ioio_out
    mov $FWCFG_DMA, %rdi
    cmpl $0, (%rdi)
    jne \fail                       # an error, or a transfer left unfinished
    ret

# OUT %eax to port %edx through the block, which is shared for the length of
# the fetch. The host reports whether it took the request as it does for a
# page state change. Clobbers rax, rcx, rdx and rdi.
ioio_out:
    mov $GHCB_ALIAS, %rcx
    movq $0, GHCB_VALID_BITMAP(%rcx)
    movq $0, GHCB_VALID_BITMAP+8(%rcx)
    movb $GHCB_IOIO_VALID_BITS, GHCB_VALID_BITMAP+GHCB_VALID_BYTE(%rcx)
    orb $GHCB_RAX_VALID_BIT, GHCB_VALID_BITMAP+GHCB_RAX_VALID_BYTE(%rcx)
    movl $0, GHCB_USAGE(%rcx)
    movw $GHCB_PROTOCOL, GHCB_PROTOCOL_VERSION(%rcx)
    mov %eax, %eax
    mov %rax, GHCB_RAX(%rcx)
    movq $SVM_EXIT_IOIO, GHCB_SW_EXIT_CODE(%rcx)
    shl $16, %edx
    or $(IOIO_SZ32 | IOIO_A64), %edx
    mov %rdx, GHCB_SW_EXIT_INFO_1(%rcx)
    movq $0, GHCB_SW_EXIT_INFO_2(%rcx)
    \exit
    mov GHCB_SW_EXIT_INFO_1(%rcx), %eax
    or GHCB_SW_EXIT_INFO_2(%rcx), %rax
    jnz \fail
    ret

.endm
