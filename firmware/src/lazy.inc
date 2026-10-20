# Memory Linux accepts itself. Accepting every page before Linux starts costs a
# host conversion a page and a pass over all of RAM, so past a measured bound
# the shim accepts only what does not fill a whole 2-MiB unit, and marks each
# unit that does in the bitmap of the unaccepted table efi.rs describes. Linux
# accepts a marked unit when it first allocates from it, as it does on an OVMF
# launch, and clears it then as init_on_free clears any page it frees.
#
# A bit is only ever set for a unit no part of which the shim accepted or the
# loader placed: a unit validated twice terminates the guest. Below the bound,
# where the decompressor runs before Linux's acceptance does, nothing is marked.
#
#   \accept  accepts [%r12, %r13) as private memory, as map.inc's does
#
# Nothing here is privileged, so the harness runs it with \accept recording.

.macro lazy_code accept

# The bitmap's size, from the top of guest RAM in %r8: a bit a unit, rounded up
# to a byte, which is how much of it Linux reserves and reads.
unaccepted_size:
    lea (UNACCEPTED_UNIT * 8 - 1)(%r8), %rax
    shr $(UNACCEPTED_UNIT_SHIFT + 3), %rax
    mov %rax, UNACCEPTED_SIZE
    ret

# The memory map efi_info names, completed from the E820 map in the zero page
# %rdi points at: one conventional-memory descriptor a RAM entry, after the
# one the image measured for the EFI page. Linux's decompressor picks where to
# randomize the kernel to from this map alone (arch/x86/boot/compressed/
# kaslr.c), and accepts what it picks itself; Linux proper takes RAM from E820.
# A map longer than the page holds is cut short, which leaves KASLR fewer slots
# rather than a wrong one. Clobbers rax, rcx, rsi and r9.
efi_memmap_build:
    movzbl BP_E820_ENTRIES(%rdi), %ecx
    lea BP_E820_TABLE(%rdi), %rsi
    mov $(EFI_PAGE + EFI_MEMMAP + EFI_MEMDESC_SIZE), %r9d
1:  test %ecx, %ecx
    jz 3f
    cmpl $E820_RAM, 16(%rsi)
    jne 2f
    cmp $(EFI_PAGE + EFI_MEMMAP + EFI_MEMMAP_MAX * EFI_MEMDESC_SIZE), %r9d
    jae 3f
    movq $EFI_CONVENTIONAL_MEMORY, (%r9)    # the type, and the padding after it
    mov (%rsi), %rax
    mov %rax, 8(%r9)                # physical start
    movq $0, 16(%r9)                # virtual start
    mov 8(%rsi), %rax
    shr $12, %rax
    mov %rax, 24(%r9)               # pages: E820 bounds here are all page-aligned
    movq $EFI_MEMORY_WB, 32(%r9)
    movq $0, 40(%r9)
    add $EFI_MEMDESC_SIZE, %r9d
2:  add $E820_ENTRY_LEN, %rsi
    dec %ecx
    jmp 1b
3:  sub $(EFI_PAGE + EFI_MEMMAP), %r9d
    mov %r9d, BP_EFI_MEMMAP_SIZE(%rdi)
    ret

# [%r12, %r13) as the accept walk hands it over: below the bound in the data
# block, all of it; past it, the part units at each end, and a bit for each
# whole unit between. A range that starts on a unit boundary has its first
# unit accepted too, so the page before it -- the end of a span Linux frees
# later, such as the initramfs -- never abuts a unit Linux has not accepted,
# which load_unaligned_zeropad() would read into. Clobbers what \accept does,
# plus rax and rdx.
accept_lazy:
    lea UNACCEPTED_UNIT(%r12), %rax
    and $-UNACCEPTED_UNIT, %rax     # the first whole unit after the start...
    mov shim_data+SHIM_DATA_LAZY(%rip), %rdx
    cmp %rdx, %rax
    cmovb %rdx, %rax                # ...at or past the bound
    mov %r13, %rdx
    and $-UNACCEPTED_UNIT, %rdx     # the end of the last
    cmp %rdx, %rax
    jae \accept                     # no whole unit past it: all of it, now
    push %r13
    push %rdx
    push %rax
    mov %rax, %r13
    call \accept                    # everything before the first
    pop %rax
    pop %rdx
    shr $UNACCEPTED_UNIT_SHIFT, %rax
    shr $UNACCEPTED_UNIT_SHIFT, %rdx
2:  bts %rax, UNACCEPTED_BITMAP
    inc %rax
    cmp %rdx, %rax
    jb 2b
    shl $UNACCEPTED_UNIT_SHIFT, %rdx
    mov %rdx, %r12
    pop %r13
    jmp \accept                     # the part unit after the last
.endm
