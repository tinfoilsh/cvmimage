# Memory Linux accepts itself. Accepting every page before Linux starts costs a
# host conversion a page -- about half a second a GiB -- so past a measured
# bound the shim accepts only what does not fill a whole 2-MiB unit, and marks
# each unit that does in the bitmap of the unaccepted table efi.rs describes.
# Linux accepts a marked unit when it first allocates from it, as it does on
# an OVMF launch.
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
