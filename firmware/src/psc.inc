# Page state changes: how a guest on SEV-SNP makes its own memory private,
# rather than being handed RAM a loader already converted. The image declares
# only the pages it loads as required memory, so everything the accept walk
# reaches is still shared when the walk reaches it, and has to be asked for.
#
#   \fail    where a host that will not finish a request terminates
#   \issue   one VMGEXIT for the batch described at PSC_BUFFER, returning only
#            if the host took the request. It may clobber rax, rcx, rdx and
#            rdi, and nothing else: the caller of psc_range holds the range it
#            is about to validate in r12 and r13 across the whole conversion,
#            so an \issue that trod on those would validate memory no one
#            converted, which is the silence this file exists to prevent.
#
# This builds the GHCB page protocol's descriptor, not the MSR protocol's
# request. The MSR protocol converts one 4 KiB page per VMGEXIT: two million
# exits for an 8 GiB guest, five hundred million for the largest map this image
# describes. One descriptor names 253 spans of 2 MiB apiece, and a host that
# coalesces them converts half a gigabyte an exit. The MSR protocol is still
# what shares the block the descriptor lives in: see snp_reset.S.
#
# Nothing here is privileged -- the one exit is inside \issue -- and the only
# addresses it names are this layout's own, so the same assembly runs in the
# test harness that holds it to the ranges boot.rs says a walk produces.

.macro psc_code fail, issue

# Make [%r9, %r10) private, in batches of at most PSC_MAX_ENTRIES entries,
# preferring 2 MiB wherever the range is aligned for one and long enough to
# hold it -- the size PVALIDATE prefers too, so the two agree on what the RMP
# entry covers. Returns with %r9 at %r10.
# Clobbers rax, rcx, rdx, rdi, r11, r14, and whatever \issue clobbers.
psc_range:
    cmp %r10, %r9
    jae 9f
1:  mov $PSC_BUFFER, %rdi
    xor %r11d, %r11d                # entries described in this batch
    movq $0, PSC_CUR_ENTRY(%rdi)    # the header, which the host moves through
2:  mov %r9, %rax                   # a page-aligned address is already a page number
    bts $PSC_ENTRY_PRIVATE, %rax
    mov $PAGE, %ecx                 # what this entry covers
    test $0x1fffff, %r9d
    jnz 3f                          # not on a 2 MiB boundary
    mov %r10, %rdx
    sub %r9, %rdx
    cmp $0x200000, %rdx
    jb 3f                           # a 2 MiB entry would run past the range
    bts $PSC_ENTRY_LARGE, %rax
    mov $0x200000, %ecx
3:  mov %rax, PSC_ENTRIES(%rdi,%r11,8)
    add %rcx, %r9
    inc %r11d
    cmp %r10, %r9
    jae 4f
    cmp $PSC_MAX_ENTRIES, %r11d
    jb 2b
4:  dec %r11d                       # end_entry names the last entry described
    mov %r11w, PSC_END_ENTRY(%rdi)
    call psc_complete
    cmp %r10, %r9
    jb 1b
9:  ret

# The batch at PSC_BUFFER, repeated until the header says every entry of it is
# done: the host is free to return having converted only part of one. A header
# that stopped moving is a host that is not going to finish, and is refused
# rather than spun on, because a shim with no console cannot say it is stuck.
# Clobbers rax, rcx, rdx, rdi and r14.
psc_complete:
    mov $PSC_BUFFER, %rdi
1:  movzwl PSC_CUR_ENTRY(%rdi), %eax
    cmp PSC_END_ENTRY(%rdi), %ax
    ja 9f                           # past the last entry: all of them are done
    mov %eax, %r14d                 # where it had reached, so progress is checked
    call \issue
    mov $PSC_BUFFER, %rdi
    movzwl PSC_CUR_ENTRY(%rdi), %eax
    cmp %r14d, %eax
    jbe \fail                       # it did not move, and it will not
    jmp 1b
9:  ret
.endm
