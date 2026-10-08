# Page state changes: how a guest on SEV-SNP makes its own memory private,
# rather than being handed RAM a loader already converted. The image declares
# only the pages it loads as required memory, so everything the accept walk
# reaches is still shared when the walk reaches it, and has to be asked for.
#
#   \fail    where a host that will not finish a request terminates
#   \exit    the VMGEXIT itself, which returns once the host has answered. It
#            may clobber rax, rdx and rdi, and nothing else: psc_vmgexit holds
#            the block in rcx across it, psc_complete the batch's end_entry in
#            r11, and the caller of psc_range holds the
#            range it is about to validate in r12 and r13 across the whole
#            conversion, so an \exit that trod on those would validate memory
#            no one converted, which is the silence this file exists to
#            prevent.
#
# This builds the GHCB page protocol's descriptor, not the MSR protocol's
# request. The MSR protocol converts one 4 KiB page per VMGEXIT: two million
# exits for an 8 GiB guest, five hundred million for the largest map this image
# describes. One descriptor names 253 spans of 2 MiB apiece, and a host that
# coalesces them converts half a gigabyte an exit. The MSR protocol is still
# what shares the block the descriptor lives in: see snp_reset.S.
#
# Nothing here is privileged -- the one exit is \exit itself -- and the only
# addresses it names are this layout's own, so the same assembly runs in the
# test harness that holds it to the ranges boot.rs says a walk produces and to
# the request the GHCB specification defines.

.macro psc_code fail, exit

# Make [%r9, %r10) private, in batches of at most PSC_MAX_ENTRIES entries,
# preferring 2 MiB wherever the range is aligned for one and long enough to
# hold it -- the size PVALIDATE prefers too, so the two agree on what the RMP
# entry covers. Returns with %r9 at %r10.
# Clobbers rax, rcx, rdx, rdi, r11, r14, and whatever \exit clobbers.
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
# done: the host may return having converted only part of it, and part of one
# entry at that, which it reports by moving the page cursor that entry carries
# rather than the entry index in the header. What has to rise is the pair of
# the two. A pair that stopped rising is a host that is not going to finish,
# and is refused rather than spun on, because a shim with no console cannot
# say it is stuck.
#
# The entry that cursor is read from is the one the header names, so it is
# bounded by the end_entry psc_range wrote, held in r11. The host's copy is
# read once and must still match it.
# Clobbers rax, rcx, rdx, rdi and r14.
psc_complete:
    mov $PSC_BUFFER, %rdi
    xor %r14d, %r14d                # how far the host had got, which must rise
    jmp 2f
1:  call psc_vmgexit
    mov $PSC_BUFFER, %rdi
2:  cmp PSC_END_ENTRY(%rdi), %r11w
    jne \fail
    movzwl PSC_CUR_ENTRY(%rdi), %eax
    cmp %r11d, %eax
    ja 9f                           # past the last entry: all of them are done
    mov PSC_ENTRIES(%rdi,%rax,8), %ecx
    and $PSC_ENTRY_CUR_PAGE, %ecx   # how far into that entry it reached
    shl $12, %eax
    or %ecx, %eax
    inc %eax                        # so the first exit beats having done nothing
    cmp %r14d, %eax
    jbe \fail                       # it did not move, and it will not
    mov %eax, %r14d
    jmp 1b
9:  ret

# One batch of page state changes through the block: the request the GHCB
# specification defines for them, naming the descriptor by the address the
# host reads it at rather than the alias this writes it through. The host
# reports whether it took the request in the block's own fields, and a request
# it did not take is not retried: psc_complete only repeats one the host
# accepted and left unfinished.
# Clobbers rax, rdx and rdi, and holds the block in rcx across \exit.
psc_vmgexit:
    mov $GHCB_ALIAS, %rcx
    # Nothing in the block is valid but the four fields this request states.
    movq $0, GHCB_VALID_BITMAP(%rcx)
    movq $0, GHCB_VALID_BITMAP+8(%rcx)
    movb $GHCB_VALID_BITS, GHCB_VALID_BITMAP+GHCB_VALID_BYTE(%rcx)
    movl $0, GHCB_USAGE(%rcx)
    movw $GHCB_PROTOCOL, GHCB_PROTOCOL_VERSION(%rcx)
    movl $SVM_VMGEXIT_PSC, GHCB_SW_EXIT_CODE(%rcx)
    movl $0, GHCB_SW_EXIT_CODE+4(%rcx)
    movq $0, GHCB_SW_EXIT_INFO_1(%rcx)
    movq $0, GHCB_SW_EXIT_INFO_2(%rcx)
    movq $PSC_BUFFER_GPA, GHCB_SW_SCRATCH(%rcx)
    \exit
    # The result is the low half of the first field, and the page state
    # change's own error code is the whole of the second.
    mov GHCB_SW_EXIT_INFO_1(%rcx), %eax
    or GHCB_SW_EXIT_INFO_2(%rcx), %rax
    jnz \fail
    ret
.endm
