.include "layout.inc"
.include "madt.inc"
.include "map.inc"
.include "psc.inc"
.section .reset,"ax"

.code32
.global snp_reset_start
# Nothing here may depend on CPUID, I/O or an exception. What it does ask the
# host for is page state changes, so that the guest makes its own memory
# private rather than a loader doing it: see psc.inc. Every other use of the
# GHCB MSR here is a termination request.
snp_reset_start:
    cli
    cld
    mov $BSP_STACK_TOP, %esp

    # The VMSA hands over 32-bit protected mode with paging off, so the shim enables it.
    mov $0xc0000080, %ecx
    rdmsr
    or $0x900, %eax                 # EFER.LME | EFER.NXE
    wrmsr
    mov $PAGE_TABLES, %eax
    mov %eax, %cr3
    mov %cr0, %eax
    bts $31, %eax
    mov %eax, %cr0
    call 1f
1:  pop %eax
    add $(snp_long_mode-1b), %eax
    push $BOOT_CS
    push %eax
    lret

.code64
snp_long_mode:
    mov $BOOT_DS, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %ss
    mov %eax, %fs
    mov %eax, %gs

    # The guest's own E820 map, which the measurement leaves to the shim because
    # measuring it would bind this image to a machine size.
    call host_regions
    call merge_regions
    mov $ZERO_PAGE, %edi
    call e820_build
    # Linux finds unvalidated memory only through EFI, so guest RAM is made
    # private and validated here, in that order and by the guest itself.
    call ghcb_share
    call accept_walk
    call ghcb_private

    # The one table the measurement leaves to the shim. SNP carries no wakeup
    # structure: Linux starts an application processor with a save area it
    # builds itself and hands over through the GHCB, needing nothing from here.
    # Each step numbers itself in %r15d so a failure names it in its code.
    mov $1, %r15d
    madt_build die_step, 0

snp_boot_kernel:
    mov $ZERO_PAGE, %rsi
    lea shim_data(%rip), %rax
    jmp *(%rax)

map_code die_map, accept_private
psc_code die_psc, psc_vmgexit

# A map this image will not run in, which is step 2 of the sequence above.
die_map:
    mov $2, %r15d
    jmp die_step

# The three ways the host can refuse to convert memory, numbered as steps 3 to
# 5: KVM prints a termination request's reason set and code, so which of them
# happened is readable on the host even though the guest has no console. A host
# that says it converted memory and did not leaves by the fourth way instead,
# PVALIDATE refusing the page in `die`.
die_ghcb_share:
    mov $3, %r15d
    jmp die_step
die_psc:
    mov $4, %r15d
    jmp die_step
die_ghcb_private:
    mov $5, %r15d
    jmp die_step

# Terminate with reason set 0xf and the step in %r15d as the code.
die_step:
    mov %r15d, %eax
    shl $16, %eax
    or $0xf100, %eax
    xor %edx, %edx
    mov $0xc0010130, %ecx
    wrmsr
    vmgexit
    jmp fatal

# The GHCB MSR termination request is the shim's only channel to the host.
die:
    mov %r12, %rax
    shr $21, %rax
    and $0xff, %eax
    shl $16, %eax
    and $7, %r15d
    shl $3, %ebx
    or %r15d, %ebx
    and $0xf, %ebx
    shl $12, %ebx
    or %ebx, %eax
    or $0x100, %eax
    xor %edx, %edx
    mov $0xc0010130, %ecx
    wrmsr
    vmgexit
fatal:
    cli
    hlt
    jmp fatal

# Accept [%r12, %r13): the host makes it private, then PVALIDATE takes it. The
# order is the whole point -- validating a page the RMP still calls shared
# fails, which is what an image that declared a machine's worth of required
# memory was hiding.
accept_private:
    mov %r12, %r9
    mov %r13, %r10
    call psc_range
    jmp validate_range

# The one request the MSR protocol has to carry: a descriptor the host reads
# needs a shared page to sit in, and the only way to share the page the
# descriptor sits in is a protocol that needs no page. The firmware validated
# the block as the image measured it, so its validation is rescinded first --
# private to shared is in that order, and shared to private in the other.
ghcb_share:
    mov $SNP_GHCB, %rax
    xor %ecx, %ecx                  # 4 KiB, as the firmware validated it
    xor %edx, %edx                  # rescind
    pvalidate
    jc die_ghcb_share               # it was not validated: not the measured state
    test %eax, %eax
    jnz die_ghcb_share
    mov $(GHCB_SHARE_REQ >> 32), %edx
    mov $(GHCB_SHARE_REQ & 0xffffffff), %eax
    call ghcb_msr
    test %edx, %edx                 # the response carries an error code up here
    jnz die_ghcb_share
    and $0xfff, %eax
    cmp $GHCB_MSR_PSC_RESP, %eax
    jne die_ghcb_share
    # A host reads no block it was not given the address of first.
    xor %edx, %edx
    mov $(SNP_GHCB | GHCB_MSR_REG_GPA_REQ), %eax
    call ghcb_msr
    cmp $(SNP_GHCB | GHCB_MSR_REG_GPA_RESP), %eax
    jne die_ghcb_share              # a response naming some other page
    test %edx, %edx
    jnz die_ghcb_share
    # GHCB info 0: the block itself, which is what the page protocol exits with.
    xor %edx, %edx
    mov $SNP_GHCB, %eax
    mov $GHCB_MSR, %ecx
    wrmsr
    ret

# ...and back, so the guest hands Linux the block in the state the image
# measured rather than a page its host can still write.
ghcb_private:
    mov $(GHCB_PRIVATE_REQ >> 32), %edx
    mov $(GHCB_PRIVATE_REQ & 0xffffffff), %eax
    call ghcb_msr
    test %edx, %edx
    jnz die_ghcb_private
    and $0xfff, %eax
    cmp $GHCB_MSR_PSC_RESP, %eax
    jne die_ghcb_private
    mov $SNP_GHCB, %rax
    xor %ecx, %ecx
    mov $1, %edx                    # validate
    pvalidate
    jc die_ghcb_private
    test %eax, %eax
    jnz die_ghcb_private
    mov $SNP_GHCB, %edi             # the descriptor is not what was measured here
    xor %eax, %eax
    mov $512, %ecx
    rep stosq
    # ...and the MSR back to the value a reset leaves in it, so the block is
    # not still named to a host that can no longer read it.
    xor %edx, %edx
    xor %eax, %eax
    mov $GHCB_MSR, %ecx
    wrmsr
    ret

# EDX:EAX as a GHCB MSR request -> EDX:EAX the response. The caller reads what
# the response puts where, because the two requests this shim makes put
# different things there.
ghcb_msr:
    mov $GHCB_MSR, %ecx
    wrmsr
    vmgexit
    mov $GHCB_MSR, %ecx
    rdmsr
    ret

# One batch of page state changes through the block. The host reports whether
# it took the request in the block's own fields, and a request it did not take
# is not retried: psc_complete only repeats one the host accepted and left
# unfinished.
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
    vmgexit
    # The result is the low half of the first field, and the page state
    # change's own error code is the whole of the second.
    mov GHCB_SW_EXIT_INFO_1(%rcx), %eax
    or GHCB_SW_EXIT_INFO_2(%rcx), %rax
    jnz die_psc
    ret

# Validate [%r12, %r13) as private memory, preferring 2 MiB; PVALIDATE reports status in EAX.
validate_range:
    cmp %r13, %r12
    jae validated
    test $0x1fffff, %r12
    jnz validate_4k
    lea 0x200000(%r12), %r14
    cmp %r13, %r14
    ja validate_4k
    mov %r12, %rax
    mov $1, %ecx
    mov $1, %edx
    pvalidate
    setc %bl
    movzbl %bl, %ebx                # %ebx arrives holding a cursor, not zero
    mov %eax, %r15d
    test %eax, %eax
    jnz size_2m
    test %bl, %bl
    jnz die                         # double validation is never accepted
    jmp zero_2m
size_2m:
    cmp $6, %eax                    # FAIL_SIZEMISMATCH: retry as 4 KiB pages
    jne die
validate_4k:
    mov %r12, %rax
    xor %ecx, %ecx
    mov $1, %edx
    pvalidate
    setc %bl
    movzbl %bl, %ebx                # %ebx arrives holding a cursor, not zero
    mov %eax, %r15d
    test %eax, %eax
    jnz die
    test %bl, %bl
    jnz die
    mov %r12, %rdi
    xor %eax, %eax
    mov $512, %ecx
    rep stosq
    add $PAGE, %r12
    jmp validate_range
zero_2m:
    mov %r12, %rdi
    xor %eax, %eax
    mov $0x40000, %ecx
    rep stosq
    add $0x200000, %r12
    jmp validate_range
validated:
    ret

    .org SHIM_MADT
madt_template:
    madt_header

    # The entry point, the least memory this image runs in, and the spans it
    # placed, all written here by the builder.
    .org SHIM_DATA
shim_data:
    .fill SHIM_DATA_SIZE,1,0

    .fill 0x1000-(.-snp_reset_start),1,0
