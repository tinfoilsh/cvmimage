.include "layout.inc"
.include "madt.inc"
.section .reset,"ax"

.code32
.global snp_reset_start
# Nothing before wake_aps may depend on CPUID, an MSR, I/O, the GHCB or an exception;
# the wake is the shim's one conversation with the host, after all private RAM is valid.
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

    # Linux finds unvalidated memory only through EFI, so guest RAM is validated here.
    lea shim_data(%rip), %rbp
    add $8, %rbp
validate_next:
    mov (%rbp), %r12
    mov 8(%rbp), %r13
    mov %r12, %rax
    or %r13, %rax
    jz wake_aps
    add $16, %rbp
    call validate_range
    jmp validate_next

    # Every application processor launched into KVM's wait-for-SIPI state, and
    # only an INIT leaves it. With no firmware to send one the boot processor
    # does, as firmware would: INIT then SIPI to all-but-self, after which each
    # AP runs its own measured VMSA into the park stub below. Under SEV-ES the
    # local APIC is reachable only through the GHCB, so one measured page is
    # first rescinded, made shared and registered as this processor's GHCB, and
    # returned to private once the interrupts are sent. Each step numbers itself
    # in %r15d so a failure names the step in its termination code.
wake_aps:
    mov $1, %r15d
    mov $SNP_GHCB, %eax
    xor %ecx, %ecx
    xor %edx, %edx                  # rescind validation
    pvalidate
    test %eax, %eax
    jnz die_wake
    mov $2, %r15d
    movabs $(SNP_GHCB | (2 << 52) | 0x14), %rax   # page state change: shared
    call ghcb_msr
    mov %rax, %rdx
    shr $32, %rdx
    jnz die_wake                    # error code in the high half
    and $0xfff, %eax
    cmp $0x15, %eax
    jne die_wake
    mov $3, %r15d
    mov $(SNP_GHCB | 0x12), %eax    # register the GHCB GPA
    call ghcb_msr
    cmp $(SNP_GHCB | 0x13), %rax
    jne die_wake
    mov $4, %r15d
    movabs $(SHARED_ALIAS + SNP_GHCB), %rbx
    mov %rbx, %rdi
    xor %eax, %eax
    mov $512, %ecx
    rep stosq
    mov $0xc4500, %esi              # INIT, all excluding self
    call send_ipi
    mov $5, %r15d
    mov $0xc4600, %esi              # SIPI, all excluding self
    call send_ipi
    mov $6, %r15d
    call send_ipi
    mov $7, %r15d
    movabs $(SNP_GHCB | (1 << 52) | 0x14), %rax   # page state change: private
    call ghcb_msr
    mov %rax, %rdx
    shr $32, %rdx
    jnz die_wake
    and $0xfff, %eax
    cmp $0x15, %eax
    jne die_wake
    mov $8, %r15d
    mov $SNP_GHCB, %eax
    xor %ecx, %ecx
    mov $1, %edx                    # validate again, so Linux sees only private RAM
    pvalidate
    test %eax, %eax
    jnz die_wake

    # The one table the measurement leaves to the shim; SNP launches every
    # processor itself, so it carries no wakeup structure.
    mov $9, %r15d
    madt_build die_wake, 0

snp_boot_kernel:
    mov $ZERO_PAGE, %rsi
    lea shim_data(%rip), %rax
    jmp *(%rax)

# Write %esi to the local APIC's ICR: an MMIO write over the GHCB at %rbx.
send_ipi:
    mov %esi, 0x800(%rbx)           # the shared buffer carries the data
    mov $0x80000002, %eax           # SVM_VMGEXIT_MMIO_WRITE
    mov %rax, 0x390(%rbx)
    mov $0xfee00300, %eax           # ICR low
    mov %rax, 0x398(%rbx)
    movq $4, 0x3a0(%rbx)
    mov $(SNP_GHCB + 0x800), %eax
    mov %rax, 0x3a8(%rbx)
    movq $0, 0x3f0(%rbx)
    movq $0, 0x3f8(%rbx)
    movb $0x3c, 0x3fe(%rbx)         # exit code, both infos and scratch are valid
    movw $2, 0xffa(%rbx)
    movl $0, 0xffc(%rbx)
    mov $0xc0010130, %ecx
    mov $SNP_GHCB, %eax
    xor %edx, %edx
    wrmsr
    vmgexit
    mov 0x398(%rbx), %eax
    test %eax, %eax
    jnz die_wake
    ret

# The GHCB MSR protocol: request in %rax, response back in %rax.
ghcb_msr:
    mov $0xc0010130, %ecx
    mov %rax, %rdx
    shr $32, %rdx
    wrmsr
    vmgexit
    rdmsr
    shl $32, %rdx
    or %rdx, %rax
    ret

# Terminate with reason set 0xf and the wake step in %r15d as the code.
die_wake:
    mov %r15d, %eax
    shl $16, %eax
    or $0xf100, %eax
    xor %edx, %edx
    mov $0xc0010130, %ecx
    wrmsr
    vmgexit
    jmp fatal

# Before the wake, the GHCB MSR termination request is the only host channel.
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

    # An application processor launches from its own measured VMSA in 32-bit
    # protected mode and parks here until Linux creates it for real through the
    # GHCB AP-creation call, which replaces this VMSA wholesale.
    #
    # The wait is an AP Reset Hold over the GHCB MSR protocol, not a HLT: under
    # SEV-ES a HLT is a non-automatic exit, so it would raise #VC into an AP that
    # has no IDT and triple-fault it. Reset Hold is the one park the hypervisor
    # can resume, and like the termination request below it needs no GHCB page.
    .code32
    .org SHIM_AP_PARK
.global snp_ap_park
snp_ap_park:
    cli
1:  mov $0xc0010130, %ecx
    xor %edx, %edx
    mov $6, %eax                    # GHCB MSR AP Reset Hold request
    wrmsr
    vmgexit
    jmp 1b                          # re-park if the host resumes us early

    .org SHIM_MADT
madt_template:
    madt_header

    # The kernel entry point and the ranges to validate, written here by the builder.
    .org SHIM_DATA
shim_data:
    .fill SHIM_DATA_SIZE,1,0

    .fill 0x1000-(.-snp_reset_start),1,0
