.include "layout.inc"
.include "madt.inc"
.include "shape.inc"
.section .reset,"ax"

.code64
.global snp_reset_start
# The VMSA hands over 64-bit long mode on the measured page tables, with the
# stack, the data segments and RFLAGS (interrupts and direction clear) already
# as the shim needs them (vmsa.rs), so there is no mode switch to make.
# Nothing here may depend on CPUID, trapped I/O or an exception, and nothing
# exits to the host but a request to terminate.
snp_reset_start:
    # The guest's map is one of the shapes the image measured: its E820 and
    # EFI tables are copied, and only the top of RAM is the loader's to say.
    # RAM below the lazy bound, and what the image leaves free of the units
    # it places in past it, is validated here, from a measured list the image
    # also declares as required memory, so the loader has made it private
    # before the guest runs; the remaining units Linux converts and validates
    # as it allocates, finding them in the EFI table efi.rs describes.
    call shape_match
    mov $ZERO_PAGE, %edi
    call shape_apply
    call accept_fixed
    call mark_lazy

    # The one table the measurement leaves to the shim. SNP carries no wakeup
    # structure: Linux starts an application processor with a save area it
    # builds itself and hands over through the GHCB, needing nothing from here.
    # Each step numbers itself in %r15d so a failure names it in its code.
    mov $2, %r15d
    madt_build die_step, 0

    mov $ZERO_PAGE, %rsi
    lea shim_data(%rip), %rax
    jmp *(%rax)

shape_code die_map, validate_range

# A map that is no shape this image knows, which is step 1 of the sequence
# above. KVM prints a termination request's reason set and code, so which
# refusal happened is readable on the host though the guest has no console.
# PVALIDATE refusing a page is another, reported by `die`.
die_map:
    mov $1, %r15d
    jmp die_step

# Boot failures use the GHCB MSR termination request:
# reason set 0xf, which is this shim's own, and the code in %r15d. The set is
# where the protocol puts the subsystem -- sets 0 and 1 are the ones the GHCB
# specification and Linux define -- so the failure goes in the code, where a
# host reading it cannot take it for either of those.
die_step:
    mov %r15d, %eax
    shl $16, %eax
    or $0xf100, %eax
    xor %edx, %edx
    mov $GHCB_MSR, %ecx
    wrmsr
    vmgexit
fatal:
    cli
    hlt
    jmp fatal

# PVALIDATE refused a page: the status it reported and the carry flag that
# says the page was already in the state asked for, under a code of their own
# well clear of the steps above.
die:
    and $7, %r15d
    shl $3, %ebx
    or %ebx, %r15d
    or $0x80, %r15d
    jmp die_step

# Validate [%r12, %r13) as private memory, preferring 2 MiB pages, and zero
# it. The loader made it private before launch because the image declares it
# required memory; a page it did not is an RMP violation, not a status the
# guest reads back, and the guest stops there. PVALIDATE reports status in EAX.
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
    movzbl %bl, %ebx                # %ebx arrives holding the shape, not zero
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
    movzbl %bl, %ebx                # %ebx arrives holding the shape, not zero
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

    # The entry point, the shape count, the lazy bound and the ranges to
    # accept, all written here by the builder.
    .org SHIM_DATA
shim_data:
    .fill SHIM_DATA_SIZE,1,0

    .fill 0x1000-(.-snp_reset_start),1,0
