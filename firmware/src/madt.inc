# The MADT, built by the shim so that the processor count stays out of the
# measurement. Everything fixed about the table is the measured template below;
# the count comes from the parameter page the loader fills, is bounded here, and
# decides only how many Local APIC entries follow.

# Clobbers rax, rbx, rcx, rdx, rsi, rdi and r12, which names the count if it is refused.
.macro madt_build fail, wakeup
    mov $PARAM_PAGE, %eax
    mov (%rax), %r12d
    test %r12d, %r12d
    jz \fail
    cmp $MAX_VCPUS, %r12d
    ja \fail
    mov $(ACPI_BASE + ACPI_MADT), %edi
    mov %rdi, %rbx
    lea madt_template(%rip), %rsi
    mov $MADT_HEADER_LEN, %ecx
    rep movsb
    xor %eax, %eax
1:  movzbl %al, %edx                # an 8-bit ACPI id, then the same APIC id
    imul $0x01010000, %edx, %edx
    or $((MADT_LAPIC_LEN << 8) | MADT_LOCAL_APIC), %edx
    mov %edx, (%rdi)
    movl $LAPIC_ENABLED, 4(%rdi)
    add $MADT_LAPIC_LEN, %rdi
    inc %eax
    cmp %r12d, %eax
    jb 1b
.if \wakeup
    movl $((MADT_WAKEUP_LEN << 8) | MADT_WAKEUP), (%rdi)
    movl $0, 4(%rdi)
    movq $MAILBOX, 8(%rdi)
    add $MADT_WAKEUP_LEN, %rdi
.endif
    mov %edi, %eax
    sub %ebx, %eax
    mov %eax, 4(%rbx)               # the length the entries came to
    mov %eax, %ecx
    mov %rbx, %rsi
    xor %edx, %edx
2:  addb (%rsi), %dl
    inc %rsi
    dec %ecx
    jnz 2b
    neg %dl
    mov %dl, 9(%rbx)                # every byte of an ACPI table sums to zero
.endm

# The header acpi.rs states, with the length and checksum left to madt_build.
.macro madt_header
    .ascii "APIC"
    .long 0
    .byte 6
    .byte 0
    .ascii "TINFOI"
    .ascii "TINFOIL "
    .long 1
    .ascii "TFNL"
    .long 1
    .long 0xfee00000
    .long 1
.endm
