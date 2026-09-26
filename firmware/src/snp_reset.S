.include "layout.inc"
.include "madt.inc"
.include "map.inc"
.section .reset,"ax"

.code32
.global snp_reset_start
# Nothing here may depend on CPUID, an MSR, I/O, the GHCB or an exception: the shim
# never speaks to the host except to terminate.
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
    # Linux finds unvalidated memory only through EFI, so guest RAM is validated here.
    call accept_walk

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

map_code die_map, validate_range

# A map this image will not run in, which is step 2 of the sequence above.
die_map:
    mov $2, %r15d
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
