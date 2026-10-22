.include "layout.inc"
.include "madt.inc"
.include "shape.inc"
.section .reset,"ax"

.code32
.global reset_start
reset_start:
    # TDH.VP.INIT starts every vCPU here in 32-bit protected mode, ESI the vCPU index.
    cli
    cld
    # MRTD covers no vCPU state, so the handed-over descriptors give way to the measured GDT.
    mov $GDT_PTR, %eax
    lgdt (%eax)
    ljmp $BOOT_CS32, $(RESET_ALIAS + (flat32 - reset_start))
flat32:
    mov $BOOT_DS, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %ss
    mov %eax, %fs
    mov %eax, %gs
    # The module leaves EFER.LME set, so PAE and paging are the whole transition.
    mov %cr4, %eax
    bts $5, %eax
    mov %eax, %cr4
    mov $PAGE_TABLES, %eax
    mov %eax, %cr3
    # Clearing a bit the module fixes in CR0 or CR4 is a #GP, so both are read-modify-written.
    mov %cr0, %eax
    bts $31, %eax
    mov %eax, %cr0
    ljmp $BOOT_CS, $(RESET_ALIAS + (long_mode - reset_start))

.code64
long_mode:
    test %esi, %esi
    jnz ap_wait
    mov $BSP_STACK_TOP, %rsp

    # The guest's map is one of the shapes the image measured: its E820 and
    # EFI tables are copied, and only the top of RAM is the loader's to say.
    # The RAM Linux needs before it can accept any arrives accepted, as
    # measured pages; the rest Linux accepts as it allocates, finding the
    # units it has to in the EFI table efi.rs describes. The MADT is the other table left to the shim.
    call shape_match
    mov $ZERO_PAGE, %edi
    call shape_apply
    call mark_lazy

    madt_build die, 1
    mov $ZERO_PAGE, %rsi
    lea shim_data(%rip), %rax
    jmp *(%rax)

shape_code die_map

# A map this image will not run in.
die_map:
    xor %r12d, %r12d
    jmp die

# APs wait here until the OS claims them through the measured ACPI wakeup mailbox.
ap_wait:
    mov $MAILBOX, %rbx
ap_poll:
    pause
    mov (%rbx), %eax
    cmp $1, %eax
    jne ap_poll
    mov 4(%rbx), %eax
    cmp %esi, %eax
    jne ap_poll
    mov 8(%rbx), %rax
    test %rax, %rax
    jz ap_poll
    movl $0, (%rbx)
    jmp *%rax

# TDG.VP.VMCALL<ReportFatalError> reports a boot failure to the host.
die:
    mov $0x1c00, %ecx               # expose R10, R11 and R12 to the host
    xor %r10d, %r10d                # standard GHCI
    mov $0x10003, %r11d             # ReportFatalError
    xor %eax, %eax                  # TDG.VP.VMCALL
    tdcall
fatal:
    cli
    hlt
    jmp fatal

    .org SHIM_MADT
madt_template:
    madt_header

    # The entry point and the shape count, written here by the builder.
    .org SHIM_DATA
shim_data:
    .fill SHIM_DATA_SIZE,1,0

    .org RESET_VECTOR
reset_vector:
    jmp reset_start
    .fill 0x1000-(.-reset_start),1,0
