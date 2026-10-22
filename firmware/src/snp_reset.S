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
    # RAM below the lazy bound arrives validated, as measured pages; past it,
    # Linux converts and validates the units it allocates, finding them in
    # the EFI table efi.rs describes.
    call shape_match
    mov $ZERO_PAGE, %edi
    call shape_apply
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

shape_code die_map

# A map that is no shape this image knows, which is step 1 of the sequence
# above. KVM prints a termination request's reason set and code, so which
# refusal happened is readable on the host though the guest has no console.
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

    .org SHIM_MADT
madt_template:
    madt_header

    # The entry point, the shape count, the lazy bound and the ranges to
    # accept, all written here by the builder.
    .org SHIM_DATA
shim_data:
    .fill SHIM_DATA_SIZE,1,0

    .fill 0x1000-(.-snp_reset_start),1,0
