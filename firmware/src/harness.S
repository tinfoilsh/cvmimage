# The shim's own assembly, assembled from the same macros the reset stubs are
# and called from a test. Neither madt.inc nor shape.inc runs a
# privileged instruction, and the only addresses they name are this layout's
# own, so all of it runs in a userspace process with those pages mapped where a
# guest has them -- which is what holds the shipped assembly, rather than a
# re-implementation of it, to the generators in acpi.rs and boot.rs.
#
# This object is linked into the crate's tests. It is not measured and no guest
# ever executes it.

.include "layout.inc"
.include "madt.inc"
.include "shape.inc"

.text
shape_code harness_fail, harness_accept

# The System V registers a caller owns, saved once so that a refusal deep inside
# a macro can return through the same epilogue an ordinary return does.
.macro harness_enter
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rsp, harness_sp(%rip)
.endm

# (zero page) -> the top of guest RAM, or zero if the map was refused: the
# boot path both shims run, with harness_accept standing in for the platform's
# accept. What it accepted is in harness_ranges, what it leaves to Linux in the
# bitmap, and the tables it wrote in that zero page and the EFI page.
.globl harness_boot_map
harness_boot_map:
    harness_enter
    mov %rdi, %r15
    movq $0, harness_count(%rip)
    call shape_match
    mov %r15, %rdi
    call shape_apply
    call accept_fixed
    call mark_lazy
    mov %r8, %rax
harness_ret:
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    ret

harness_fail:
    mov harness_sp(%rip), %rsp
    xor %eax, %eax
    jmp harness_ret

# What the shims give PVALIDATE and TDG.MEM.PAGE.ACCEPT: the empty range is
# dropped here exactly as both of them drop it. It leaves every register the
# real ones may (validate_range, accept_range) holding garbage and
# %r12 at the end of the range, so a caller that kept something there across
# the call fails here rather than only in a guest.
harness_accept:
    cmp %r13, %r12
    jae 1f
    mov harness_count(%rip), %rax
    cmp $HARNESS_RANGES, %rax
    jae harness_fail                # before the counter the test reads is overrun
    shl $4, %rax
    lea harness_ranges(%rip), %rcx
    mov %r12, (%rcx,%rax)
    mov %r13, 8(%rcx,%rax)
    shr $4, %rax
    inc %rax
    mov %rax, harness_count(%rip)
1:  mov %r13, %r12
    movabs $HARNESS_POISON, %rax
    mov %rax, %rbx
    mov %rax, %rcx
    mov %rax, %rdx
    mov %rax, %rdi
    mov %rax, %rsi
    mov %rax, %r9
    mov %rax, %r10
    mov %rax, %r11
    mov %rax, %r14
    mov %rax, %r15
    ret

.set HARNESS_POISON, 0x0bad0bad0bad0bad

# () -> 1, or zero if the processor count was refused. The wakeup structure is
# an assembly-time choice, so each platform's table gets its own entry point.
.globl harness_madt_wakeup
harness_madt_wakeup:
    harness_enter
    madt_build harness_fail, 1
    mov $1, %eax
    jmp harness_ret

.globl harness_madt_bare
harness_madt_bare:
    harness_enter
    madt_build harness_fail, 0
    mov $1, %eax
    jmp harness_ret

.data
.balign 8
# The data block the shims carry in their measured page, which a test fills.
.globl harness_shim_data
harness_shim_data:
shim_data:
    .fill SHIM_DATA_SIZE,1,0

# Room for every range the data block can list.
.set HARNESS_RANGES, 256
.balign 8
.globl harness_ranges
harness_ranges:
    .fill HARNESS_RANGES * 16,1,0

.balign 8
harness_sp:
    .quad 0
.globl harness_count
harness_count:
    .quad 0

# The header madt_build copies, which each shim carries in its measured page.
.globl harness_madt_template
harness_madt_template:
madt_template:
    madt_header
