# The shim's own assembly, assembled from the same macros the reset stubs are
# and called from a test. Nothing in madt.inc or map.inc runs a privileged
# instruction or names an address a caller has not passed it, so all of it runs
# in a userspace process with the pages it reads mapped at their real addresses
# -- which is what holds the shipped assembly, rather than a re-implementation
# of it, to the generators in acpi.rs and boot.rs.
#
# This object is linked into the crate's tests. It is not measured and no guest
# ever executes it.

.include "layout.inc"
.include "madt.inc"
.include "map.inc"

.text
map_code harness_fail, harness_accept

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

# () -> the top of guest RAM, or zero if the map was refused, with the merged
# region list left where the shim leaves it.
.globl harness_regions
harness_regions:
    harness_enter
    call host_regions
    call merge_regions
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

# (zero page, top of RAM) -> 1, or zero if the map was refused.
.globl harness_e820
harness_e820:
    harness_enter
    mov %rsi, %r8
    call e820_build
    mov $1, %eax
    jmp harness_ret

# (top of RAM) -> how many ranges accept_walk asked for, recorded in
# harness_ranges; zero if the walk was refused, which it cannot be.
.globl harness_accept_walk
harness_accept_walk:
    harness_enter
    mov %rdi, %r8
    movq $0, harness_count(%rip)
    call accept_walk
    mov harness_count(%rip), %rax
    jmp harness_ret

# What the shims give PVALIDATE and TDG.MEM.PAGE.ACCEPT: the empty range is
# dropped here exactly as both of them drop it.
harness_accept:
    cmp %r13, %r12
    jae 1f
    mov harness_count(%rip), %rax
    shl $4, %rax
    lea harness_ranges(%rip), %rcx
    mov %r12, (%rcx,%rax)
    mov %r13, 8(%rcx,%rax)
    shr $4, %rax
    inc %rax
    mov %rax, harness_count(%rip)
1:  ret

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
# The data block the shims carry in their measured page, which a test fills.
.globl harness_shim_data
harness_shim_data:
shim_data:
    .fill SHIM_DATA_SIZE,1,0

# Room for every range a walk of a full data block can produce.
.globl harness_ranges
harness_ranges:
    .fill 4096,1,0

harness_sp:
    .quad 0
harness_count:
    .quad 0

# The header madt_build copies, which each shim carries in its measured page.
.globl harness_madt_template
harness_madt_template:
madt_template:
    madt_header
