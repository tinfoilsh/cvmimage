# The shim's own assembly, assembled from the same macros the reset stubs are
# and called from a test. None of madt.inc, map.inc or psc.inc runs a
# privileged instruction, and the only addresses they name are this layout's
# own, so all of it runs in a userspace process with those pages mapped where a
# guest has them -- which is what holds the shipped assembly, rather than a
# re-implementation of it, to the generators in acpi.rs and boot.rs.
#
# This object is linked into the crate's tests. It is not measured and no guest
# ever executes it.

.include "layout.inc"
.include "madt.inc"
.include "map.inc"
.include "psc.inc"

.text
map_code harness_fail, harness_accept
psc_code harness_fail, harness_psc_issue

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
    cmp $HARNESS_RANGES, %rax
    jae harness_fail                # before the counter the test reads is overrun
    shl $4, %rax
    lea harness_ranges(%rip), %rcx
    mov %r12, (%rcx,%rax)
    mov %r13, 8(%rcx,%rax)
    shr $4, %rax
    inc %rax
    mov %rax, harness_count(%rip)
1:  ret

# (lo, hi, host) -> 1, or zero where the walk refused the host, with every
# entry it described recorded in harness_psc_entries.
.globl harness_psc_range
harness_psc_range:
    harness_enter
    mov %rdi, %r9
    mov %rsi, %r10
    mov %rdx, harness_psc_host(%rip)
    movq $0, harness_psc_count(%rip)
    movq $0, harness_psc_calls(%rip)
    movq $0, harness_psc_bytes(%rip)
    call psc_range
    mov $1, %eax
    jmp harness_ret

# What a host does with a batch, which the test chooses: 0 finishes it in one
# exit, 1 converts a single entry an exit, 2 converts nothing -- and a host
# that converts nothing is what psc_complete has to refuse rather than spin on.
# Every entry a call does convert is recorded with its index in its batch, so a
# test reads both what was asked for and how it was divided into exits.
harness_psc_issue:
    push %rsi
    push %rbx
    push %r8
    mov harness_psc_calls(%rip), %rax
    inc %rax
    mov %rax, harness_psc_calls(%rip)
    mov $PSC_BUFFER, %rsi
    cmpq $2, harness_psc_host(%rip)
    je 4f
    movzwl PSC_CUR_ENTRY(%rsi), %ecx
    movzwl PSC_END_ENTRY(%rsi), %edx
1:  cmp %edx, %ecx
    ja 3f
    mov PSC_ENTRIES(%rsi,%rcx,8), %rdi
    # How much this entry covers, which is counted for every range however
    # long, where only the first of them are recorded one by one.
    mov $PAGE, %r8
    bt $PSC_ENTRY_LARGE, %rdi
    jnc 2f
    mov $0x200000, %r8
2:  add %r8, harness_psc_bytes(%rip)
    mov harness_psc_count(%rip), %rax
    inc %rax
    mov %rax, harness_psc_count(%rip)
    dec %rax
    cmp $HARNESS_PSC_ENTRIES, %rax
    jae 5f
    lea harness_psc_entries(%rip), %rbx
    shl $4, %rax
    mov %rdi, (%rbx,%rax)
    mov %rcx, 8(%rbx,%rax)
5:  inc %ecx
    cmpq $1, harness_psc_host(%rip)
    jne 1b
3:  mov %cx, PSC_CUR_ENTRY(%rsi)
4:  pop %r8
    pop %rbx
    pop %rsi
    ret

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

# Room for every range a walk of a full region list can produce.
.set HARNESS_RANGES, 256
.balign 8
.globl harness_ranges
harness_ranges:
    .fill HARNESS_RANGES * 16,1,0

# Room for several batches' worth of page state change entries, each recorded
# with the index it held in its own batch. A walk of a large guest produces far
# more than this; past the end they are counted and not recorded.
.set HARNESS_PSC_ENTRIES, 4096
.balign 8
.globl harness_psc_entries
harness_psc_entries:
    .fill HARNESS_PSC_ENTRIES * 16,1,0

.balign 8
.globl harness_psc_count
harness_psc_count:
    .quad 0
.globl harness_psc_calls
harness_psc_calls:
    .quad 0
.globl harness_psc_bytes
harness_psc_bytes:
    .quad 0
harness_psc_host:
    .quad 0

.balign 8
harness_sp:
    .quad 0
harness_count:
    .quad 0

# The header madt_build copies, which each shim carries in its measured page.
.globl harness_madt_template
harness_madt_template:
madt_template:
    madt_header
