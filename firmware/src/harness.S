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
.include "power.inc"

.text
map_code harness_fail, harness_accept
psc_code harness_fail, "call harness_psc_issue"
snp_port_write_code harness_fail, "call harness_snp_io"
tdx_port_write_code harness_fail, "call harness_tdx_io"

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

# (TDX, failing call, module failure) -> success. Record the wire requests
# from the real helpers, replacing only the privileged hypervisor exit.
.globl harness_power
harness_power:
    harness_enter
    mov %rsi, harness_power_failure(%rip)
    mov %rdx, harness_power_module_failure(%rip)
    movq $0, harness_power_count(%rip)
    test %rdi, %rdi
    jnz 1f
    q35_power_init snp_port_write
    jmp 2f
1:  q35_power_init tdx_port_write
2:  mov $1, %eax
    jmp harness_ret

harness_power_record:
    mov harness_power_count(%rip), %rdi
    cmp $HARNESS_POWER_WRITES, %rdi
    jae harness_fail
    incq harness_power_count(%rip)
    shl $6, %rdi
    lea harness_power_requests(%rip), %rsi
    add %rdi, %rsi
    ret

harness_snp_io:
    call harness_power_record
    mov GHCB_SW_EXIT_CODE(%rcx), %rax
    mov %rax, 0(%rsi)
    mov GHCB_SW_EXIT_INFO_1(%rcx), %rax
    mov %rax, 8(%rsi)
    mov GHCB_SW_EXIT_INFO_2(%rcx), %rax
    mov %rax, 16(%rsi)
    mov GHCB_RAX(%rcx), %rax
    mov %rax, 24(%rsi)
    mov GHCB_VALID_BITMAP(%rcx), %rax
    mov %rax, 32(%rsi)
    mov GHCB_VALID_BITMAP+8(%rcx), %rax
    mov %rax, 40(%rsi)
    movzwl GHCB_PROTOCOL_VERSION(%rcx), %eax
    mov %rax, 48(%rsi)
    mov GHCB_USAGE(%rcx), %eax
    mov %rax, 56(%rsi)
    mov harness_power_count(%rip), %rax
    cmp harness_power_failure(%rip), %rax
    sete %al
    movzbl %al, %eax
    mov %rax, GHCB_SW_EXIT_INFO_1(%rcx)
    ret

harness_tdx_io:
    call harness_power_record
    mov %rax, 0(%rsi)
    mov %rcx, 8(%rsi)
    mov %r10, 16(%rsi)
    mov %r11, 24(%rsi)
    mov %r12, 32(%rsi)
    mov %r13, 40(%rsi)
    mov %r14, 48(%rsi)
    mov %r15, 56(%rsi)
    # A VMM may overwrite the exposed arguments; the next request must not
    # inherit any of them as a port, value, or access size.
    xor %r12d, %r12d
    xor %r14d, %r14d
    xor %r15d, %r15d
    xor %eax, %eax
    xor %r10d, %r10d
    mov harness_power_count(%rip), %rdi
    cmp harness_power_failure(%rip), %rdi
    jne 1f
    cmpq $0, harness_power_module_failure(%rip)
    jne 2f
    inc %r10
1:  ret
2:  inc %rax
    ret

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

# A range of nothing in particular, so that a routine that recomputed it
# rather than leaving it alone would not land on it by chance.
.set HARNESS_HELD_LO, 0x0000123400000000
.set HARNESS_HELD_HI, 0x0000123410000000

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
    movq $0, harness_psc_lost(%rip)
    # The range accept_private holds while the conversion runs, which psc.inc
    # is handed a copy of in %r9 and %r10 and must not reach.
    mov $HARNESS_HELD_LO, %r12
    mov $HARNESS_HELD_HI, %r13
    call psc_range
    call harness_psc_held
    mov $1, %eax
    jmp harness_ret

# Whether that range is still the range: anything that trod on it would leave
# accept_private validating memory it never asked anyone to convert, which no
# listing and no entry this harness records can show. Clobbers rax.
harness_psc_held:
    mov $HARNESS_HELD_LO, %rax
    cmp %rax, %r12
    jne 1f
    mov $HARNESS_HELD_HI, %rax
    cmp %rax, %r13
    je 2f
1:  incq harness_psc_lost(%rip)
2:  ret

# What a host does with a batch, which the test chooses. The first three are
# within a host's rights and the shim has to finish against all of them; the
# last five are hosts it has to refuse rather than spin on or follow. Every
# entry a call does convert is recorded with its index in its batch, so a test
# reads both what was asked for and how it was divided into exits.
.set HOST_WHOLE, 0                  # the whole batch in one exit
.set HOST_ONE_AT_A_TIME, 1          # one entry an exit
.set HOST_NOTHING, 2                # nothing at all, for ever
.set HOST_PART_OF_AN_ENTRY, 3       # one page of an entry, then the entry
.set HOST_BACKWARDS, 4              # the entry cursor wound back
.set HOST_PAST_THE_BATCH, 5         # an end_entry the guest never wrote
.set HOST_REFUSES, 6                # the request reported as not taken
.set HOST_RAISES_THE_END, 7         # an end_entry a full batch writes
harness_psc_issue:
    push %rcx                       # psc_vmgexit holds the block here
    push %rsi
    push %rbx
    push %r8
    call harness_psc_held
    incq harness_psc_calls(%rip)
    mov $PSC_BUFFER, %rsi
    mov harness_psc_host(%rip), %rax
    cmp $HOST_NOTHING, %rax
    je 9f                           # leaving the header exactly as it was
    cmp $HOST_REFUSES, %rax
    je 6f
    cmp $HOST_BACKWARDS, %rax
    je 7f
    cmp $HOST_PAST_THE_BATCH, %rax
    je 8f
    cmp $HOST_RAISES_THE_END, %rax
    je 10f
    movzwl PSC_CUR_ENTRY(%rsi), %ecx
    movzwl PSC_END_ENTRY(%rsi), %edx
1:  cmp %edx, %ecx
    ja 3f
    mov PSC_ENTRIES(%rsi,%rcx,8), %rdi
    cmpq $HOST_PART_OF_AN_ENTRY, harness_psc_host(%rip)
    jne 2f
    test $PSC_ENTRY_CUR_PAGE, %edi
    jnz 2f                          # it was left part done, so finish it now
    orq $1, PSC_ENTRIES(%rsi,%rcx,8)  # one page in, and back to the guest
    jmp 3f
2:  and $~PSC_ENTRY_CUR_PAGE, %rdi  # the entry as the guest wrote it
    mov %rdi, PSC_ENTRIES(%rsi,%rcx,8)
    # How much this entry covers, which is counted for every range however
    # long, where only the first of them are recorded one by one.
    mov $PAGE, %r8
    bt $PSC_ENTRY_LARGE, %rdi
    jnc 4f
    mov $0x200000, %r8
4:  add %r8, harness_psc_bytes(%rip)
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
    cmpq $HOST_WHOLE, harness_psc_host(%rip)
    je 1b
3:  mov %cx, PSC_CUR_ENTRY(%rsi)
9:  pop %r8
    pop %rbx
    pop %rsi
    pop %rcx
    ret

# The request reported as failed in the block's own fields, which is a batch
# the shim must not ask about again.
6:  mov $GHCB_ALIAS, %rcx
    movq $1, GHCB_SW_EXIT_INFO_2(%rcx)
    jmp 9b

# An entry an exit while there are any left, and then the cursor wound back,
# which is the one direction the protocol does not let it go.
7:  movzwl PSC_CUR_ENTRY(%rsi), %ecx
    cmp PSC_END_ENTRY(%rsi), %cx
    jae 70f
    inc %ecx
    jmp 3b
70: xor %ecx, %ecx
    jmp 3b

# A batch ending past the one the guest described, so that the entry the guest
# is told to read its own progress out of is one it never wrote. The cursor
# moves with it, so nothing but the bound on end_entry catches this.
8:  movw $PSC_MAX_ENTRIES, PSC_END_ENTRY(%rsi)
    movzwl PSC_CUR_ENTRY(%rsi), %ecx
    inc %ecx
    jmp 3b

# The same, but to an end_entry some full batch does write, so only the
# guest's own record of the batch it described catches it.
10: movw $PSC_MAX_ENTRIES-1, PSC_END_ENTRY(%rsi)
    movzwl PSC_CUR_ENTRY(%rsi), %ecx
    inc %ecx
    jmp 3b

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
.set HARNESS_POWER_WRITES, 5
.globl harness_power_requests
harness_power_requests:
    .fill HARNESS_POWER_WRITES * 64,1,0
.globl harness_power_count
harness_power_count:
    .quad 0
harness_power_failure:
    .quad 0
harness_power_module_failure:
    .quad 0

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
.globl harness_psc_lost
harness_psc_lost:
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
