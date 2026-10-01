.include "layout.inc"
.include "madt.inc"
.include "map.inc"
.include "psc.inc"
.section .reset,"ax"

.code32
.global snp_reset_start
# Nothing here may depend on CPUID, I/O or an exception. What it does ask the
# host for is page state changes, so that the guest makes its own memory
# private rather than a loader doing it: see psc.inc. Every other use of the
# GHCB MSR here is a termination request.
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
    # Linux finds unvalidated memory only through EFI, so guest RAM is made
    # private and validated here, in that order and by the guest itself.
    call ghcb_share
    call accept_walk
    call ghcb_private

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

map_code die_map, accept_private
psc_code die_psc, vmgexit

# A map this image will not run in, which is step 2 of the sequence above.
die_map:
    mov $2, %r15d
    jmp die_step

# The three refusals the shim can report, numbered as steps 3 to 5: KVM prints
# a termination request's reason set and code, so which of them happened is
# readable on the host even though the guest has no console. PVALIDATE
# refusing a page is a fourth, reported by `die`.
#
# A host that answers the share request with success and leaves the block
# assigned to the guest is reported by nothing at all. The first write to the
# descriptor is then an unencrypted write to a page the RMP still says the
# guest owns, which is an RMP violation: the host takes a nested page fault
# and the guest stops where it stood, with no exception a shim without an IDT
# could have turned into a request. Nothing here probes for it, because
# touching the page to find out is that same violation -- a probe would stop
# an honest host rather than catch a lying one -- so the evidence is where KVM
# says the guest stopped.
die_ghcb_share:
    mov $3, %r15d
    jmp die_step
die_psc:
    mov $4, %r15d
    jmp die_step
die_ghcb_private:
    mov $5, %r15d
    jmp die_step

# The GHCB MSR termination request is the shim's only channel to the host:
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

# Accept [%r12, %r13): the host makes it private, then PVALIDATE takes it. The
# order is the whole point -- a PVALIDATE of a page the RMP still says the
# host owns is a violation of it, not a status the guest reads back -- and an
# image that declared a machine's worth of required memory never had to get it
# right, because its loader had converted everything before the shim ran.
accept_private:
    mov %r12, %r9
    mov %r13, %r10
    call psc_range
    jmp validate_range

# The one request the MSR protocol has to carry: a descriptor the host reads
# needs a shared page to sit in, and the only way to share the page the
# descriptor sits in is a protocol that needs no page. The firmware validated
# the block as the image measured it, so its validation is rescinded first --
# private to shared is in that order, and shared to private in the other.
ghcb_share:
    mov $SNP_GHCB, %rax
    xor %ecx, %ecx                  # 4 KiB, as the firmware validated it
    xor %edx, %edx                  # rescind
    pvalidate
    jc die_ghcb_share               # it was not validated: not the measured state
    test %eax, %eax
    jnz die_ghcb_share
    mov $(GHCB_SHARE_REQ >> 32), %edx
    mov $(GHCB_SHARE_REQ & 0xffffffff), %eax
    call ghcb_msr
    test %edx, %edx                 # the response carries an error code up here
    jnz die_ghcb_share
    and $0xfff, %eax
    cmp $GHCB_MSR_PSC_RESP, %eax
    jne die_ghcb_share
    # A host reads no block it was not given the address of first.
    xor %edx, %edx
    mov $(SNP_GHCB | GHCB_MSR_REG_GPA_REQ), %eax
    call ghcb_msr
    cmp $(SNP_GHCB | GHCB_MSR_REG_GPA_RESP), %eax
    jne die_ghcb_share              # a response naming some other page
    test %edx, %edx
    jnz die_ghcb_share
    # GHCB info 0: the block itself, which is what the page protocol exits with.
    xor %edx, %edx
    mov $SNP_GHCB, %eax
    mov $GHCB_MSR, %ecx
    wrmsr
    ret

# ...and back, so the guest hands Linux the block in the state the image
# measured rather than a page its host can still write.
ghcb_private:
    mov $(GHCB_PRIVATE_REQ >> 32), %edx
    mov $(GHCB_PRIVATE_REQ & 0xffffffff), %eax
    call ghcb_msr
    test %edx, %edx
    jnz die_ghcb_private
    and $0xfff, %eax
    cmp $GHCB_MSR_PSC_RESP, %eax
    jne die_ghcb_private
    mov $SNP_GHCB, %rax
    xor %ecx, %ecx
    mov $1, %edx                    # validate
    pvalidate
    jc die_ghcb_private
    test %eax, %eax
    jnz die_ghcb_private
    # The block was written through the shared alias and is zeroed here through
    # the encrypted map, with nothing flushing a cache line between the two
    # views of it. Every part that implements SNP reports SME_COHERENT (CPUID
    # 0x8000001f EAX[10]) and keeps those views coherent in hardware, which is
    # why Linux skips the same flush (amd_enc_cache_flush_required). Nothing
    # here may read CPUID, so that is an assumption about the parts this image
    # is published for rather than something it checks.
    mov $SNP_GHCB, %edi             # the descriptor is not what was measured here
    xor %eax, %eax
    mov $512, %ecx
    rep stosq
    # ...and the MSR to the value a reset leaves in it, so the register does
    # not still name a page the host can no longer read. It withdraws nothing:
    # the GHCB address a host has registered lives in the control area it owns,
    # no request in the protocol takes it back, and KVM keeps it for the life
    # of the processor. This only leaves the register in a defined state.
    xor %edx, %edx
    xor %eax, %eax
    mov $GHCB_MSR, %ecx
    wrmsr
    ret

# EDX:EAX as a GHCB MSR request -> EDX:EAX the response. The caller reads what
# the response puts where, because the two requests this shim makes put
# different things there.
ghcb_msr:
    mov $GHCB_MSR, %ecx
    wrmsr
    vmgexit
    mov $GHCB_MSR, %ecx
    rdmsr
    ret

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
