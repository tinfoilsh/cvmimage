# Q35's LPC bridge is at 00:1f.0. These fixed writes establish the PM I/O
# window described by the measured FADT; no host-provided address is used.
# Reload all hypervisor-visible arguments before every call.
.macro q35_power_init write
    mov $IO_DWORD_BYTES, %r12d
    mov $PCI_CONFIG_ADDRESS, %r14d
    mov $Q35_LPC_PMBASE, %r15d
    call \write
    mov $IO_DWORD_BYTES, %r12d
    mov $PCI_CONFIG_DATA, %r14d
    mov $(Q35_PM_BASE | Q35_PM_IO_ENABLE), %r15d
    call \write
    mov $IO_DWORD_BYTES, %r12d
    mov $PCI_CONFIG_ADDRESS, %r14d
    mov $Q35_LPC_ACPI_CTRL, %r15d
    call \write
    mov $IO_DWORD_BYTES, %r12d
    mov $PCI_CONFIG_DATA, %r14d
    mov $Q35_ACPI_ENABLE, %r15d
    call \write
    mov $IO_WORD_BYTES, %r12d
    mov $Q35_PM_CONTROL, %r14d
    mov $ACPI_SCI_ENABLE, %r15d
    call \write
.endm

# R12 bytes, R14 port, R15 value. The SNP caller owns an already shared GHCB.
# Only the output value and the IOIO request are exposed, never guest pointers.
.macro snp_port_write_code fail, exit
snp_port_write:
    mov $GHCB_ALIAS, %rcx
    movq $0, GHCB_VALID_BITMAP(%rcx)
    movq $0, GHCB_VALID_BITMAP+8(%rcx)
    movb $(1 << (GHCB_RAX / 8 % 8)), GHCB_VALID_BITMAP+(GHCB_RAX / 64)(%rcx)
    movb $(7 << (GHCB_SW_EXIT_CODE / 8 % 8)), GHCB_VALID_BITMAP+GHCB_VALID_BYTE(%rcx)
    movl $0, GHCB_USAGE(%rcx)
    movw $GHCB_PROTOCOL, GHCB_PROTOCOL_VERSION(%rcx)
    movq $SVM_EXIT_IOIO, GHCB_SW_EXIT_CODE(%rcx)
    mov %r14, %rax
    shl $16, %rax
    mov %r12, %rdx
    shl $4, %rdx
    or %rdx, %rax
    or $IOIO_ADDR_64, %rax
    mov %rax, GHCB_SW_EXIT_INFO_1(%rcx)
    movq $0, GHCB_SW_EXIT_INFO_2(%rcx)
    mov %r15, GHCB_RAX(%rcx)
    \exit
    cmpl $0, GHCB_SW_EXIT_INFO_1(%rcx)
    jne \fail
    ret
.endm

# TDG.VP.VMCALL<Instruction.IO>, with only R10 through R15 shared with the VMM.
.macro tdx_port_write_code fail, exit
tdx_port_write:
    xor %eax, %eax
    mov $TDX_IO_REGISTERS, %ecx
    xor %r10d, %r10d
    mov $TDX_IO_EXIT, %r11d
    mov $TDX_IO_WRITE, %r13d
    \exit
    test %rax, %rax
    jnz \fail
    test %r10, %r10
    jnz \fail
    ret
.endm
