# Q35's LPC bridge is at 00:1f.0. These fixed writes establish the PM I/O
# window described by the measured FADT; no host-provided address is used.
# Every argument the hypervisor can see is reloaded before each call. Replies
# are not checked: a host can drop a write either way, and then only loses the
# ability to power the guest down.
.macro q35_out port, value, write
    mov $\port, %r14d
    mov $\value, %r15d
    call \write
.endm

.macro q35_power_init write
    q35_out PCI_CONFIG_ADDRESS, Q35_LPC_PMBASE, \write
    q35_out PCI_CONFIG_DATA, Q35_PM_BASE, \write
    q35_out PCI_CONFIG_ADDRESS, Q35_LPC_ACPI_CTRL, \write
    q35_out PCI_CONFIG_DATA, Q35_ACPI_ENABLE, \write
.endm

# A 4-byte write of R15 to port R14. The SNP caller owns an already shared GHCB.
# Only the output value and the IOIO request are exposed, never guest pointers.
.macro snp_port_write_code exit
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
    or $(IO_DWORD_BYTES << 4 | IOIO_ADDR_64), %rax
    mov %rax, GHCB_SW_EXIT_INFO_1(%rcx)
    movq $0, GHCB_SW_EXIT_INFO_2(%rcx)
    mov %r15, GHCB_RAX(%rcx)
    \exit
    ret
.endm

# TDG.VP.VMCALL<Instruction.IO>, with only R10 through R15 shared with the VMM.
.macro tdx_port_write_code exit
tdx_port_write:
    xor %eax, %eax
    mov $TDX_IO_REGISTERS, %ecx
    xor %r10d, %r10d
    mov $TDX_IO_EXIT, %r11d
    mov $IO_DWORD_BYTES, %r12d
    mov $TDX_IO_WRITE, %r13d
    \exit
    ret
.endm
