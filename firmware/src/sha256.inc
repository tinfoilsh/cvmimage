# SHA-256, as FIPS 180-4 states it, for the files the SNP shim fetches rather
# than has measured: see fetch.inc. Plain integer instructions, one round at a
# time, because nothing before Linux may ask CPUID whether SHA-NI is there, and
# because nine megabytes at a few hundred megabytes a second is not where boot
# spends its time. The constants are in the shim's data block (see kernel.rs).
# Nothing here is privileged and it names no address of the layout's, so the
# test harness runs this same assembly against a reference.

# The state, the message schedule and the padded tail, in one frame on the stack.
.set SHA_W, 32
.set SHA_PAD, SHA_W + 64 * 4
.set SHA_FRAME, SHA_PAD + 128

.macro sha256_code

# The SHA-256 of [%rsi, %rsi + %rcx) into the 32 bytes at %rdi.
# Clobbers every general register but %rbp and %rsp.
sha256:
    push %rbp
    sub $SHA_FRAME, %rsp
    mov %rsp, %rbp
    push %rdi
    push %rcx
    push %rsi
    lea shim_data+SHIM_DATA_SHA_H(%rip), %rsi
    mov %rbp, %rdi
    mov $32, %ecx
    rep movsb
    pop %rsi
    mov (%rsp), %rcx
    shr $6, %rcx                    # whole blocks
1:  test %rcx, %rcx
    jz 2f
    push %rcx
    push %rsi
    call sha256_block
    pop %rsi
    pop %rcx
    add $64, %rsi
    dec %rcx
    jmp 1b
    # What is left, then 0x80, then the length in bits at the end of the
    # block, which is the next block if the tail leaves it no room.
2:  lea SHA_PAD(%rbp), %rdi
    xor %eax, %eax
    mov $128, %ecx
    rep stosb
    mov (%rsp), %rcx
    and $63, %ecx
    lea SHA_PAD(%rbp), %rdi
    rep movsb
    movb $0x80, (%rdi)
    mov (%rsp), %rax
    shl $3, %rax
    bswap %rax
    mov (%rsp), %rcx
    and $63, %ecx
    lea SHA_PAD(%rbp), %rsi
    cmp $56, %ecx
    jb 3f
    mov %rax, SHA_PAD+120(%rbp)
    push %rsi
    call sha256_block
    pop %rsi
    add $64, %rsi
    jmp 4f
3:  mov %rax, SHA_PAD+56(%rbp)
4:  call sha256_block
    pop %rcx
    pop %rdi
    xor %ecx, %ecx
5:  mov (%rbp,%rcx,4), %eax
    bswap %eax
    mov %eax, (%rdi,%rcx,4)
    inc %ecx
    cmp $8, %ecx
    jb 5b
    add $SHA_FRAME, %rsp
    pop %rbp
    ret

# One 64-byte block at %rsi into the state at %rbp, with a..h in r8d..r15d.
# Clobbers rax, rbx, rcx, rdx, rsi, rdi and r8 to r15.
sha256_block:
    xor %ecx, %ecx
1:  mov (%rsi,%rcx,4), %eax
    bswap %eax
    mov %eax, SHA_W(%rbp,%rcx,4)
    inc %ecx
    cmp $16, %ecx
    jb 1b
2:  mov SHA_W-8(%rbp,%rcx,4), %eax  # sigma1(W[t-2])
    mov %eax, %edx
    mov %eax, %ebx
    ror $17, %eax
    ror $19, %edx
    shr $10, %ebx
    xor %edx, %eax
    xor %ebx, %eax
    mov SHA_W-60(%rbp,%rcx,4), %edx # sigma0(W[t-15])
    mov %edx, %ebx
    mov %edx, %edi
    ror $7, %edx
    ror $18, %ebx
    shr $3, %edi
    xor %ebx, %edx
    xor %edi, %edx
    add %edx, %eax
    add SHA_W-28(%rbp,%rcx,4), %eax # W[t-7]
    add SHA_W-64(%rbp,%rcx,4), %eax # W[t-16]
    mov %eax, SHA_W(%rbp,%rcx,4)
    inc %ecx
    cmp $64, %ecx
    jb 2b
    mov (%rbp), %r8d
    mov 4(%rbp), %r9d
    mov 8(%rbp), %r10d
    mov 12(%rbp), %r11d
    mov 16(%rbp), %r12d
    mov 20(%rbp), %r13d
    mov 24(%rbp), %r14d
    mov 28(%rbp), %r15d
    lea shim_data+SHIM_DATA_SHA_K(%rip), %rsi
    xor %ecx, %ecx
3:  mov %r12d, %eax                 # Sigma1(e)
    mov %r12d, %ebx
    mov %r12d, %edx
    ror $6, %eax
    ror $11, %ebx
    ror $25, %edx
    xor %ebx, %eax
    xor %edx, %eax
    mov %r12d, %ebx                 # Ch(e, f, g)
    and %r13d, %ebx
    mov %r12d, %edx
    not %edx
    and %r14d, %edx
    xor %edx, %ebx
    add %ebx, %eax
    add %r15d, %eax
    add (%rsi,%rcx,4), %eax
    add SHA_W(%rbp,%rcx,4), %eax    # T1
    mov %r8d, %ebx                  # Sigma0(a)
    mov %r8d, %edx
    mov %r8d, %edi
    ror $2, %ebx
    ror $13, %edx
    ror $22, %edi
    xor %edx, %ebx
    xor %edi, %ebx
    mov %r8d, %edx                  # Maj(a, b, c)
    or %r9d, %edx
    and %r10d, %edx
    mov %r8d, %edi
    and %r9d, %edi
    or %edi, %edx
    add %edx, %ebx                  # T2
    mov %r14d, %r15d
    mov %r13d, %r14d
    mov %r12d, %r13d
    lea (%r11,%rax), %r12d
    mov %r10d, %r11d
    mov %r9d, %r10d
    mov %r8d, %r9d
    lea (%rax,%rbx), %r8d
    inc %ecx
    cmp $64, %ecx
    jb 3b
    add %r8d, (%rbp)
    add %r9d, 4(%rbp)
    add %r10d, 8(%rbp)
    add %r11d, 12(%rbp)
    add %r12d, 16(%rbp)
    add %r13d, 20(%rbp)
    add %r14d, 24(%rbp)
    add %r15d, 28(%rbp)
    ret

.endm
