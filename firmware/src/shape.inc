# The guest-physical map, from shapes measured at build time. A shim never
# walks or merges what the loader describes: it finds the one shape the
# loader's map is, entry for entry, takes the end of that shape's one variable
# RAM entry, and copies the tables the image built for it.
#
#   \fail    where a map that is no shape this image knows terminates
#
# The routines run in this order, the shape in %rbx and the top of guest RAM in
# %r8 from the first on: shape_match, shape_apply (with the zero page in %rdi),
# mark_lazy. The shim accepts no memory: the image delivers what Linux needs
# accepted as measured pages, and Linux accepts the units mark_lazy marks.
# None of it executes a privileged instruction, and the only addresses it names
# are this layout's own, so the same assembly runs in the test harness that
# holds it to boot.rs with those pages mapped where a guest has them.

.macro shape_code fail

# The shape the loader's map is -> %rbx the shape, %r8 the top of guest RAM.
# Clobbers rax, rcx, rdx, rsi, rdi, r9, r10 and r11.
shape_match:
    mov shim_data+SHIM_DATA_SHAPES(%rip), %rcx
    mov $SHAPES_PAGE, %ebx
1:  test %rcx, %rcx
    jz \fail                        # a map that is none of them
    call shape_try
    test %r8, %r8
    jnz 2f
    add $SHAPE_LEN, %rbx
    dec %rcx
    jmp 1b
2:  ret

# Whether the loader's map is exactly the shape at %rbx: its entries one for
# one, each where the shape puts it, of the type it says, and as long -- all
# but the variable entry, whose end has to lie within the shape's bounds once
# rounded down to a whole unit -- and then an empty entry. An entry's flags
# word is not read: nothing here depends on it.
# -> %r8 the top of guest RAM, or zero. Clobbers rax, rdx, rsi, rdi, r9, r10, r11.
shape_try:
    xor %r8d, %r8d
    xor %r11d, %r11d
    mov SHAPE_ENTRIES(%rbx), %r9
    mov $PARAM_MAP_PAGE, %esi
    lea SHAPE_MAP(%rbx), %rdi
    xor %r10d, %r10d                # the entry compared next
1:  cmp %r9, %r10
    je 4f
    mov (%rsi), %rax
    cmp (%rdi), %rax
    jne 9f                          # an entry somewhere else
    movzwl MAP_ENTRY_TYPE(%rsi), %eax
    cmp 16(%rdi), %rax
    jne 9f                          # ...or of another type
    mov MAP_ENTRY_PAGES(%rsi), %rdx
    cmp SHAPE_VAR(%rbx), %r10
    je 2f
    cmp 8(%rdi), %rdx
    jne 9f                          # ...or of another length
    jmp 3f
    # Bounded before it is added to, so no count can wrap the sum.
2:  cmp $(MAX_MEMORY / PAGE), %rdx
    ja 9f
    add (%rsi), %rdx
    shl $12, %rdx
    and $-UNACCEPTED_UNIT, %rdx     # a part unit at the end is left out
    cmp SHAPE_VAR_MIN(%rbx), %rdx
    jb 9f
    cmp SHAPE_VAR_MAX(%rbx), %rdx
    ja 9f
    mov %rdx, %r11
3:  add $MAP_ENTRY_LEN, %rsi
    add $SHAPE_MAP_ENTRY_LEN, %rdi
    inc %r10
    jmp 1b
4:  cmpq $0, MAP_ENTRY_PAGES(%rsi)
    jne 9f                          # a longer map is another machine
    mov %r11, %r8
9:  ret

# The shape at %rbx written out for a guest whose RAM tops out at %r8: its
# E820 table into the zero page %rdi points at and its descriptors after the
# EFI page's own, the last of each -- the one that ends at the top of RAM --
# made to, and the size of the bitmap Linux reads. The image measured at
# least one of each.
# Clobbers rax, rcx, rsi, rdi and r9.
shape_apply:
    mov %rdi, %r9                   # the zero page
    mov SHAPE_E820_COUNT(%rbx), %rcx
    mov %cl, BP_E820_ENTRIES(%r9)
    imul $E820_ENTRY_LEN, %rcx
    lea SHAPE_E820(%rbx), %rsi
    lea BP_E820_TABLE(%r9), %rdi
    rep movsb
    mov %r8, %rax
    sub -E820_ENTRY_LEN(%rdi), %rax
    mov %rax, -E820_ENTRY_LEN+8(%rdi)   # the last runs to the top of RAM
    mov SHAPE_EFI_COUNT(%rbx), %rcx
    lea 1(%rcx), %rax
    imul $EFI_MEMDESC_SIZE, %rax
    mov %eax, BP_EFI_MEMMAP_SIZE(%r9)
    imul $EFI_MEMDESC_SIZE, %rcx
    lea SHAPE_EFI(%rbx), %rsi
    mov $(EFI_PAGE + EFI_MEMMAP + EFI_MEMDESC_SIZE), %edi
    rep movsb
    mov %r8, %rax
    sub -EFI_MEMDESC_SIZE+8(%rdi), %rax
    shr $12, %rax
    mov %rax, -EFI_MEMDESC_SIZE+24(%rdi)    # ...and so do its pages
    # A bit a unit up to the top of RAM, rounded up to a byte, which is how
    # much of the bitmap Linux reserves and reads.
    lea (UNACCEPTED_UNIT * 8 - 1)(%r8), %rax
    shr $(UNACCEPTED_UNIT_SHIFT + 3), %rax
    mov %rax, UNACCEPTED_SIZE
    ret

# A bit in the unaccepted bitmap for each whole unit of the shape's RAM ranges,
# for Linux to accept as it allocates. The image built them to leave out the
# units that arrive accepted (boot::early_units): the first, those it places a
# page in, the guard after the initramfs and the decompressor's, which it
# fills out with measured zero pages. Nothing else is marked:
# Linux also accepts the unit after a range it accepts whenever that unit's
# bit is set, so a bit past the end of RAM would send it to accept memory no
# one backed. The bitmap is accepted RAM, and so zero, by now.
# Clobbers rax, rcx, rdx and rsi.
mark_lazy:
    mov SHAPE_RAM_COUNT(%rbx), %rcx
    lea SHAPE_RAM(%rbx), %rsi
1:  test %rcx, %rcx
    jz 4f
    mov (%rsi), %rax
    mov 8(%rsi), %rdx
    test %rdx, %rdx
    cmovz %r8, %rdx                 # the variable range runs to the top of RAM
    shr $UNACCEPTED_UNIT_SHIFT, %rax
    shr $UNACCEPTED_UNIT_SHIFT, %rdx
2:  cmp %rdx, %rax
    jae 3f
    bts %rax, UNACCEPTED_BITMAP
    inc %rax
    jmp 2b
3:  add $16, %rsi
    dec %rcx
    jmp 1b
4:  ret
.endm
