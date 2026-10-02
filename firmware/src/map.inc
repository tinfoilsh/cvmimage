# The guest-physical map, built by the shim so that the machine a guest is
# given stays out of the measurement. Two lists decide it:
#
#   - the spans this image placed, measured in the shim's own page, and
#   - the extents an untrusted loader describes in its memory map parameter.
#
# The loader's map is not copied anywhere. What is taken from it is where RAM
# begins and ends and where it does not: the gaps between its extents are the
# apertures a guest's devices live in, and anything it marks other than memory
# is reserved. Every bound below, and every entry the shim goes on to write from
# the merged list, is this image's own.
#
#   \fail    where a map outside this image's bounds terminates
#   \accept  accepts [%r12, %r13) as private memory, and returns
#
# The routines run in this order, handing the top of guest RAM on in %r8:
# host_regions, merge_regions, e820_build (with the zero page in %rdi),
# accept_walk. None of it executes a privileged instruction, and the only
# addresses it names are this layout's own, so the same assembly runs in the
# test harness that holds it to boot.rs with those pages mapped where a guest
# has them.

# The entry e820_push last wrote, which it extends when the next one abuts it.
.set E820_LAST_BASE, 0 - E820_ENTRY_LEN
.set E820_LAST_SIZE, 8 - E820_ENTRY_LEN
.set E820_LAST_KIND, 16 - E820_ENTRY_LEN

.macro map_code fail, accept

# The parts of the loader's map that are not RAM, into SHIM_HOST_REGIONS.
# -> %r8 the top of guest RAM, %rdi one past the last region written.
# Clobbers rax, rbx, rcx, rdx, rsi, r9, r10 and r11.
host_regions:
    mov $PARAM_MAP_PAGE, %esi
    mov $(PARAM_MAP_PAGE + MAP_ENTRIES * MAP_ENTRY_LEN), %r11d
    mov $SHIM_HOST_REGIONS, %edi
    xor %r8d, %r8d                  # the top of RAM, once an extent states it
    xor %r9d, %r9d                  # the end of the extent before this one
    xor %r10d, %r10d                # extents read
1:  mov MAP_ENTRY_PAGES(%rsi), %rdx
    test %rdx, %rdx
    jz 6f                           # an empty entry, and the page arrives zeroed
    mov (%rsi), %rax                # the first page of the extent
    cmp $(MAX_MEMORY / PAGE), %rax
    jae 7f                          # this extent, and the rest, lie past the map
    add %rax, %rdx                  # one past its last
    jc \fail
    cmp $(MAX_MEMORY / PAGE), %rdx
    ja \fail                        # RAM past what the measured page tables reach
    shl $12, %rax
    shl $12, %rdx
    cmp %r9, %rax
    jb \fail                        # the extents have to ascend and not overlap
    test %r10d, %r10d
    jnz 2f
    # The first extent is the RAM this image was loaded into. Anything else
    # describes a machine the loader did not build.
    test %rax, %rax
    jnz \fail
    cmpw $MAP_TYPE_MEMORY, MAP_ENTRY_TYPE(%rsi)
    jne \fail
    lea shim_data(%rip), %rbx
    cmp SHIM_DATA_MIN_MEMORY(%rbx), %rdx
    jb \fail                        # too little to hold what this image placed
2:  inc %r10d
    # Whatever lies between two extents belongs to no entry at all: that is
    # where a guest's devices are given their windows. The extent's own bounds
    # go on the stack rather than being read from the map a second time.
    push %rax
    push %rdx
    mov %rax, %rdx                  # add_region takes [%rax, %rdx)
    mov %r9, %rax
    mov $E820_ABSENT, %ecx
    call add_region
    pop %rdx
    pop %rax
    cmpw $MAP_TYPE_MEMORY, MAP_ENTRY_TYPE(%rsi)
    je 3f
    mov $E820_RESERVED, %ecx
    call add_region
    jmp 4f
3:  mov %rdx, %r8                   # RAM, so the top of it moves out to here
4:  mov %rdx, %r9
6:  add $MAP_ENTRY_LEN, %rsi
    cmp %r11, %rsi
    jb 1b
    # One entry past the last this shim reads: a longer map is a machine it was
    # not shown, so it is refused rather than described in part.
    mov (%rsi), %rax
    or MAP_ENTRY_PAGES(%rsi), %rax
    or MAP_ENTRY_TYPE(%rsi), %rax    # every field of it, not the two that matter
    jnz \fail
7:  test %r8, %r8
    jz \fail                        # a map with no memory in it
    ret

# Add [%rax, %rdx) as type %ecx at %rdi, which the caller keeps as its cursor.
add_region:
    cmp %rdx, %rax
    jae 1f
    cmp $(SHIM_HOST_REGIONS_END - SPAN_LEN), %edi
    ja \fail                        # the whole region has to fit, not its start
    mov %rax, (%rdi)
    mov %rdx, SPAN_HI(%rdi)
    mov %ecx, SPAN_KIND(%rdi)
    movl $0, SPAN_KIND+4(%rdi)
    add $SPAN_LEN, %rdi
1:  ret

# The measured spans and those regions in one ascending list at SHIM_REGIONS,
# a measured span first where the two begin together. %rdi is where
# host_regions stopped. Clobbers rax, rbx, rdx, rsi, rdi, r9 and r11.
merge_regions:
    mov %rdi, %r11                  # one past the last region of the loader's
    mov $SHIM_HOST_REGIONS, %esi
    lea shim_data+SHIM_DATA_SPANS(%rip), %rdx
    mov $SHIM_REGIONS, %edi
1:  xor %ebx, %ebx                  # the record to copy next
    xor %r9d, %r9d                  # ...and which list it came from
    mov (%rdx), %rax
    or SPAN_HI(%rdx), %rax
    jz 2f
    mov %rdx, %rbx                  # a measured span is still to come
2:  cmp %r11, %rsi
    jae 3f
    test %rbx, %rbx
    jz 4f
    mov (%rsi), %rax
    cmp (%rbx), %rax
    jae 3f
4:  mov %rsi, %rbx                  # ...but the loader's region starts first
    mov $1, %r9d
3:  test %rbx, %rbx
    jz 7f                           # both lists are done
    test %r9d, %r9d
    jz 5f
    add $SPAN_LEN, %rsi
    jmp 6f
5:  add $SPAN_LEN, %rdx
6:  cmp $(SHIM_REGIONS_END - SPAN_LEN), %edi
    jae \fail
    mov (%rbx), %rax
    mov %rax, (%rdi)
    mov SPAN_HI(%rbx), %rax
    mov %rax, SPAN_HI(%rdi)
    mov SPAN_KIND(%rbx), %eax
    mov %eax, SPAN_KIND(%rdi)
    movl $0, SPAN_KIND+4(%rdi)
    add $SPAN_LEN, %rdi
    jmp 1b
7:  movq $0, (%rdi)
    movq $0, SPAN_HI(%rdi)
    ret

# The E820 map, written into the zero page %rdi points at: every region under
# its own type, every gap ordinary RAM, adjacent runs of one type coalesced,
# all of it stopping at the top of RAM in %r8.
# Clobbers rax, rcx, rdx, rsi, rdi, r9, r10, r11, r13 and r14.
e820_build:
    push %rdi                       # the zero page, for the entry count below
    add $BP_E820_TABLE, %rdi
    mov $SHIM_REGIONS, %esi
    xor %r10d, %r10d                # entries written
    xor %r11d, %r11d                # the end of every region walked so far
1:  mov (%rsi), %r13
    mov SPAN_HI(%rsi), %r14
    mov %r13, %rax
    or %r14, %rax
    jz 5f                           # the terminating region
    cmp %r8, %r13
    jae 5f                          # this region and the rest lie past the RAM
    mov %r11, %rax
    mov %r13, %rdx
    mov $E820_RAM, %ecx
    call e820_push
    mov SPAN_KIND(%rsi), %ecx
    test %ecx, %ecx
    jz 3f                           # an aperture belongs to no entry at all
    mov %r13, %rax
    mov %r14, %rdx
    cmp %r8, %rdx
    jbe 2f
    mov %r8, %rdx
2:  call e820_push
3:  cmp %r11, %r14
    jbe 4f
    mov %r14, %r11
4:  add $SPAN_LEN, %rsi
    jmp 1b
5:  mov %r11, %rax
    mov %r8, %rdx
    mov $E820_RAM, %ecx
    call e820_push
    pop %rax
    mov %r10b, BP_E820_ENTRIES(%rax)
    ret

# Add [%rax, %rdx) as type %ecx, extending the last entry where they abut.
# A region nested inside one already written starts where that one ended, so
# the table only ever ascends: Linux is handed no entry that overlaps another.
e820_push:
    test %r10d, %r10d
    jz 1f
    mov E820_LAST_BASE(%rdi), %r9
    add E820_LAST_SIZE(%rdi), %r9
    cmp %r9, %rax
    jae 1f
    mov %r9, %rax
1:  cmp %rdx, %rax
    jae 8f
    test %r10d, %r10d
    jz 9f
    cmp %rax, %r9
    jne 9f
    cmp E820_LAST_KIND(%rdi), %ecx
    jne 9f
    sub %rax, %rdx
    add %rdx, E820_LAST_SIZE(%rdi)
8:  ret
    # The layout asserts bound the merged list well inside both buffers and the
    # table well inside boot_params, so neither this nor add_region's bound can
    # be reached; they are what makes that a property rather than an argument.
9:  cmp $E820_MAX, %r10d
    jae \fail                       # more than boot_params has room for
    mov %rax, (%rdi)
    sub %rax, %rdx
    mov %rdx, 8(%rdi)
    mov %ecx, 16(%rdi)
    add $E820_ENTRY_LEN, %rdi
    inc %r10d
    ret

# Every gap between the regions, in ascending order, handed to \accept: RAM the
# loader described and this image did not already place something in. Nothing
# placed, and nothing outside the loader's RAM, is ever accepted.
accept_walk:
    mov $SHIM_REGIONS, %esi
    xor %ebp, %ebp                  # the end of every region walked so far
1:  mov (%rsi), %rax
    mov SPAN_HI(%rsi), %rdx
    mov %rax, %rcx
    or %rdx, %rcx
    jz 4f
    cmp %rbp, %rax
    jbe 3f
    mov %rbp, %r12
    mov %rax, %r13
    cmp %r8, %r13
    jbe 2f
    mov %r8, %r13
2:  push %rsi                       # \accept is free to clobber all of these
    push %rbp
    push %r8
    push %rdx
    call \accept
    pop %rdx
    pop %r8
    pop %rbp
    pop %rsi
3:  cmp %rbp, %rdx
    jbe 5f
    mov %rdx, %rbp
5:  add $SPAN_LEN, %rsi
    jmp 1b
4:  mov %rbp, %r12
    mov %r8, %r13
    jmp \accept                     # the RAM above every region
.endm
