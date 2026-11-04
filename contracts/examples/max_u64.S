/* Independent GAS encoding oracle; host tests only, not a product dependency. */
.text
.globl bb_max_u64
.type bb_max_u64,@function
bb_max_u64:
    push %rbx
    mov %rdi,%rbx
    cmp %rsi,%rbx
    jae .Lselected
    mov %rsi,%rbx
.Lselected:
    mov %rbx,%rax
    pop %rbx
    ret
.size bb_max_u64,.-bb_max_u64
.section .note.GNU-stack,"",@progbits
