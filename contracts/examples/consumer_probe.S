/* Host-only SysV caller with its own stack alignment and callee-save discipline. */
.text
.globl bb_abi_probe
.type bb_abi_probe,@function
bb_abi_probe:
    push %rbx
    push %r12
    sub $8,%rsp
    mov %rdx,%r12
    movabs $0x13579bdf2468ace0,%rbx
    call bb_max_u64
    mov %rbx,(%r12)
    add $8,%rsp
    pop %r12
    pop %rbx
    ret
.size bb_abi_probe,.-bb_abi_probe
.section .note.GNU-stack,"",@progbits
