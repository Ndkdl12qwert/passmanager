.text
.globl xor_stream_crypt
.type xor_stream_crypt, @function
xor_stream_crypt:
    test %r8, %r8
    je .done
    xor %r9, %r9
.loop:
    mov %r9, %r10
    and $31, %r10
    movzbq (%rdx,%r10), %r10
    mov %r9, %r11
    and $15, %r11
    movzbq (%rcx,%r11), %r11
    xor %r10, %r11
    movzbq (%rdi,%r9), %r12
    xor %r10, %r12
    mov %r12b, (%rsi,%r9)
    inc %r9
    cmp %r9, %r8
    jne .loop
.done:
    ret
