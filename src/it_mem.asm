; IronTLS - memory and constant-time utilities (Win64 ABI)
default rel

section .text

global it_memcpy
global it_memset
global it_memzero
global it_ct_eq

; void *it_memcpy(void *dst, const void *src, size_t len)
it_memcpy:
    mov     rax, rcx
    push    rdi
    push    rsi
    mov     rdi, rcx
    mov     rsi, rdx
    mov     rcx, r8
    rep movsb
    pop     rsi
    pop     rdi
    ret

; void *it_memset(void *dst, int value, size_t len)
it_memset:
    mov     r9, rcx
    push    rdi
    mov     rdi, rcx
    mov     eax, edx
    mov     rcx, r8
    rep stosb
    mov     rax, r9
    pop     rdi
    ret

; void *it_memzero(void *dst, size_t len)
it_memzero:
    mov     r8, rdx
    xor     edx, edx
    jmp     it_memset

; int it_ct_eq(const void *a, const void *b, size_t len)
; Returns 1 when equal, 0 otherwise. Runs in time independent of the data.
it_ct_eq:
    xor     r9d, r9d                ; diff accumulator
    xor     r10d, r10d              ; index
    test    r8, r8
    jz      .equal
.loop:
    movzx   eax, byte [rcx + r10]
    movzx   r11d, byte [rdx + r10]
    xor     eax, r11d
    or      r9d, eax
    inc     r10
    cmp     r10, r8
    jb      .loop
    xor     eax, eax
    test    r9d, r9d
    sete    al
    ret
.equal:
    mov     eax, 1
    ret
