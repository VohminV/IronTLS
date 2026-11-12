; IronTLS - SHA-256 (Win64 ABI)
default rel
%include "it_offsets.inc"

section .rodata
align 16
sha256_iv:
    dd 06a09e667h, 0bb67ae85h, 03c6ef372h, 0a54ff53ah
    dd 0510e527fh, 09b05688ch, 01f83d9abh, 05be0cd19h
sha256_k:
    dd 0428a2f98h, 071374491h, 0b5c0fbcfh, 0e9b5dba5h
    dd 03956c25bh, 059f111f1h, 0923f82a4h, 0ab1c5ed5h
    dd 0d807aa98h, 012835b01h, 0243185beh, 0550c7dc3h
    dd 072be5d74h, 080deb1feh, 09bdc06a7h, 0c19bf174h
    dd 0e49b69c1h, 0efbe4786h, 00fc19dc6h, 0240ca1cch
    dd 02de92c6fh, 04a7484aah, 05cb0a9dch, 076f988dah
    dd 0983e5152h, 0a831c66dh, 0b00327c8h, 0bf597fc7h
    dd 0c6e00bf3h, 0d5a79147h, 006ca6351h, 014292967h
    dd 027b70a85h, 02e1b2138h, 04d2c6dfch, 053380d13h
    dd 0650a7354h, 0766a0abbh, 081c2c92eh, 092722c85h
    dd 0a2bfe8a1h, 0a81a664bh, 0c24b8b70h, 0c76c51a3h
    dd 0d192e819h, 0d6990624h, 0f40e3585h, 0106aa070h
    dd 019a4c116h, 01e376c08h, 02748774ch, 034b0bcb5h
    dd 0391c0cb3h, 04ed8aa4ah, 05b9cca4fh, 0682e6ff3h
    dd 0748f82eeh, 078a5636fh, 084c87814h, 08cc70208h
    dd 090befffah, 0a4506cebh, 0bef9a3f7h, 0c67178f2h

section .text

global it_sha256_init
global it_sha256_update
global it_sha256_final
global it_sha256
global it_sha256_transform

; void it_sha256_init(it_sha256_ctx *ctx)
it_sha256_init:
    lea     rax, [sha256_iv]
    xor     edx, edx
.copy:
    mov     r8d, [rax + rdx*4]
    mov     [rcx + rdx*4], r8d
    inc     edx
    cmp     edx, 8
    jb      .copy
    mov     qword [rcx + SHA_TOTAL], 0
    mov     dword [rcx + SHA_BUFLEN], 0
    ret

%macro ROUND 0
    mov     eax, r12d
    ror     eax, 6
    mov     ecx, r12d
    ror     ecx, 11
    xor     eax, ecx
    mov     ecx, r12d
    ror     ecx, 25
    xor     eax, ecx
    mov     ecx, r12d
    and     ecx, r13d
    mov     edx, r12d
    not     edx
    and     edx, r14d
    xor     ecx, edx
    add     eax, ecx
    add     eax, r15d
    add     eax, [rdi + rsi*4]
    add     eax, [rsp + rsi*4]

    mov     ecx, r8d
    ror     ecx, 2
    mov     edx, r8d
    ror     edx, 13
    xor     ecx, edx
    mov     edx, r8d
    ror     edx, 22
    xor     ecx, edx
    mov     edx, r8d
    and     edx, r9d
    mov     ebx, r8d
    and     ebx, r10d
    xor     edx, ebx
    mov     ebx, r9d
    and     ebx, r10d
    xor     edx, ebx
    add     ecx, edx

    mov     r15d, r14d
    mov     r14d, r13d
    mov     r13d, r12d
    add     r11d, eax
    mov     r12d, r11d
    mov     r11d, r10d
    mov     r10d, r9d
    mov     r9d, r8d
    mov     r8d, eax
    add     r8d, ecx
%endmacro

; internal: void sha256_transform(ctx, const uint8_t block[64])
it_sha256_transform:
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 264
    mov     [rsp + 256], rcx

    xor     esi, esi
.load:
    mov     eax, [rdx + rsi*4]
    bswap   eax
    mov     [rsp + rsi*4], eax
    inc     esi
    cmp     esi, 16
    jb      .load

    mov     esi, 16
.expand:
    mov     eax, [rsp + rsi*4 - 60]
    mov     ecx, eax
    ror     eax, 7
    ror     ecx, 18
    xor     eax, ecx
    mov     ecx, [rsp + rsi*4 - 60]
    shr     ecx, 3
    xor     eax, ecx
    add     eax, [rsp + rsi*4 - 64]

    mov     ecx, [rsp + rsi*4 - 8]
    mov     edx, ecx
    ror     ecx, 17
    ror     edx, 19
    xor     ecx, edx
    mov     edx, [rsp + rsi*4 - 8]
    shr     edx, 10
    xor     ecx, edx
    add     eax, ecx
    add     eax, [rsp + rsi*4 - 28]
    mov     [rsp + rsi*4], eax
    inc     esi
    cmp     esi, 64
    jb      .expand

    lea     rdi, [sha256_k]
    mov     rax, [rsp + 256]
    mov     r8d,  [rax + SHA_H + 0]
    mov     r9d,  [rax + SHA_H + 4]
    mov     r10d, [rax + SHA_H + 8]
    mov     r11d, [rax + SHA_H + 12]
    mov     r12d, [rax + SHA_H + 16]
    mov     r13d, [rax + SHA_H + 20]
    mov     r14d, [rax + SHA_H + 24]
    mov     r15d, [rax + SHA_H + 28]

    xor     esi, esi
.rounds:
    ROUND
    inc     esi
    cmp     esi, 64
    jb      .rounds

    mov     rax, [rsp + 256]
    add     [rax + SHA_H + 0],  r8d
    add     [rax + SHA_H + 4],  r9d
    add     [rax + SHA_H + 8],  r10d
    add     [rax + SHA_H + 12], r11d
    add     [rax + SHA_H + 16], r12d
    add     [rax + SHA_H + 20], r13d
    add     [rax + SHA_H + 24], r14d
    add     [rax + SHA_H + 28], r15d

    add     rsp, 264
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    ret

; void it_sha256_update(it_sha256_ctx *ctx, const void *data, size_t len)
it_sha256_update:
    test    r8, r8
    jz      .ret_empty
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    mov     rbx, rcx
    mov     rsi, rdx
    mov     r12, r8
    add     [rbx + SHA_TOTAL], r12

    mov     eax, [rbx + SHA_BUFLEN]
    test    eax, eax
    jz      .bulk

    mov     ebp, 64
    sub     ebp, eax
    cmp     r12, rbp
    jb      .fill_partial

    mov     rdi, rbx
    add     rdi, SHA_BUF
    add     rdi, rax
    mov     rcx, rbp
.fill_loop:
    mov     al, [rsi]
    mov     [rdi], al
    inc     rsi
    inc     rdi
    dec     rcx
    jnz     .fill_loop
    sub     r12, rbp
    mov     dword [rbx + SHA_BUFLEN], 0
    mov     rcx, rbx
    mov     rdx, rbx
    add     rdx, SHA_BUF
    call    it_sha256_transform

.bulk:
    cmp     r12, 64
    jb      .tail
    mov     rcx, rbx
    mov     rdx, rsi
    call    it_sha256_transform
    add     rsi, 64
    sub     r12, 64
    jmp     .bulk

.tail:
    mov     dword [rbx + SHA_BUFLEN], r12d
    test    r12, r12
    jz      .done
    mov     rdi, rbx
    add     rdi, SHA_BUF
    mov     rcx, r12
.tail_loop:
    mov     al, [rsi]
    mov     [rdi], al
    inc     rsi
    inc     rdi
    dec     rcx
    jnz     .tail_loop
    jmp     .done

.fill_partial:
    mov     eax, [rbx + SHA_BUFLEN]
    mov     rdi, rbx
    add     rdi, SHA_BUF
    add     rdi, rax
    mov     rcx, r12
    add     [rbx + SHA_BUFLEN], r12d
.fill_loop2:
    mov     al, [rsi]
    mov     [rdi], al
    inc     rsi
    inc     rdi
    dec     rcx
    jnz     .fill_loop2

.done:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
.ret_empty:
    ret

; void it_sha256_final(it_sha256_ctx *ctx, uint8_t out[32])
it_sha256_final:
    push    rbx
    push    r12
    push    r13
    push    rdi
    push    rsi
    mov     rbx, rcx
    mov     r12, rdx

    mov     r13, [rbx + SHA_TOTAL]
    shl     r13, 3

    mov     eax, [rbx + SHA_BUFLEN]
    mov     byte [rbx + SHA_BUF + rax], 80h
    inc     eax
    cmp     eax, 56
    jbe     .pad_rest

    mov     rdi, rbx
    add     rdi, SHA_BUF
    add     rdi, rax
    mov     ecx, 64
    sub     ecx, eax
    xor     eax, eax
    rep stosb
    mov     rcx, rbx
    mov     rdx, rbx
    add     rdx, SHA_BUF
    call    it_sha256_transform
    xor     eax, eax

.pad_rest:
    mov     rdi, rbx
    add     rdi, SHA_BUF
    add     rdi, rax
    mov     ecx, 56
    sub     ecx, eax
    xor     eax, eax
    rep stosb

    mov     rax, r13
    bswap   rax
    mov     [rbx + SHA_BUF + 56], rax

    mov     rcx, rbx
    mov     rdx, rbx
    add     rdx, SHA_BUF
    call    it_sha256_transform

    xor     ecx, ecx
.out_loop:
    mov     eax, [rbx + SHA_H + rcx*4]
    bswap   eax
    mov     [r12 + rcx*4], eax
    inc     ecx
    cmp     ecx, 8
    jb      .out_loop

    mov     rcx, rbx
    mov     edx, SHA_SIZE
    call    it_memzero

    pop     rsi
    pop     rdi
    pop     r13
    pop     r12
    pop     rbx
    ret

; void it_sha256(const void *data, size_t len, uint8_t out[32])
it_sha256:
    push    rbx
    sub     rsp, 128
    mov     [rsp + 112], rcx
    mov     [rsp + 120], rdx
    mov     rbx, r8
    mov     rcx, rsp
    call    it_sha256_init
    mov     rcx, rsp
    mov     rdx, [rsp + 112]
    mov     r8, [rsp + 120]
    call    it_sha256_update
    mov     rcx, rsp
    mov     rdx, rbx
    call    it_sha256_final
    add     rsp, 128
    pop     rbx
    ret

extern it_memzero
