; IronTLS - HMAC-SHA256 (Win64 ABI)
default rel
%include "it_offsets.inc"

section .text

global it_hmac_init
global it_hmac_update
global it_hmac_final

extern it_sha256_init
extern it_sha256_update
extern it_sha256_final
extern it_sha256
extern it_memzero
extern it_memcpy

; void it_hmac_init(it_hmac_ctx *ctx, const void *key, size_t key_len)
it_hmac_init:
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 96
    mov     rbx, rcx
    mov     rsi, rdx
    mov     rdi, r8

    cmp     rdi, 64
    jbe     .key_ready
    mov     rcx, rsi
    mov     rdx, rdi
    mov     r8, rsp
    call    it_sha256
    mov     rsi, rsp
    mov     edi, 32

.key_ready:
    mov     rcx, rsp
    add     rcx, 32
    mov     edx, 64
    call    it_memzero
    mov     rcx, rsp
    add     rcx, 32
    mov     rdx, rsi
    mov     r8, rdi
    call    it_memcpy

    xor     ecx, ecx
.pad_loop:
    mov     al, [rsp + 32 + rcx]
    mov     dl, al
    xor     dl, 5ch
    mov     [rbx + HMAC_OPAD + rcx], dl
    xor     al, 36h
    mov     [rsp + 32 + rcx], al
    inc     ecx
    cmp     ecx, 64
    jb      .pad_loop

    mov     rcx, rbx
    call    it_sha256_init
    mov     rcx, rbx
    mov     rdx, rsp
    add     rdx, 32
    mov     r8d, 64
    call    it_sha256_update

    add     rsp, 96
    pop     rdi
    pop     rsi
    pop     rbx
    ret

; void it_hmac_update(it_hmac_ctx *ctx, const void *data, size_t len)
it_hmac_update:
    jmp     it_sha256_update

; void it_hmac_final(it_hmac_ctx *ctx, uint8_t out[32])
it_hmac_final:
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 144
    mov     rbx, rcx
    mov     rdi, rdx

    mov     rcx, rbx
    mov     rdx, rsp
    add     rdx, 112
    call    it_sha256_final

    mov     rcx, rsp
    call    it_sha256_init
    mov     rcx, rsp
    mov     rdx, rbx
    add     rdx, HMAC_OPAD
    mov     r8d, 64
    call    it_sha256_update
    mov     rcx, rsp
    mov     rdx, rsp
    add     rdx, 112
    mov     r8d, 32
    call    it_sha256_update
    mov     rcx, rsp
    mov     rdx, rdi
    call    it_sha256_final

    mov     rcx, rbx
    mov     edx, HMAC_SIZE
    call    it_memzero

    add     rsp, 144
    pop     rdi
    pop     rsi
    pop     rbx
    ret
