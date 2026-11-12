; IronTLS - AES-128-GCM (AES-NI + software GHASH), Win64 ABI
default rel
%include "it_offsets.inc"

section .text

global it_aes128gcm_seal
global it_aes128gcm_open

; ---------------------------------------------------------------
; internal: aes128_expand_key(const uint8_t key[16], uint8_t rk[176])
; ---------------------------------------------------------------
%macro KEYSTEP 2
    aeskeygenassist xmm1, xmm0, %1
    pshufd  xmm1, xmm1, 0xff
    movdqa  xmm2, xmm0
    pslldq  xmm2, 4
    pxor    xmm0, xmm2
    pslldq  xmm2, 4
    pxor    xmm0, xmm2
    pslldq  xmm2, 4
    pxor    xmm0, xmm2
    pxor    xmm0, xmm1
    movdqu  [rdx + %2], xmm0
%endmacro

aes128_expand_key:
    movdqu  xmm0, [rcx]
    movdqu  [rdx], xmm0
    KEYSTEP 01h, 16
    KEYSTEP 02h, 32
    KEYSTEP 04h, 48
    KEYSTEP 08h, 64
    KEYSTEP 10h, 80
    KEYSTEP 20h, 96
    KEYSTEP 40h, 112
    KEYSTEP 80h, 128
    KEYSTEP 1bh, 144
    KEYSTEP 36h, 160
    ret

; ---------------------------------------------------------------
; internal: aes128_encrypt_block(const uint8_t rk[176], in, out)
; ---------------------------------------------------------------
aes128_encrypt_block:
    movdqu  xmm0, [rdx]
    pxor    xmm0, [rcx]
    aesenc  xmm0, [rcx + 16]
    aesenc  xmm0, [rcx + 32]
    aesenc  xmm0, [rcx + 48]
    aesenc  xmm0, [rcx + 64]
    aesenc  xmm0, [rcx + 80]
    aesenc  xmm0, [rcx + 96]
    aesenc  xmm0, [rcx + 112]
    aesenc  xmm0, [rcx + 128]
    aesenc  xmm0, [rcx + 144]
    aesenclast xmm0, [rcx + 160]
    movdqu  [r8], xmm0
    ret

; ---------------------------------------------------------------
; internal: gcm_ghash_mul(H, Y, X)  ->  Y = (Y xor X) * H
; Software GF(2^128), constant-time with respect to data.
; ---------------------------------------------------------------
gcm_ghash_mul:
    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 64
    mov     rbx, rcx
    mov     rdi, rdx
    mov     rsi, r8

    movdqu  xmm0, [rsi]
    movdqu  xmm1, [rdi]
    pxor    xmm0, xmm1
    movdqu  [rsp + 32], xmm0        ; Xc = Y xor X

    movdqu  xmm0, [rbx]
    movdqu  [rsp + 16], xmm0        ; V = H

    pxor    xmm0, xmm0
    movdqu  [rsp], xmm0             ; Z = 0

    xor     r12d, r12d
.bitloop:
    mov     eax, r12d
    shr     eax, 3
    movzx   ecx, byte [rsp + 32 + rax]
    mov     edx, r12d
    and     edx, 7
    mov     eax, 7
    sub     eax, edx
    bt      ecx, eax
    jnc     .skip_xor
    movdqu  xmm0, [rsp]
    movdqu  xmm1, [rsp + 16]
    pxor    xmm0, xmm1
    movdqu  [rsp], xmm0
.skip_xor:
    xor     r10d, r10d
    xor     r9d, r9d
.shift:
    movzx   eax, byte [rsp + 16 + r9]
    mov     r11d, eax
    and     r11d, 1
    shr     eax, 1
    mov     ecx, r10d
    shl     ecx, 7
    or      eax, ecx
    mov     [rsp + 16 + r9], al
    mov     r10d, r11d
    inc     r9d
    cmp     r9d, 16
    jb      .shift
    test    r10d, r10d
    jz      .no_reduce
    xor     byte [rsp + 16], 0e1h
.no_reduce:
    inc     r12d
    cmp     r12d, 128
    jb      .bitloop

    movdqu  xmm0, [rsp]
    movdqu  [rdi], xmm0
    add     rsp, 64
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

; ---------------------------------------------------------------
; internal: gcm_hash_pad(H, Y, data, len)
; ---------------------------------------------------------------
gcm_hash_pad:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 16
    mov     rbx, rcx
    mov     r12, rdx
    mov     r13, r8
    mov     r14, r9

.full:
    cmp     r14, 16
    jb      .tail
    mov     rcx, rbx
    mov     rdx, r12
    mov     r8, r13
    call    gcm_ghash_mul
    add     r13, 16
    sub     r14, 16
    jmp     .full

.tail:
    test    r14, r14
    jz      .done
    pxor    xmm0, xmm0
    movdqu  [rsp], xmm0
    xor     ecx, ecx
.copy:
    mov     al, [r13 + rcx]
    mov     [rsp + rcx], al
    inc     rcx
    cmp     rcx, r14
    jb      .copy
    mov     rcx, rbx
    mov     rdx, r12
    mov     r8, rsp
    call    gcm_ghash_mul

.done:
    add     rsp, 16
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

; ---------------------------------------------------------------
; internal: gcm_hash_len(H, Y, aad_len, ct_len)
; ---------------------------------------------------------------
gcm_hash_len:
    push    rbx
    push    r12
    sub     rsp, 24
    mov     rbx, rcx
    mov     r12, rdx
    shl     r8, 3
    bswap   r8
    mov     [rsp], r8
    shl     r9, 3
    bswap   r9
    mov     [rsp + 8], r9
    mov     rcx, rbx
    mov     rdx, r12
    mov     r8, rsp
    call    gcm_ghash_mul
    add     rsp, 24
    pop     r12
    pop     rbx
    ret

; ---------------------------------------------------------------
; int it_aes128gcm_seal(key, nonce, aad, aad_len, pt, pt_len, out, tag)
; args 5..8 at [rbp+48], [rbp+56], [rbp+64], [rbp+72]
; ---------------------------------------------------------------
it_aes128gcm_seal:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 264

    mov     rbx, rcx                ; key
    mov     r12, rdx                ; nonce
    mov     r13, r8                 ; aad
    mov     r14, r9                 ; aad_len
    mov     r15, [rbp + 48]         ; pt

    mov     rcx, rbx
    mov     rdx, rsp
    call    aes128_expand_key

    pxor    xmm0, xmm0
    movdqu  [rsp + 176], xmm0
    mov     rcx, rsp
    lea     rdx, [rsp + 176]
    lea     r8,  [rsp + 176]
    call    aes128_encrypt_block     ; H

    pxor    xmm0, xmm0
    movdqu  [rsp + 192], xmm0        ; Y = 0

    mov     rax, [r12]
    mov     [rsp + 208], rax
    mov     eax, [r12 + 8]
    mov     [rsp + 216], eax
    mov     dword [rsp + 220], 01000000h   ; J0 counter = 1

    mov     rcx, rsp
    add     rcx, 176
    lea     rdx, [rsp + 192]
    mov     r8, r13
    mov     r9, r14
    call    gcm_hash_pad             ; AAD

    mov     rbx, r14                 ; save aad_len

    mov     r14, [rbp + 56]          ; remaining = pt_len
    mov     r12, [rbp + 64]          ; out
    movdqu  xmm0, [rsp + 208]
    movdqu  [rsp + 224], xmm0        ; CTR = J0
    mov     dword [rsp + 236], 02000000h

.ctr_full:
    cmp     r14, 16
    jb      .ctr_tail
    mov     rcx, rsp
    lea     rdx, [rsp + 224]
    lea     r8,  [rsp + 240]
    call    aes128_encrypt_block
    movdqu  xmm0, [r15]
    movdqu  xmm1, [rsp + 240]
    pxor    xmm0, xmm1
    movdqu  [r12], xmm0
    add     r15, 16
    add     r12, 16
    sub     r14, 16
    mov     eax, [rsp + 236]
    bswap   eax
    inc     eax
    bswap   eax
    mov     [rsp + 236], eax
    jmp     .ctr_full

.ctr_tail:
    test    r14, r14
    jz      .ctr_done
    mov     rcx, rsp
    lea     rdx, [rsp + 224]
    lea     r8,  [rsp + 240]
    call    aes128_encrypt_block
    xor     ecx, ecx
.ctr_tail_loop:
    mov     al, [r15 + rcx]
    xor     al, [rsp + 240 + rcx]
    mov     [r12 + rcx], al
    inc     rcx
    cmp     rcx, r14
    jb      .ctr_tail_loop

.ctr_done:
    lea     rcx, [rsp + 176]
    lea     rdx, [rsp + 192]
    mov     r8, [rbp + 64]
    mov     r9, [rbp + 56]
    call    gcm_hash_pad             ; ciphertext

    lea     rcx, [rsp + 176]
    lea     rdx, [rsp + 192]
    mov     r8, rbx
    mov     r9, [rbp + 56]
    call    gcm_hash_len

    mov     rcx, rsp
    lea     rdx, [rsp + 208]
    lea     r8,  [rsp + 240]
    call    aes128_encrypt_block
    movdqu  xmm0, [rsp + 240]
    movdqu  xmm1, [rsp + 192]
    pxor    xmm0, xmm1
    mov     rdx, [rbp + 72]
    movdqu  [rdx], xmm0

    xor     eax, eax
    add     rsp, 264
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; ---------------------------------------------------------------
; int it_aes128gcm_open(key, nonce, aad, aad_len, ct, ct_len, out, tag)
; ---------------------------------------------------------------
it_aes128gcm_open:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 264

    mov     rbx, rcx
    mov     r12, rdx
    mov     r13, r8
    mov     r14, r9
    mov     r15, [rbp + 48]         ; ct

    mov     rcx, rbx
    mov     rdx, rsp
    call    aes128_expand_key

    pxor    xmm0, xmm0
    movdqu  [rsp + 176], xmm0
    mov     rcx, rsp
    lea     rdx, [rsp + 176]
    lea     r8,  [rsp + 176]
    call    aes128_encrypt_block

    pxor    xmm0, xmm0
    movdqu  [rsp + 192], xmm0

    mov     rax, [r12]
    mov     [rsp + 208], rax
    mov     eax, [r12 + 8]
    mov     [rsp + 216], eax
    mov     dword [rsp + 220], 01000000h

    mov     rcx, rsp
    add     rcx, 176
    lea     rdx, [rsp + 192]
    mov     r8, r13
    mov     r9, r14
    call    gcm_hash_pad             ; AAD

    mov     rbx, r14                 ; save aad_len

    lea     rcx, [rsp + 176]
    lea     rdx, [rsp + 192]
    mov     r8, r15
    mov     r9, [rbp + 56]
    call    gcm_hash_pad             ; ciphertext

    lea     rcx, [rsp + 176]
    lea     rdx, [rsp + 192]
    mov     r8, rbx
    mov     r9, [rbp + 56]
    call    gcm_hash_len

    mov     rcx, rsp
    lea     rdx, [rsp + 208]
    lea     r8,  [rsp + 240]
    call    aes128_encrypt_block
    movdqu  xmm0, [rsp + 240]
    movdqu  xmm1, [rsp + 192]
    pxor    xmm0, xmm1
    movdqu  [rsp + 240], xmm0        ; computed tag

    mov     rbx, [rbp + 72]
    xor     r9d, r9d
    xor     ecx, ecx
.tag_cmp:
    movzx   eax, byte [rsp + 240 + rcx]
    movzx   edx, byte [rbx + rcx]
    xor     eax, edx
    or      r9d, eax
    inc     ecx
    cmp     ecx, 16
    jb      .tag_cmp
    test    r9d, r9d
    jnz     .auth_fail

    mov     r15, [rbp + 48]          ; ct
    mov     r12, [rbp + 64]          ; out
    mov     r14, [rbp + 56]          ; remaining
    movdqu  xmm0, [rsp + 208]
    movdqu  [rsp + 224], xmm0
    mov     dword [rsp + 236], 02000000h

.ctr_full:
    cmp     r14, 16
    jb      .ctr_tail
    mov     rcx, rsp
    lea     rdx, [rsp + 224]
    lea     r8,  [rsp + 240]
    call    aes128_encrypt_block
    movdqu  xmm0, [r15]
    movdqu  xmm1, [rsp + 240]
    pxor    xmm0, xmm1
    movdqu  [r12], xmm0
    add     r15, 16
    add     r12, 16
    sub     r14, 16
    mov     eax, [rsp + 236]
    bswap   eax
    inc     eax
    bswap   eax
    mov     [rsp + 236], eax
    jmp     .ctr_full

.ctr_tail:
    test    r14, r14
    jz      .success
    mov     rcx, rsp
    lea     rdx, [rsp + 224]
    lea     r8,  [rsp + 240]
    call    aes128_encrypt_block
    xor     ecx, ecx
.ctr_tail_loop:
    mov     al, [r15 + rcx]
    xor     al, [rsp + 240 + rcx]
    mov     [r12 + rcx], al
    inc     rcx
    cmp     rcx, r14
    jb      .ctr_tail_loop

.success:
    xor     eax, eax
    jmp     .done

.auth_fail:
    mov     eax, -1

.done:
    add     rsp, 264
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
