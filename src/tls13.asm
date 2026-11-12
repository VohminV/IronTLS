; IronTLS - TLS 1.3 PSK engine (Win64 ABI)
default rel
%include "it_offsets.inc"

%define FLAG_EE 4

section .rodata
label_ext_binder: db "ext binder"
label_derived:    db "derived"
label_c_hs:       db "c hs traffic"
label_s_hs:       db "s hs traffic"
label_c_ap:       db "c ap traffic"
label_s_ap:       db "s ap traffic"
label_finished:   db "finished"
label_key:        db "key"
label_iv:         db "iv"
empty_hash:
    db 0e3h,0b0h,0c4h,42h,98h,0fch,1ch,14h,9ah,0fbh,0f4h,0c8h,99h,6fh,0b9h,24h
    db 27h,0aeh,41h,0e4h,64h,9bh,93h,4ch,0a4h,95h,99h,1bh,78h,52h,0b8h,55h
zeros32:
    times 32 db 0

section .text

global it_tls_init
global it_tls_feed
global it_tls_drain
global it_tls_step
global it_tls_handshake_done
global it_tls_write
global it_tls_read
global it_tls_clear

extern it_memcpy
extern it_memset
extern it_memzero
extern it_ct_eq
extern it_sha256_init
extern it_sha256_update
extern it_sha256_final
extern it_sha256
extern it_hmac_init
extern it_hmac_update
extern it_hmac_final
extern it_hkdf_extract
extern it_hkdf_expand_label
extern it_aes128gcm_seal
extern it_aes128gcm_open
extern __imp_BCryptGenRandom

; void it_tls_clear(it_tls_ctx *ctx)
it_tls_clear:
    mov     edx, 98912
    jmp     it_memzero

; int it_tls_init(it_tls_ctx *ctx, int role, const void *psk, size_t psk_len,
;                 const void *identity, size_t identity_len)
it_tls_init:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 8

    test    rcx, rcx
    jz      .bad
    test    edx, edx
    jz      .role_ok
    cmp     edx, 1
    jne     .bad
.role_ok:
    test    r9, r9
    jz      .bad
    cmp     r9, IT_MAX_PSK
    ja      .bad
    mov     rax, [rbp + 56]
    cmp     rax, IT_MAX_IDENTITY
    ja      .bad

    mov     rbx, rcx
    mov     r12d, edx
    mov     r13, r8
    mov     r14, r9
    mov     r15, [rbp + 48]

    mov     rcx, rbx
    mov     edx, 98912
    call    it_memzero

    mov     [rbx + CTX_ROLE], r12d
    cmp     r12d, ROLE_CLIENT
    jne     .server
    mov     dword [rbx + CTX_STATE], ST_INIT
    jmp     .copy
.server:
    mov     dword [rbx + CTX_STATE], ST_WAIT_CH

.copy:
    mov     [rbx + CTX_PSK_LEN], r14d
    lea     rcx, [rbx + CTX_PSK]
    mov     rdx, r13
    mov     r8, r14
    call    it_memcpy

    mov     rax, [rbp + 56]
    mov     [rbx + CTX_ID_LEN], eax
    test    rax, rax
    jz      .no_id
    lea     rcx, [rbx + CTX_IDENTITY]
    mov     rdx, r15
    mov     r8, rax
    call    it_memcpy
.no_id:
    lea     rcx, [rbx + CTX_TRANSCRIPT]
    call    it_sha256_init
    xor     eax, eax
    jmp     .done
.bad:
    mov     eax, IT_ERR_ARGS
.done:
    add     rsp, 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int it_tls_feed(it_tls_ctx *ctx, const void *data, size_t len)
it_tls_feed:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14

    test    rcx, rcx
    jz      .bad
    test    r8, r8
    jz      .ok
    test    rdx, rdx
    jz      .bad
    mov     ebx, [rcx + CTX_RX_LEN]
    lea     rax, [rbx + r8]
    cmp     rax, IT_RX_CAP
    ja      .nobuf

    mov     r12, rcx
    mov     r13, rdx
    mov     r14, r8
    lea     rcx, [r12 + CTX_RX]
    add     rcx, rbx
    mov     rdx, r13
    mov     r8, r14
    call    it_memcpy
    mov     eax, [r12 + CTX_RX_LEN]
    add     eax, r14d
    mov     [r12 + CTX_RX_LEN], eax
.ok:
    xor     eax, eax
    jmp     .done
.bad:
    mov     eax, IT_ERR_ARGS
    jmp     .done
.nobuf:
    mov     eax, IT_ERR_BUFFER
.done:
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int it_tls_drain(it_tls_ctx *ctx, void *out, size_t cap)
it_tls_drain:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14

    test    rcx, rcx
    jz      .bad
    test    rdx, rdx
    jz      .bad
    mov     rbx, rcx
    mov     r12, rdx
    mov     r13, r8
    mov     r14d, [rbx + CTX_TX_LEN]
    test    r14d, r14d
    jz      .zero
    test    r13, r13
    jz      .zero
    cmp     r13, r14
    jbe     .have_n
    mov     r13d, r14d
.have_n:
    mov     rcx, r12
    lea     rdx, [rbx + CTX_TX]
    mov     r8, r13
    call    it_memcpy

    mov     eax, r14d
    sub     eax, r13d
    test    eax, eax
    jz      .store
    mov     r12d, eax
    lea     rcx, [rbx + CTX_TX]
    lea     rdx, [rcx + r13]
    mov     r8d, r12d
    call    it_memcpy
    mov     eax, r12d
.store:
    mov     [rbx + CTX_TX_LEN], eax
    mov     eax, r13d
    jmp     .done
.zero:
    xor     eax, eax
    jmp     .done
.bad:
    mov     eax, IT_ERR_ARGS
.done:
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int it_tls_handshake_done(const it_tls_ctx *ctx)
it_tls_handshake_done:
    xor     eax, eax
    test    rcx, rcx
    jz      .out
    cmp     dword [rcx + CTX_STATE], ST_ESTABLISHED
    sete    al
.out:
    ret

; int rng_bytes(void *buf, size_t len)
rng_bytes:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 32
    mov     r8, rdx
    mov     rdx, rcx
    xor     ecx, ecx
    mov     r9d, 2
    call    qword [__imp_BCryptGenRandom]
    test    eax, eax
    jz      .ok
    mov     eax, IT_ERR_CRYPTO
    jmp     .done
.ok:
    xor     eax, eax
.done:
    add     rsp, 32
    pop     rbp
    ret

; void tls_transcript_update(ctx, data, len)
tls_transcript_update:
    add     rcx, CTX_TRANSCRIPT
    jmp     it_sha256_update

; void tls_transcript_hash(ctx, out)
tls_transcript_hash:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    sub     rsp, 176
    mov     rbx, rdx
    mov     r12, rcx
    lea     rcx, [rsp + 64]
    lea     rdx, [r12 + CTX_TRANSCRIPT]
    mov     r8d, SHA_SIZE
    call    it_memcpy
    lea     rcx, [rsp + 64]
    mov     rdx, rbx
    call    it_sha256_final
    add     rsp, 176
    pop     r12
    pop     rbx
    pop     rbp
    ret

; void tls_derive_secret(secret, label, label_len, hash_ptr, out)
; hash_ptr == NULL means empty context.
tls_derive_secret:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    sub     rsp, 80

    mov     rbx, rcx
    mov     r12, rdx
    mov     [rsp + 56], r8
    mov     [rsp + 64], r9
    mov     [rsp + 72], r10

    mov     rcx, rbx
    mov     rdx, r12
    mov     r8, [rsp + 56]
    mov     rax, [rsp + 64]
    test    rax, rax
    jz      .empty
    mov     r9, rax
    mov     qword [rsp + 32], 32
    jmp     .go
.empty:
    xor     r9d, r9d
    mov     qword [rsp + 32], 0
.go:
    mov     rax, [rsp + 72]
    mov     [rsp + 40], rax
    mov     qword [rsp + 48], 32
    call    it_hkdf_expand_label
    add     rsp, 80
    pop     r12
    pop     rbx
    pop     rbp
    ret

; void tls_make_dir(dir, secret)
tls_make_dir:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    sub     rsp, 64
    mov     rbx, rcx
    mov     r12, rdx

    mov     rcx, r12
    lea     rdx, [label_key]
    mov     r8d, 3
    xor     r9d, r9d
    mov     qword [rsp + 32], 0
    lea     rax, [rbx + AE_KEY]
    mov     [rsp + 40], rax
    mov     qword [rsp + 48], 16
    call    it_hkdf_expand_label

    mov     rcx, r12
    lea     rdx, [label_iv]
    mov     r8d, 2
    xor     r9d, r9d
    mov     qword [rsp + 32], 0
    lea     rax, [rbx + AE_IV]
    mov     [rsp + 40], rax
    mov     qword [rsp + 48], 12
    call    it_hkdf_expand_label

    mov     qword [rbx + AE_SEQ], 0
    mov     dword [rbx + AE_PAD], 0
    add     rsp, 64
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int tls_finished_verify(ctx, base_secret, out32)
tls_finished_verify:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 328

    mov     rbx, rcx
    mov     r12, rdx
    mov     r13, r8

    mov     rcx, r12
    lea     rdx, [label_finished]
    mov     r8d, 8
    xor     r9d, r9d
    mov     qword [rsp + 32], 0
    lea     rax, [rsp + 64]
    mov     [rsp + 40], rax
    mov     qword [rsp + 48], 32
    call    it_hkdf_expand_label

    mov     rcx, rbx
    lea     rdx, [rsp + 96]
    call    tls_transcript_hash

    lea     rcx, [rsp + 128]
    lea     rdx, [rsp + 64]
    mov     r8d, 32
    call    it_hmac_init
    lea     rcx, [rsp + 128]
    lea     rdx, [rsp + 96]
    mov     r8d, 32
    call    it_hmac_update
    lea     rcx, [rsp + 128]
    mov     rdx, r13
    call    it_hmac_final

    lea     rcx, [rsp + 64]
    mov     edx, 240
    call    it_memzero
    xor     eax, eax
    add     rsp, 328
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int tls_append_plain(ctx, type, data, len)
tls_append_plain:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14

    mov     rbx, rcx
    mov     r14d, edx
    mov     r12, r8
    mov     r13, r9
    cmp     r13, 16379
    ja      .nobuf
    mov     eax, [rbx + CTX_TX_LEN]
    lea     rcx, [rax + r13 + 5]
    cmp     rcx, IT_TX_CAP
    ja      .nobuf

    lea     r10, [rbx + CTX_TX]
    add     r10, rax
    mov     [r10], r14b
    mov     byte [r10 + 1], 3
    mov     byte [r10 + 2], 3
    mov     eax, r13d
    xchg    al, ah
    mov     [r10 + 3], ax

    mov     eax, [rbx + CTX_TX_LEN]
    lea     rcx, [rbx + CTX_TX]
    add     rcx, rax
    add     rcx, 5
    mov     rdx, r12
    mov     r8, r13
    call    it_memcpy
    mov     eax, r13d
    add     eax, 5
    add     [rbx + CTX_TX_LEN], eax
    xor     eax, eax
    jmp     .done
.nobuf:
    mov     eax, IT_ERR_BUFFER
.done:
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int tls_encrypt_record(ctx, dir, inner_type, data, len)
tls_encrypt_record:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 72

    mov     rbx, rcx
    mov     r12, rdx
    mov     r13d, r8d
    mov     r14, r9
    mov     r15, r10
    cmp     r15, 16000
    ja      .nobuf
    mov     eax, [rbx + CTX_TX_LEN]
    lea     rcx, [rax + r15 + 22]
    cmp     rcx, IT_TX_CAP
    ja      .nobuf

    lea     rcx, [rbx + CTX_SCRATCH]
    mov     rdx, r14
    mov     r8, r15
    call    it_memcpy
    lea     rax, [rbx + CTX_SCRATCH]
    mov     [rax + r15], r13b

    lea     rcx, [rbx + CTX_SCRATCH]
    add     rcx, 16368
    lea     rdx, [r12 + AE_IV]
    mov     r8d, 12
    call    it_memcpy
    mov     rax, [r12 + AE_SEQ]
    bswap   rax
    lea     rcx, [rbx + CTX_SCRATCH]
    xor     [rcx + 16372], rax

    mov     eax, [rbx + CTX_TX_LEN]
    lea     rcx, [rbx + CTX_TX]
    add     rcx, rax
    mov     [rsp + 64], rcx
    mov     byte [rcx], 23
    mov     byte [rcx + 1], 3
    mov     byte [rcx + 2], 3
    mov     eax, r15d
    add     eax, 17
    xchg    al, ah
    mov     [rcx + 3], ax

    mov     r10, [rsp + 64]
    mov     rcx, r12
    lea     rdx, [rbx + CTX_SCRATCH + 16368]
    mov     r8, r10
    mov     r9d, 5
    lea     rax, [rbx + CTX_SCRATCH]
    mov     [rsp + 32], rax
    mov     eax, r15d
    inc     eax
    mov     [rsp + 40], rax
    lea     rax, [r10 + 5]
    mov     [rsp + 48], rax
    lea     rax, [r10 + r15 + 6]
    mov     [rsp + 56], rax
    call    it_aes128gcm_seal
    test    eax, eax
    jnz     .crypto

    inc     qword [r12 + AE_SEQ]
    mov     eax, r15d
    add     eax, 22
    add     [rbx + CTX_TX_LEN], eax
    xor     eax, eax
    jmp     .done
.nobuf:
    mov     eax, IT_ERR_BUFFER
    jmp     .done
.crypto:
    mov     eax, IT_ERR_CRYPTO
.done:
    add     rsp, 72
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int tls_decrypt_record(ctx, dir, rec_ptr, rec_len)
; Returns (edx = inner type, eax = data len), plaintext in ctx->scratch.
tls_decrypt_record:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi
    sub     rsp, 88

    mov     rbx, rcx
    mov     r12, rdx
    mov     r13, r8
    mov     r14, r9
    cmp     r14, 17
    jb      .proto
    cmp     r14, 16379
    ja      .proto
    lea     r15, [r14 - 16]

    lea     rcx, [rsp + 64]
    lea     rdx, [r12 + AE_IV]
    mov     r8d, 12
    call    it_memcpy
    mov     rax, [r12 + AE_SEQ]
    bswap   rax
    xor     [rsp + 68], rax

    mov     rcx, r12
    lea     rdx, [rsp + 64]
    mov     r8, r13
    mov     r9d, 5
    lea     rax, [r13 + 5]
    mov     [rsp + 32], rax
    mov     [rsp + 40], r15
    lea     rax, [rbx + CTX_SCRATCH]
    mov     [rsp + 48], rax
    lea     rax, [r13 + r15 + 5]
    mov     [rsp + 56], rax
    call    it_aes128gcm_open
    test    eax, eax
    jnz     .crypto

    inc     qword [r12 + AE_SEQ]
    lea     rsi, [rbx + CTX_SCRATCH]
    mov     rcx, r15
.scan:
    test    rcx, rcx
    jz      .proto
    dec     rcx
    movzx   eax, byte [rsi + rcx]
    test    eax, eax
    jz      .scan
    cmp     eax, 20
    jb      .proto
    cmp     eax, 23
    ja      .proto
    mov     edx, eax
    mov     eax, ecx
    jmp     .done
.crypto:
    mov     eax, IT_ERR_CRYPTO
    jmp     .done
.proto:
    mov     eax, IT_ERR_PROTOCOL
.done:
    add     rsp, 88
    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int it_tls_write(it_tls_ctx *ctx, const void *data, size_t len)
it_tls_write:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    sub     rsp, 8

    test    rcx, rcx
    jz      .bad
    cmp     dword [rcx + CTX_STATE], ST_ESTABLISHED
    jne     .state
    test    r8, r8
    jz      .ok
    test    rdx, rdx
    jz      .bad
    mov     rbx, rcx
    mov     r12, rdx
    mov     r13, r8
    cmp     r13, 16000
    ja      .nobuf
    mov     rax, [rbx + CTX_ROLE]
    test    eax, eax
    jnz     .srv
    lea     rdx, [rbx + CTX_C_AP]
    jmp     .go
.srv:
    lea     rdx, [rbx + CTX_S_AP]
.go:
    mov     rcx, rbx
    mov     r8d, 23
    mov     r9, r12
    mov     r10, r13
    call    tls_encrypt_record
    jmp     .done
.ok:
    xor     eax, eax
    jmp     .done
.bad:
    mov     eax, IT_ERR_ARGS
    jmp     .done
.state:
    mov     eax, IT_ERR_STATE
    jmp     .done
.nobuf:
    mov     eax, IT_ERR_BUFFER
.done:
    add     rsp, 8
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int it_tls_read(it_tls_ctx *ctx, void *out, size_t cap)
it_tls_read:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    sub     rsp, 8

    test    rcx, rcx
    jz      .bad
    test    rdx, rdx
    jz      .bad
    mov     rbx, rcx
    mov     r12, rdx
    mov     r13, r8
    mov     eax, [rbx + CTX_APP_OFF]
    mov     ecx, [rbx + CTX_APP_LEN]
    cmp     eax, ecx
    jb      .have
    mov     dword [rbx + CTX_APP_OFF], 0
    mov     dword [rbx + CTX_APP_LEN], 0
    xor     eax, eax
    jmp     .done
.have:
    sub     ecx, eax
    test    r13, r13
    jz      .zero
    cmp     r13, rcx
    jbe     .n_ok
    mov     r13d, ecx
.n_ok:
    lea     rdx, [rbx + CTX_APP]
    add     rdx, rax
    mov     rcx, r12
    mov     r8, r13
    call    it_memcpy
    mov     eax, [rbx + CTX_APP_OFF]
    add     eax, r13d
    mov     [rbx + CTX_APP_OFF], eax
    cmp     eax, [rbx + CTX_APP_LEN]
    jne     .ret_n
    mov     dword [rbx + CTX_APP_OFF], 0
    mov     dword [rbx + CTX_APP_LEN], 0
.ret_n:
    mov     eax, r13d
    jmp     .done
.zero:
    xor     eax, eax
    jmp     .done
.bad:
    mov     eax, IT_ERR_ARGS
.done:
    add     rsp, 8
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int tls_client_send_ch(ctx)
tls_client_send_ch:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 456

    mov     rbx, rcx
    mov     r12d, [rbx + CTX_ID_LEN]
    cmp     r12d, IT_MAX_IDENTITY
    ja      .proto
    lea     r13, [rbx + CTX_APP]
    mov     r14d, r12d
    add     r14d, 106
    cmp     r14d, IT_APP_CAP
    ja      .nobuf

    mov     byte [r13], 1
    mov     eax, r14d
    sub     eax, 4
    mov     [r13 + 3], al
    shr     eax, 8
    mov     [r13 + 2], al
    shr     eax, 8
    mov     [r13 + 1], al
    mov     byte [r13 + 4], 3
    mov     byte [r13 + 5], 3
    lea     rcx, [r13 + 6]
    mov     edx, 32
    call    rng_bytes
    test    eax, eax
    jnz     .crypto
    mov     byte [r13 + 38], 0
    mov     byte [r13 + 39], 0
    mov     byte [r13 + 40], 2
    mov     byte [r13 + 41], 13h
    mov     byte [r13 + 42], 1
    mov     byte [r13 + 43], 1
    mov     byte [r13 + 44], 0
    mov     eax, r12d
    add     eax, 59
    mov     [r13 + 46], al
    shr     eax, 8
    mov     [r13 + 45], al
    mov     byte [r13 + 47], 0
    mov     byte [r13 + 48], 2bh
    mov     byte [r13 + 49], 0
    mov     byte [r13 + 50], 3
    mov     byte [r13 + 51], 2
    mov     byte [r13 + 52], 3
    mov     byte [r13 + 53], 4
    mov     byte [r13 + 54], 0
    mov     byte [r13 + 55], 2dh
    mov     byte [r13 + 56], 0
    mov     byte [r13 + 57], 2
    mov     byte [r13 + 58], 1
    mov     byte [r13 + 59], 0
    mov     byte [r13 + 60], 0
    mov     byte [r13 + 61], 29h
    mov     eax, r12d
    add     eax, 42
    mov     [r13 + 63], al
    shr     eax, 8
    mov     [r13 + 62], al
    mov     eax, r12d
    add     eax, 6
    mov     [r13 + 65], al
    shr     eax, 8
    mov     [r13 + 64], al
    mov     eax, r12d
    mov     [r13 + 67], al
    shr     eax, 8
    mov     [r13 + 66], al
    lea     rcx, [r13 + 68]
    lea     rdx, [rbx + CTX_IDENTITY]
    mov     r8, r12
    call    it_memcpy
    mov     r15d, r12d
    add     r15d, 68
    mov     dword [r13 + r15], 0
    add     r15d, 4
    mov     byte [r13 + r15], 0
    mov     byte [r13 + r15 + 1], 32
    add     r15d, 2
    lea     rcx, [r13 + r15]
    xor     edx, edx
    mov     r8d, 32
    call    it_memset

    xor     ecx, ecx
    xor     edx, edx
    lea     r8, [rbx + CTX_PSK]
    mov     r9d, [rbx + CTX_PSK_LEN]
    lea     rax, [rbx + CTX_EARLY]
    mov     [rsp + 32], rax
    call    it_hkdf_extract

    lea     rcx, [rbx + CTX_EARLY]
    lea     rdx, [label_ext_binder]
    mov     r8d, 10
    lea     r9, [empty_hash]
    lea     r10, [rsp + 88]
    call    tls_derive_secret

    lea     rcx, [rsp + 88]
    lea     rdx, [label_finished]
    mov     r8d, 8
    xor     r9d, r9d
    lea     r10, [rsp + 120]
    call    tls_derive_secret

    mov     rcx, r13
    mov     edx, r14d
    sub     edx, 34
    lea     r8, [rsp + 152]
    call    it_sha256

    lea     rcx, [rsp + 216]
    lea     rdx, [rsp + 120]
    mov     r8d, 32
    call    it_hmac_init
    lea     rcx, [rsp + 216]
    lea     rdx, [rsp + 152]
    mov     r8d, 32
    call    it_hmac_update
    lea     rcx, [rsp + 216]
    lea     rdx, [rsp + 184]
    call    it_hmac_final

    lea     rcx, [r13 + r15]
    lea     rdx, [rsp + 184]
    mov     r8d, 32
    call    it_memcpy

    mov     rcx, rbx
    mov     rdx, r13
    mov     r8, r14
    call    tls_transcript_update

    mov     rcx, rbx
    mov     edx, 22
    mov     r8, r13
    mov     r9, r14
    call    tls_append_plain
    test    eax, eax
    js      .done

    mov     dword [rbx + CTX_STATE], ST_CH_SENT
    xor     eax, eax
    jmp     .done
.nobuf:
    mov     eax, IT_ERR_BUFFER
    jmp     .done
.crypto:
    mov     eax, IT_ERR_CRYPTO
    jmp     .done
.proto:
    mov     eax, IT_ERR_PROTOCOL
.done:
    add     rsp, 456
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int tls_handle_client_hello(ctx, msg, msg_len)
tls_handle_client_hello:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 584

    mov     rbx, rcx
    mov     r12, rdx
    mov     r13, r8
    cmp     r13, 47
    jb      .proto
    cmp     byte [r12], 1
    jne     .proto
    movzx   eax, byte [r12 + 1]
    shl     eax, 16
    movzx   ecx, byte [r12 + 2]
    shl     ecx, 8
    or      eax, ecx
    movzx   ecx, byte [r12 + 3]
    or      eax, ecx
    add     eax, 4
    cmp     rax, r13
    jne     .proto

    lea     r14, [r12 + 4]
    lea     r15, [r12 + r13]
    mov     rax, r14
    add     rax, 43
    cmp     rax, r15
    ja      .proto
    movzx   eax, word [r14]
    rol     ax, 8
    cmp     ax, 0303h
    jne     .proto
    add     r14, 2
    add     r14, 32
    movzx   eax, byte [r14]
    inc     r14
    cmp     eax, 32
    ja      .proto
    add     r14, rax

    movzx   ecx, word [r14]
    rol     cx, 8
    add     r14, 2
    test    ecx, 1
    jnz     .proto
    mov     rdx, r14
    add     rdx, rcx
    cmp     rdx, r15
    ja      .proto
    mov     r8, r14
.scan_suites:
    cmp     r8, rdx
    jae     .proto
    movzx   eax, word [r8]
    rol     ax, 8
    cmp     ax, 1301h
    je      .suite_ok
    add     r8, 2
    jmp     .scan_suites
.suite_ok:
    mov     r14, rdx

    cmp     r14, r15
    jae     .proto
    movzx   eax, byte [r14]
    inc     r14
    cmp     eax, 1
    jne     .proto
    cmp     r14, r15
    jae     .proto
    cmp     byte [r14], 0
    jne     .proto
    inc     r14

    mov     rax, r15
    sub     rax, r14
    cmp     rax, 2
    jb      .proto
    movzx   ecx, word [r14]
    rol     cx, 8
    add     r14, 2
    mov     rax, r14
    add     rax, rcx
    cmp     rax, r15
    jne     .proto

    mov     qword [rsp + 64], 0
    mov     dword [rsp + 80], 0

.eloop:
    cmp     r14, r15
    jae     .edone
    mov     rax, r15
    sub     rax, r14
    cmp     rax, 4
    jb      .proto
    movzx   ecx, word [r14]
    rol     cx, 8
    movzx   edx, word [r14 + 2]
    rol     dx, 8
    add     r14, 4
    mov     rax, r14
    add     rax, rdx
    cmp     rax, r15
    ja      .proto
    mov     r8, rax
    cmp     ecx, 43
    je      .ext_sv
    cmp     ecx, 45
    je      .ext_modes
    cmp     ecx, 41
    je      .ext_psk
    mov     r14, r8
    jmp     .eloop

.ext_sv:
    cmp     edx, 3
    jne     .proto
    cmp     byte [r14], 2
    jne     .proto
    movzx   eax, word [r14 + 1]
    rol     ax, 8
    cmp     ax, 0304h
    jne     .proto
    or      dword [rsp + 80], 1
    mov     r14, r8
    jmp     .eloop

.ext_modes:
    cmp     edx, 2
    jne     .proto
    cmp     byte [r14], 1
    jne     .proto
    cmp     byte [r14 + 1], 0
    jne     .proto
    or      dword [rsp + 80], 2
    mov     r14, r8
    jmp     .eloop

.ext_psk:
    cmp     r8, r15
    jne     .proto
    mov     [rsp + 520], r8
    mov     r9, r14
    mov     rax, r8
    sub     rax, r9
    cmp     rax, 2
    jb      .proto
    movzx   ecx, word [r9]
    rol     cx, 8
    add     r9, 2
    test    ecx, ecx
    jz      .proto
    mov     rax, r9
    add     rax, rcx
    cmp     rax, r8
    ja      .proto
    mov     rax, r8
    sub     rax, r9
    cmp     rax, 2
    jb      .proto
    movzx   edx, word [r9]
    rol     dx, 8
    add     r9, 2
    mov     [rsp + 536], rdx
    cmp     edx, [rbx + CTX_ID_LEN]
    jne     .proto
    mov     rax, [rsp + 536]
    add     rax, 6
    cmp     rax, rcx
    jne     .proto
    mov     rax, r9
    add     rax, rdx
    add     rax, 4
    cmp     rax, r8
    ja      .proto
    lea     rcx, [rbx + CTX_IDENTITY]
    mov     rdx, r9
    mov     r8, [rsp + 536]
    call    it_ct_eq
    test    eax, eax
    jz      .proto
    mov     r9, r14
    add     r9, 4
    add     r9, [rsp + 536]
    mov     r8, [rsp + 520]
    mov     rax, r9
    add     rax, 4
    cmp     rax, r8
    ja      .proto
    add     r9, 4
    mov     rax, r8
    sub     rax, r9
    cmp     rax, 2
    jb      .proto
    movzx   ecx, word [r9]
    rol     cx, 8
    add     r9, 2
    cmp     ecx, 32
    jne     .proto
    mov     rax, r9
    add     rax, 32
    cmp     rax, r8
    jne     .proto
    mov     [rsp + 64], r9
    mov     qword [rsp + 72], 32
    mov     r14, r8
    jmp     .eloop

.edone:
    cmp     dword [rsp + 80], 3
    jne     .proto
    cmp     qword [rsp + 64], 0
    je      .proto

    xor     ecx, ecx
    xor     edx, edx
    lea     r8, [rbx + CTX_PSK]
    mov     r9d, [rbx + CTX_PSK_LEN]
    lea     rax, [rbx + CTX_EARLY]
    mov     [rsp + 32], rax
    call    it_hkdf_extract

    lea     rcx, [rbx + CTX_EARLY]
    lea     rdx, [label_ext_binder]
    mov     r8d, 10
    lea     r9, [empty_hash]
    lea     r10, [rsp + 88]
    call    tls_derive_secret

    lea     rcx, [rsp + 88]
    lea     rdx, [label_finished]
    mov     r8d, 8
    xor     r9d, r9d
    lea     r10, [rsp + 120]
    call    tls_derive_secret

    mov     rcx, r12
    mov     rdx, r13
    sub     rdx, [rsp + 72]
    sub     rdx, 2
    lea     r8, [rsp + 152]
    call    it_sha256

    lea     rcx, [rsp + 344]
    lea     rdx, [rsp + 120]
    mov     r8d, 32
    call    it_hmac_init
    lea     rcx, [rsp + 344]
    lea     rdx, [rsp + 152]
    mov     r8d, 32
    call    it_hmac_update
    lea     rcx, [rsp + 344]
    lea     rdx, [rsp + 184]
    call    it_hmac_final

    lea     rcx, [rsp + 184]
    mov     rdx, [rsp + 64]
    mov     r8d, 32
    call    it_ct_eq
    test    eax, eax
    jz      .proto

    mov     rcx, rbx
    mov     rdx, r12
    mov     r8, r13
    call    tls_transcript_update

    lea     r14, [rbx + CTX_APP]
    mov     byte [r14], 2
    mov     byte [r14 + 1], 0
    mov     byte [r14 + 2], 0
    mov     byte [r14 + 3], 34h
    mov     byte [r14 + 4], 3
    mov     byte [r14 + 5], 3
    lea     rcx, [r14 + 6]
    mov     edx, 32
    call    rng_bytes
    test    eax, eax
    jnz     .crypto
    mov     byte [r14 + 38], 0
    mov     byte [r14 + 39], 13h
    mov     byte [r14 + 40], 1
    mov     byte [r14 + 41], 0
    mov     byte [r14 + 42], 0
    mov     byte [r14 + 43], 0ch
    mov     byte [r14 + 44], 0
    mov     byte [r14 + 45], 2bh
    mov     byte [r14 + 46], 0
    mov     byte [r14 + 47], 2
    mov     byte [r14 + 48], 3
    mov     byte [r14 + 49], 4
    mov     byte [r14 + 50], 0
    mov     byte [r14 + 51], 29h
    mov     byte [r14 + 52], 0
    mov     byte [r14 + 53], 2
    mov     byte [r14 + 54], 0
    mov     byte [r14 + 55], 0

    mov     rcx, rbx
    mov     edx, 22
    mov     r8, r14
    mov     r9d, 56
    call    tls_append_plain
    test    eax, eax
    js      .done
    mov     rcx, rbx
    mov     rdx, r14
    mov     r8d, 56
    call    tls_transcript_update

    lea     rcx, [rbx + CTX_EARLY]
    lea     rdx, [label_derived]
    mov     r8d, 7
    lea     r9, [empty_hash]
    lea     r10, [rsp + 216]
    call    tls_derive_secret

    lea     rcx, [rsp + 216]
    mov     edx, 32
    lea     r8, [zeros32]
    mov     r9d, 32
    lea     rax, [rsp + 248]
    mov     [rsp + 32], rax
    call    it_hkdf_extract

    lea     rcx, [rsp + 248]
    lea     rdx, [label_derived]
    mov     r8d, 7
    lea     r9, [empty_hash]
    lea     r10, [rsp + 216]
    call    tls_derive_secret

    lea     rcx, [rsp + 216]
    mov     edx, 32
    lea     r8, [zeros32]
    mov     r9d, 32
    lea     rax, [rbx + CTX_MASTER]
    mov     [rsp + 32], rax
    call    it_hkdf_extract

    mov     rcx, rbx
    lea     rdx, [rsp + 152]
    call    tls_transcript_hash

    lea     rcx, [rsp + 248]
    lea     rdx, [label_c_hs]
    mov     r8d, 12
    lea     r9, [rsp + 152]
    lea     r10, [rbx + CTX_C_HS_SECRET]
    call    tls_derive_secret

    lea     rcx, [rsp + 248]
    lea     rdx, [label_s_hs]
    mov     r8d, 12
    lea     r9, [rsp + 152]
    lea     r10, [rbx + CTX_S_HS_SECRET]
    call    tls_derive_secret

    lea     rcx, [rbx + CTX_C_HS]
    lea     rdx, [rbx + CTX_C_HS_SECRET]
    call    tls_make_dir
    lea     rcx, [rbx + CTX_S_HS]
    lea     rdx, [rbx + CTX_S_HS_SECRET]
    call    tls_make_dir
    or      dword [rbx + CTX_FLAGS], FLAG_HS_KEYS

    mov     byte [r14], 8
    mov     byte [r14 + 1], 0
    mov     byte [r14 + 2], 0
    mov     byte [r14 + 3], 2
    mov     byte [r14 + 4], 0
    mov     byte [r14 + 5], 0
    mov     rcx, rbx
    lea     rdx, [rbx + CTX_S_HS]
    mov     r8d, 22
    mov     r9, r14
    mov     r10d, 6
    call    tls_encrypt_record
    test    eax, eax
    js      .done
    mov     rcx, rbx
    mov     rdx, r14
    mov     r8d, 6
    call    tls_transcript_update

    mov     rcx, rbx
    lea     rdx, [rbx + CTX_S_HS_SECRET]
    lea     r8, [rsp + 184]
    call    tls_finished_verify
    mov     byte [r14], 20
    mov     byte [r14 + 1], 0
    mov     byte [r14 + 2], 0
    mov     byte [r14 + 3], 32
    lea     rcx, [r14 + 4]
    lea     rdx, [rsp + 184]
    mov     r8d, 32
    call    it_memcpy
    mov     rcx, rbx
    lea     rdx, [rbx + CTX_S_HS]
    mov     r8d, 22
    mov     r9, r14
    mov     r10d, 36
    call    tls_encrypt_record
    test    eax, eax
    js      .done
    mov     rcx, rbx
    mov     rdx, r14
    mov     r8d, 36
    call    tls_transcript_update

    mov     rcx, rbx
    lea     rdx, [rsp + 152]
    call    tls_transcript_hash

    lea     rcx, [rbx + CTX_MASTER]
    lea     rdx, [label_c_ap]
    mov     r8d, 12
    lea     r9, [rsp + 152]
    lea     r10, [rsp + 312]
    call    tls_derive_secret
    lea     rcx, [rbx + CTX_C_AP]
    lea     rdx, [rsp + 312]
    call    tls_make_dir

    lea     rcx, [rbx + CTX_MASTER]
    lea     rdx, [label_s_ap]
    mov     r8d, 12
    lea     r9, [rsp + 152]
    lea     r10, [rsp + 312]
    call    tls_derive_secret
    lea     rcx, [rbx + CTX_S_AP]
    lea     rdx, [rsp + 312]
    call    tls_make_dir
    or      dword [rbx + CTX_FLAGS], FLAG_APP_KEYS
    mov     dword [rbx + CTX_STATE], ST_WAIT_CFIN
    xor     eax, eax
    jmp     .done
.proto:
    mov     eax, IT_ERR_PROTOCOL
    jmp     .done
.crypto:
    mov     eax, IT_ERR_CRYPTO
    jmp     .done
.done:
    add     rsp, 584
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int tls_handle_server_hello(ctx, msg, msg_len)
tls_handle_server_hello:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 200

    mov     rbx, rcx
    mov     r12, rdx
    mov     r13, r8
    cmp     r13, 44
    jb      .proto
    cmp     byte [r12], 2
    jne     .proto
    movzx   eax, byte [r12 + 1]
    shl     eax, 16
    movzx   ecx, byte [r12 + 2]
    shl     ecx, 8
    or      eax, ecx
    movzx   ecx, byte [r12 + 3]
    or      eax, ecx
    add     eax, 4
    cmp     rax, r13
    jne     .proto

    lea     r14, [r12 + 4]
    lea     r15, [r12 + r13]
    mov     rax, r14
    add     rax, 40
    cmp     rax, r15
    ja      .proto
    movzx   eax, word [r14]
    rol     ax, 8
    cmp     ax, 0303h
    jne     .proto
    add     r14, 2
    add     r14, 32
    movzx   eax, byte [r14]
    inc     r14
    test    eax, eax
    jnz     .proto
    mov     rax, r15
    sub     rax, r14
    cmp     rax, 5
    jb      .proto
    movzx   eax, word [r14]
    rol     ax, 8
    cmp     ax, 1301h
    jne     .proto
    add     r14, 2
    cmp     byte [r14], 0
    jne     .proto
    inc     r14
    movzx   ecx, word [r14]
    rol     cx, 8
    add     r14, 2
    mov     rax, r14
    add     rax, rcx
    cmp     rax, r15
    jne     .proto

    mov     dword [rsp + 192], 0
.eloop:
    cmp     r14, r15
    jae     .edone
    mov     rax, r15
    sub     rax, r14
    cmp     rax, 4
    jb      .proto
    movzx   ecx, word [r14]
    rol     cx, 8
    movzx   edx, word [r14 + 2]
    rol     dx, 8
    add     r14, 4
    mov     rax, r14
    add     rax, rdx
    cmp     rax, r15
    ja      .proto
    mov     r8, rax
    cmp     ecx, 43
    je      .sv
    cmp     ecx, 41
    je      .psk
    mov     r14, r8
    jmp     .eloop
.sv:
    cmp     edx, 2
    jne     .proto
    movzx   eax, word [r14]
    rol     ax, 8
    cmp     ax, 0304h
    jne     .proto
    or      dword [rsp + 192], 1
    mov     r14, r8
    jmp     .eloop
.psk:
    cmp     edx, 2
    jne     .proto
    movzx   eax, word [r14]
    rol     ax, 8
    test    ax, ax
    jnz     .proto
    or      dword [rsp + 192], 2
    mov     r14, r8
    jmp     .eloop

.edone:
    cmp     dword [rsp + 192], 3
    jne     .proto

    mov     rcx, rbx
    mov     rdx, r12
    mov     r8, r13
    call    tls_transcript_update

    lea     rcx, [rbx + CTX_EARLY]
    lea     rdx, [label_derived]
    mov     r8d, 7
    lea     r9, [empty_hash]
    lea     r10, [rsp + 64]
    call    tls_derive_secret

    lea     rcx, [rsp + 64]
    mov     edx, 32
    lea     r8, [zeros32]
    mov     r9d, 32
    lea     rax, [rsp + 96]
    mov     [rsp + 32], rax
    call    it_hkdf_extract

    lea     rcx, [rsp + 96]
    lea     rdx, [label_derived]
    mov     r8d, 7
    lea     r9, [empty_hash]
    lea     r10, [rsp + 64]
    call    tls_derive_secret

    lea     rcx, [rsp + 64]
    mov     edx, 32
    lea     r8, [zeros32]
    mov     r9d, 32
    lea     rax, [rbx + CTX_MASTER]
    mov     [rsp + 32], rax
    call    it_hkdf_extract

    mov     rcx, rbx
    lea     rdx, [rsp + 128]
    call    tls_transcript_hash

    lea     rcx, [rsp + 96]
    lea     rdx, [label_c_hs]
    mov     r8d, 12
    lea     r9, [rsp + 128]
    lea     r10, [rbx + CTX_C_HS_SECRET]
    call    tls_derive_secret

    lea     rcx, [rsp + 96]
    lea     rdx, [label_s_hs]
    mov     r8d, 12
    lea     r9, [rsp + 128]
    lea     r10, [rbx + CTX_S_HS_SECRET]
    call    tls_derive_secret

    lea     rcx, [rbx + CTX_C_HS]
    lea     rdx, [rbx + CTX_C_HS_SECRET]
    call    tls_make_dir
    lea     rcx, [rbx + CTX_S_HS]
    lea     rdx, [rbx + CTX_S_HS_SECRET]
    call    tls_make_dir
    or      dword [rbx + CTX_FLAGS], FLAG_HS_KEYS
    mov     dword [rbx + CTX_STATE], ST_WAIT_SFIN
    xor     eax, eax
    jmp     .done
.proto:
    mov     eax, IT_ERR_PROTOCOL
.done:
    add     rsp, 200
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int tls_handle_ee(ctx, msg, msg_len)
tls_handle_ee:
    cmp     r8, 6
    jne     .proto
    cmp     byte [rdx], 8
    jne     .proto
    cmp     byte [rdx + 1], 0
    jne     .proto
    cmp     byte [rdx + 2], 0
    jne     .proto
    cmp     byte [rdx + 3], 2
    jne     .proto
    cmp     byte [rdx + 4], 0
    jne     .proto
    cmp     byte [rdx + 5], 0
    jne     .proto
    or      dword [rcx + CTX_FLAGS], FLAG_EE
    add     rcx, CTX_TRANSCRIPT
    jmp     it_sha256_update
.proto:
    mov     eax, IT_ERR_PROTOCOL
    ret

; int tls_handle_server_finished(ctx, msg, msg_len)
tls_handle_server_finished:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 168

    mov     rbx, rcx
    mov     r12, rdx
    mov     r13, r8
    cmp     r13, 36
    jne     .proto
    cmp     byte [r12], 20
    jne     .proto
    cmp     byte [r12 + 1], 0
    jne     .proto
    cmp     byte [r12 + 2], 0
    jne     .proto
    cmp     byte [r12 + 3], 32
    jne     .proto

    mov     rcx, rbx
    lea     rdx, [rbx + CTX_S_HS_SECRET]
    lea     r8, [rsp + 64]
    call    tls_finished_verify
    lea     rcx, [rsp + 64]
    lea     rdx, [r12 + 4]
    mov     r8d, 32
    call    it_ct_eq
    test    eax, eax
    jz      .proto

    mov     rcx, rbx
    mov     rdx, r12
    mov     r8d, 36
    call    tls_transcript_update

    mov     rcx, rbx
    lea     rdx, [rsp + 96]
    call    tls_transcript_hash

    lea     rcx, [rbx + CTX_MASTER]
    lea     rdx, [label_c_ap]
    mov     r8d, 12
    lea     r9, [rsp + 96]
    lea     r10, [rsp + 128]
    call    tls_derive_secret
    lea     rcx, [rbx + CTX_C_AP]
    lea     rdx, [rsp + 128]
    call    tls_make_dir

    lea     rcx, [rbx + CTX_MASTER]
    lea     rdx, [label_s_ap]
    mov     r8d, 12
    lea     r9, [rsp + 96]
    lea     r10, [rsp + 128]
    call    tls_derive_secret
    lea     rcx, [rbx + CTX_S_AP]
    lea     rdx, [rsp + 128]
    call    tls_make_dir
    or      dword [rbx + CTX_FLAGS], FLAG_APP_KEYS

    mov     rcx, rbx
    lea     rdx, [rbx + CTX_C_HS_SECRET]
    lea     r8, [rsp + 64]
    call    tls_finished_verify

    lea     r14, [rbx + CTX_APP]
    mov     byte [r14], 20
    mov     byte [r14 + 1], 0
    mov     byte [r14 + 2], 0
    mov     byte [r14 + 3], 32
    lea     rcx, [r14 + 4]
    lea     rdx, [rsp + 64]
    mov     r8d, 32
    call    it_memcpy

    mov     rcx, rbx
    lea     rdx, [rbx + CTX_C_HS]
    mov     r8d, 22
    mov     r9, r14
    mov     r10d, 36
    call    tls_encrypt_record
    test    eax, eax
    js      .done
    mov     rcx, rbx
    mov     rdx, r14
    mov     r8d, 36
    call    tls_transcript_update
    mov     dword [rbx + CTX_STATE], ST_ESTABLISHED
    xor     eax, eax
    jmp     .done
.proto:
    mov     eax, IT_ERR_PROTOCOL
.done:
    add     rsp, 168
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int tls_handle_client_finished(ctx, msg, msg_len)
tls_handle_client_finished:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 104

    mov     rbx, rcx
    mov     r12, rdx
    mov     r13, r8
    cmp     r13, 36
    jne     .proto
    cmp     byte [r12], 20
    jne     .proto
    cmp     byte [r12 + 1], 0
    jne     .proto
    cmp     byte [r12 + 2], 0
    jne     .proto
    cmp     byte [r12 + 3], 32
    jne     .proto

    mov     rcx, rbx
    lea     rdx, [rbx + CTX_C_HS_SECRET]
    lea     r8, [rsp + 64]
    call    tls_finished_verify
    lea     rcx, [rsp + 64]
    lea     rdx, [r12 + 4]
    mov     r8d, 32
    call    it_ct_eq
    test    eax, eax
    jz      .proto

    mov     rcx, rbx
    mov     rdx, r12
    mov     r8d, 36
    call    tls_transcript_update
    mov     dword [rbx + CTX_STATE], ST_ESTABLISHED
    xor     eax, eax
    jmp     .done
.proto:
    mov     eax, IT_ERR_PROTOCOL
.done:
    add     rsp, 104
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int tls_process_hs(ctx)
tls_process_hs:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi
    sub     rsp, 8

    mov     rbx, rcx
.loop:
    mov     eax, [rbx + CTX_HS_LEN]
    cmp     eax, 4
    jb      .ok
    lea     rsi, [rbx + CTX_HS]
    movzx   r13d, byte [rsi]
    movzx   eax, byte [rsi + 1]
    shl     eax, 16
    movzx   ecx, byte [rsi + 2]
    shl     ecx, 8
    or      eax, ecx
    movzx   ecx, byte [rsi + 3]
    or      eax, ecx
    add     eax, 4
    cmp     eax, IT_HS_CAP
    ja      .proto
    cmp     eax, [rbx + CTX_HS_LEN]
    ja      .ok
    mov     r14d, eax

    mov     eax, [rbx + CTX_ROLE]
    test    eax, eax
    jnz     .server

.client:
    mov     eax, [rbx + CTX_STATE]
    cmp     eax, ST_CH_SENT
    je      .c_sh
    cmp     eax, ST_WAIT_SFIN
    je      .c_sfin
    jmp     .proto
.c_sh:
    cmp     r13d, 2
    jne     .proto
    mov     rcx, rbx
    mov     rdx, rsi
    mov     r8d, r14d
    call    tls_handle_server_hello
    test    eax, eax
    js      .done
    jmp     .after
.c_sfin:
    cmp     r13d, 8
    je      .c_ee
    cmp     r13d, 20
    je      .c_fin
    jmp     .proto
.c_ee:
    mov     rcx, rbx
    mov     rdx, rsi
    mov     r8d, r14d
    call    tls_handle_ee
    test    eax, eax
    js      .done
    jmp     .after
.c_fin:
    test    dword [rbx + CTX_FLAGS], FLAG_EE
    jz      .proto
    mov     rcx, rbx
    mov     rdx, rsi
    mov     r8d, r14d
    call    tls_handle_server_finished
    test    eax, eax
    js      .done
    jmp     .after

.server:
    mov     eax, [rbx + CTX_STATE]
    cmp     eax, ST_WAIT_CH
    je      .s_ch
    cmp     eax, ST_WAIT_CFIN
    je      .s_fin
    jmp     .proto
.s_ch:
    cmp     r13d, 1
    jne     .proto
    mov     rcx, rbx
    mov     rdx, rsi
    mov     r8d, r14d
    call    tls_handle_client_hello
    test    eax, eax
    js      .done
    jmp     .after
.s_fin:
    cmp     r13d, 20
    jne     .proto
    mov     rcx, rbx
    mov     rdx, rsi
    mov     r8d, r14d
    call    tls_handle_client_finished
    test    eax, eax
    js      .done
    jmp     .after

.after:
    mov     eax, [rbx + CTX_HS_LEN]
    sub     eax, r14d
    mov     [rbx + CTX_HS_LEN], eax
    test    eax, eax
    jz      .loop
    lea     rcx, [rbx + CTX_HS]
    lea     rdx, [rcx + r14]
    mov     r8d, eax
    call    it_memcpy
    jmp     .loop

.ok:
    cmp     dword [rbx + CTX_STATE], ST_ESTABLISHED
    je      .done_state
    xor     eax, eax
    jmp     .done
.done_state:
    mov     eax, IT_DONE
    jmp     .done
.proto:
    mov     eax, IT_ERR_PROTOCOL
.done:
    add     rsp, 8
    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int it_tls_step(it_tls_ctx *ctx)
it_tls_step:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi
    sub     rsp, 88

    test    rcx, rcx
    jz      .bad
    mov     rbx, rcx
    mov     qword [rsp + 64], 0

    cmp     dword [rbx + CTX_STATE], ST_ERROR
    je      .state_err

    cmp     dword [rbx + CTX_ROLE], ROLE_CLIENT
    jne     .loop
    cmp     dword [rbx + CTX_STATE], ST_INIT
    jne     .loop
    mov     rcx, rbx
    call    tls_client_send_ch
    test    eax, eax
    js      .ret_err
    mov     qword [rsp + 64], 1

.loop:
    mov     eax, [rbx + CTX_RX_LEN]
    cmp     eax, 5
    jb      .after
    lea     rsi, [rbx + CTX_RX]
    movzx   r12d, byte [rsi]
    movzx   r13d, word [rsi + 3]
    rol     r13w, 8
    cmp     r13d, 16379
    ja      .proto
    mov     eax, [rbx + CTX_RX_LEN]
    lea     rcx, [r13 + 5]
    cmp     rax, rcx
    jb      .after

    cmp     r12d, 20
    je      .consumed
    cmp     r12d, 21
    je      .proto
    cmp     r12d, 22
    je      .plain_hs
    cmp     r12d, 23
    je      .encrypted
    jmp     .proto

.plain_hs:
    mov     eax, [rbx + CTX_STATE]
    cmp     eax, ST_CH_SENT
    je      .append_hs
    cmp     eax, ST_WAIT_CH
    jne     .proto
.append_hs:
    mov     eax, [rbx + CTX_HS_LEN]
    lea     rcx, [rax + r13]
    cmp     rcx, IT_HS_CAP
    ja      .nobuf
    lea     rcx, [rbx + CTX_HS]
    add     rcx, rax
    lea     rdx, [rsi + 5]
    mov     r8, r13
    call    it_memcpy
    add     [rbx + CTX_HS_LEN], r13d
    mov     rcx, rbx
    call    tls_process_hs
    test    eax, eax
    js      .ret_err
    jmp     .consumed

.encrypted:
    mov     eax, [rbx + CTX_ROLE]
    test    eax, eax
    jnz     .srv_enc
    mov     eax, [rbx + CTX_STATE]
    cmp     eax, ST_WAIT_SFIN
    je      .client_hs
    cmp     eax, ST_ESTABLISHED
    je      .client_ap
    jmp     .proto
.client_hs:
    lea     r12, [rbx + CTX_S_HS]
    jmp     .dec
.client_ap:
    lea     r12, [rbx + CTX_S_AP]
    jmp     .dec
.srv_enc:
    mov     eax, [rbx + CTX_STATE]
    cmp     eax, ST_WAIT_CFIN
    je      .srv_hs
    cmp     eax, ST_ESTABLISHED
    je      .srv_ap
    jmp     .proto
.srv_hs:
    lea     r12, [rbx + CTX_C_HS]
    jmp     .dec
.srv_ap:
    lea     r12, [rbx + CTX_C_AP]
.dec:
    mov     rcx, rbx
    mov     rdx, r12
    mov     r8, rsi
    mov     r9, r13
    call    tls_decrypt_record
    test    eax, eax
    js      .ret_err
    mov     r14d, eax
    mov     r15d, edx
    cmp     r15d, 22
    je      .inner_hs
    cmp     r15d, 23
    je      .inner_app
    cmp     r15d, 21
    je      .proto
    cmp     r15d, 20
    je      .consumed
    jmp     .proto
.inner_hs:
    mov     eax, [rbx + CTX_HS_LEN]
    lea     rcx, [rax + r14]
    cmp     rcx, IT_HS_CAP
    ja      .nobuf
    lea     rcx, [rbx + CTX_HS]
    add     rcx, rax
    lea     rdx, [rbx + CTX_SCRATCH]
    mov     r8, r14
    call    it_memcpy
    add     [rbx + CTX_HS_LEN], r14d
    mov     rcx, rbx
    call    tls_process_hs
    test    eax, eax
    js      .ret_err
    jmp     .consumed
.inner_app:
    cmp     dword [rbx + CTX_STATE], ST_ESTABLISHED
    jne     .proto
    mov     eax, [rbx + CTX_APP_OFF]
    test    eax, eax
    jz      .app_cap
    mov     ecx, [rbx + CTX_APP_LEN]
    sub     ecx, eax
    test    ecx, ecx
    jz      .app_reset
    lea     rcx, [rbx + CTX_APP]
    lea     rdx, [rcx + rax]
    mov     r8d, [rbx + CTX_APP_LEN]
    sub     r8d, eax
    call    it_memcpy
    mov     eax, [rbx + CTX_APP_LEN]
    sub     eax, [rbx + CTX_APP_OFF]
    mov     [rbx + CTX_APP_LEN], eax
    mov     dword [rbx + CTX_APP_OFF], 0
    jmp     .app_cap
.app_reset:
    mov     dword [rbx + CTX_APP_OFF], 0
    mov     dword [rbx + CTX_APP_LEN], 0
.app_cap:
    mov     eax, [rbx + CTX_APP_LEN]
    lea     rcx, [rax + r14]
    cmp     rcx, IT_APP_CAP
    ja      .nobuf
    lea     rcx, [rbx + CTX_APP]
    add     rcx, rax
    lea     rdx, [rbx + CTX_SCRATCH]
    mov     r8, r14
    call    it_memcpy
    add     [rbx + CTX_APP_LEN], r14d
    jmp     .consumed

.consumed:
    mov     r12d, r13d
    add     r12d, 5
    mov     eax, [rbx + CTX_RX_LEN]
    sub     eax, r12d
    mov     [rbx + CTX_RX_LEN], eax
    test    eax, eax
    jz      .moved
    lea     rcx, [rbx + CTX_RX]
    lea     rdx, [rcx + r12]
    mov     r8d, eax
    call    it_memcpy
.moved:
    mov     qword [rsp + 64], 1
    jmp     .loop

.after:
    cmp     dword [rbx + CTX_STATE], ST_ESTABLISHED
    je      .done
    cmp     qword [rsp + 64], 0
    jne     .need
    mov     eax, IT_NEED_MORE
    jmp     .out
.need:
    mov     eax, IT_OK
    jmp     .out
.done:
    mov     eax, IT_DONE
    jmp     .out
.bad:
    mov     eax, IT_ERR_ARGS
    jmp     .out
.state_err:
    mov     eax, IT_ERR_STATE
    jmp     .out
.proto:
    mov     eax, IT_ERR_PROTOCOL
    jmp     .ret_err
.nobuf:
    mov     eax, IT_ERR_BUFFER
    jmp     .ret_err
.ret_err:
    mov     dword [rbx + CTX_STATE], ST_ERROR
    mov     [rbx + CTX_ERR], eax
.out:
    add     rsp, 88
    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
