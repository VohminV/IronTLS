; IronTLS - HKDF-SHA256 and TLS 1.3 HKDF-Expand-Label (Win64 ABI)
default rel
%include "it_offsets.inc"

section .text

global it_hkdf_extract
global it_hkdf_expand
global it_hkdf_expand_label

extern it_hmac_init
extern it_hmac_update
extern it_hmac_final
extern it_memcpy
extern it_memzero

; void it_hkdf_extract(const void *salt, size_t salt_len,
;                      const void *ikm, size_t ikm_len, uint8_t out[32])
it_hkdf_extract:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 200

    mov     r14, rcx                ; salt
    mov     r15, rdx                ; salt_len
    mov     rbx, r8                 ; ikm
    mov     r12, r9                 ; ikm_len
    mov     r13, [rbp + 48]         ; out

    mov     rcx, rsp
    mov     rdx, r14
    mov     r8, r15
    call    it_hmac_init
    mov     rcx, rsp
    mov     rdx, rbx
    mov     r8, r12
    call    it_hmac_update
    mov     rcx, rsp
    mov     rdx, r13
    call    it_hmac_final

    mov     rcx, rsp
    mov     edx, HMAC_SIZE
    call    it_memzero

    add     rsp, 200
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int it_hkdf_expand(const void *prk, size_t prk_len,
;                    const void *info, size_t info_len,
;                    uint8_t *out, size_t out_len)
it_hkdf_expand:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 232

    mov     rbx, rcx                ; prk
    mov     r12, rdx                ; prk_len
    mov     r13, r8                 ; info
    mov     r14, r9                 ; info_len
    mov     r15, [rbp + 48]         ; out
    mov     rax, [rbp + 56]         ; out_len

    mov     rcx, 8160               ; 255 * 32
    cmp     rax, rcx
    ja      .out_of_range

    mov     [rsp + 216], rax        ; remaining
    mov     dword [rsp + 224], 1    ; block counter

    test    rax, rax
    jz      .success

.loop:
    mov     rcx, rsp
    mov     rdx, rbx
    mov     r8, r12
    call    it_hmac_init

    cmp     dword [rsp + 224], 1
    je      .no_t_prev
    mov     rcx, rsp
    mov     rdx, rsp
    add     rdx, 176
    mov     r8d, 32
    call    it_hmac_update
.no_t_prev:
    mov     rcx, rsp
    mov     rdx, r13
    mov     r8, r14
    call    it_hmac_update

    mov     eax, [rsp + 224]
    mov     [rsp + 208], al
    mov     rcx, rsp
    mov     rdx, rsp
    add     rdx, 208
    mov     r8d, 1
    call    it_hmac_update

    mov     rcx, rsp
    mov     rdx, rsp
    add     rdx, 176
    call    it_hmac_final

    mov     rax, [rsp + 216]
    cmp     rax, 32
    jbe     .have_n
    mov     eax, 32
.have_n:
    mov     r9, rax                 ; n
    mov     rcx, r15
    mov     rdx, rsp
    add     rdx, 176
    mov     r8, r9
    call    it_memcpy
    add     r15, r9
    sub     [rsp + 216], r9
    inc     dword [rsp + 224]
    cmp     qword [rsp + 216], 0
    jne     .loop

.success:
    xor     eax, eax
    jmp     .done

.out_of_range:
    mov     eax, -1

.done:
    add     rsp, 232
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; int it_hkdf_expand_label(const void *secret, const char *label, size_t label_len,
;                          const void *context, size_t context_len,
;                          uint8_t *out, size_t out_len)
it_hkdf_expand_label:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 640

    mov     [rsp + 576], rcx        ; secret
    mov     [rsp + 584], rdx        ; label
    mov     [rsp + 592], r8         ; label_len
    mov     [rsp + 600], r9         ; context

    mov     rax, [rbp + 48]         ; context_len
    cmp     rax, 255
    ja      .bad_args
    mov     r10, [rbp + 64]         ; out_len
    cmp     r10, 65535
    ja      .bad_args
    mov     r11, [rsp + 592]        ; label_len
    cmp     r11, 249
    ja      .bad_args

    mov     eax, r10d
    rol     ax, 8
    mov     [rsp], ax

    mov     eax, r11d
    add     eax, 6
    mov     [rsp + 2], al                   ; label length (incl. "tls13 ")

    mov     dword [rsp + 3], 31736c74h      ; "tls1"
    mov     word  [rsp + 7], 2033h          ; "3 "

    mov     rcx, rsp
    add     rcx, 9
    mov     rdx, [rsp + 584]
    mov     r8, [rsp + 592]
    call    it_memcpy

    mov     r11, [rsp + 592]
    mov     rax, [rbp + 48]         ; context_len
    mov     [rsp + 9 + r11], al
    mov     rcx, rsp
    add     rcx, 10
    add     rcx, r11
    mov     rdx, [rsp + 600]
    mov     r8, rax
    call    it_memcpy

    mov     r11, [rsp + 592]
    mov     r9, [rbp + 48]          ; context_len
    lea     r9, [r9 + r11 + 10]     ; info_len

    mov     r10, [rbp + 56]         ; out
    mov     r11, [rbp + 64]         ; out_len
    mov     rcx, [rsp + 576]
    mov     edx, 32
    mov     r8, rsp
    sub     rsp, 48
    mov     [rsp + 32], r10
    mov     [rsp + 40], r11
    call    it_hkdf_expand
    add     rsp, 48
    jmp     .done

.bad_args:
    mov     eax, -1

.done:
    leave
    ret

