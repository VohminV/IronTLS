; IronTLS - X25519 (curve25519) field arithmetic and Montgomery ladder (Win64 ABI)
; Field elements are 5 limbs of 51 bits, little-endian.
default rel

%define MASK51      0x7FFFFFFFFFFFF
%define IT_ERR_ARGS     (-1)
%define IT_ERR_CRYPTO   (-4)

; x25519_core workspace layout (bytes)
%define FE_X1       0
%define FE_X2       40
%define FE_Z2       80
%define FE_X3       120
%define FE_Z3       160
%define FE_A        200
%define FE_AA       240
%define FE_B        280
%define FE_BB       320
%define FE_E        360
%define FE_C        400
%define FE_D        440
%define FE_DA       480
%define FE_CB       520
%define FE_T0       560
%define FE_T1       600
%define WS_SCALAR   640
%define WS_SIZE     672
%define WS_FRAME    696

section .rodata
align 8
x25519_basepoint: db 9
                  times 31 db 0

section .text

global it_x25519
global it_x25519_base

extern it_memzero

; ---------------------------------------------------------------------------
; void fe_reduce(uint64_t *f)
; Carry-propagate until all 5 limbs are < 2^51. In place.
; Clobbers rax, r9, r10, r11.
; ---------------------------------------------------------------------------
fe_reduce:
    mov     r11, MASK51
    mov     r10d, 6
.round:
    xor     r9d, r9d
    mov     rax, [rcx]
    add     rax, r9
    mov     r9, rax
    and     r9, r11
    shr     rax, 51
    mov     [rcx], r9
    mov     r9, rax
    mov     rax, [rcx + 8]
    add     rax, r9
    mov     r9, rax
    and     r9, r11
    shr     rax, 51
    mov     [rcx + 8], r9
    mov     r9, rax
    mov     rax, [rcx + 16]
    add     rax, r9
    mov     r9, rax
    and     r9, r11
    shr     rax, 51
    mov     [rcx + 16], r9
    mov     r9, rax
    mov     rax, [rcx + 24]
    add     rax, r9
    mov     r9, rax
    and     r9, r11
    shr     rax, 51
    mov     [rcx + 24], r9
    mov     r9, rax
    mov     rax, [rcx + 32]
    add     rax, r9
    mov     r9, rax
    and     r9, r11
    shr     rax, 51
    mov     [rcx + 32], r9
    mov     r9, rax
    test    r9, r9
    jz      .done
    imul    r9, r9, 19
    add     [rcx], r9
    dec     r10d
    jnz     .round
.done:
    ret

; ---------------------------------------------------------------------------
; void fe_add(uint64_t *dst, const uint64_t *a, const uint64_t *b)
; ---------------------------------------------------------------------------
fe_add:
    mov     rax, [rdx]
    add     rax, [r8]
    mov     [rcx], rax
    mov     rax, [rdx + 8]
    add     rax, [r8 + 8]
    mov     [rcx + 8], rax
    mov     rax, [rdx + 16]
    add     rax, [r8 + 16]
    mov     [rcx + 16], rax
    mov     rax, [rdx + 24]
    add     rax, [r8 + 24]
    mov     [rcx + 24], rax
    mov     rax, [rdx + 32]
    add     rax, [r8 + 32]
    mov     [rcx + 32], rax
    jmp     fe_reduce

; ---------------------------------------------------------------------------
; void fe_sub(uint64_t *dst, const uint64_t *a, const uint64_t *b)
; dst = a - b + 2p, kept non-negative.
; ---------------------------------------------------------------------------
fe_sub:
    mov     r9, 0xFFFFFFFFFFFFE          ; 2^52 - 2
    mov     r10, 0xFFFFFFFFFFFDA         ; 2^52 - 38
    mov     rax, [rdx]
    add     rax, r10
    sub     rax, [r8]
    mov     [rcx], rax
    mov     rax, [rdx + 8]
    add     rax, r9
    sub     rax, [r8 + 8]
    mov     [rcx + 8], rax
    mov     rax, [rdx + 16]
    add     rax, r9
    sub     rax, [r8 + 16]
    mov     [rcx + 16], rax
    mov     rax, [rdx + 24]
    add     rax, r9
    sub     rax, [r8 + 24]
    mov     [rcx + 24], rax
    mov     rax, [rdx + 32]
    add     rax, r9
    sub     rax, [r8 + 32]
    mov     [rcx + 32], rax
    jmp     fe_reduce

; ---------------------------------------------------------------------------
; void fe_mul(uint64_t *dst, const uint64_t *a, const uint64_t *b)
; 5x51 schoolbook multiplication modulo 2^255 - 19.
; ---------------------------------------------------------------------------
fe_mul:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 136

    mov     rbx, rcx
    mov     r12, rdx
    mov     r13, r8

    xor     eax, eax
    mov     [rsp + 0], rax
    mov     [rsp + 8], rax
    mov     [rsp + 16], rax
    mov     [rsp + 24], rax
    mov     [rsp + 32], rax
    mov     [rsp + 40], rax
    mov     [rsp + 48], rax
    mov     [rsp + 56], rax
    mov     [rsp + 64], rax
    mov     [rsp + 72], rax

    mov     rax, [r12]
    imul    rax, rax, 19
    mov     [rsp + 80], rax
    mov     rax, [r12 + 8]
    imul    rax, rax, 19
    mov     [rsp + 88], rax
    mov     rax, [r12 + 16]
    imul    rax, rax, 19
    mov     [rsp + 96], rax
    mov     rax, [r12 + 24]
    imul    rax, rax, 19
    mov     [rsp + 104], rax
    mov     rax, [r12 + 32]
    imul    rax, rax, 19
    mov     [rsp + 112], rax

    xor     r14d, r14d
.outer:
    xor     r15d, r15d
.inner:
    mov     r10, r14
    add     r10, r15
    cmp     r10, 5
    jb      .nofold
    sub     r10, 5
    mov     rax, [rsp + r14*8 + 80]
    jmp     .have
.nofold:
    mov     rax, [r12 + r14*8]
.have:
    mul     qword [r13 + r15*8]
    shl     r10, 4
    add     [rsp + r10], rax
    adc     [rsp + r10 + 8], rdx
    inc     r15d
    cmp     r15d, 5
    jb      .inner
    inc     r14d
    cmp     r14d, 5
    jb      .outer

    mov     r8, MASK51
    xor     r9d, r9d
    xor     ecx, ecx
.fold:
    mov     r11, rcx
    shl     r11, 4
    mov     rax, [rsp + r11]
    mov     rdx, [rsp + r11 + 8]
    add     rax, r9
    adc     rdx, 0
    mov     r10, rax
    and     r10, r8
    shr     rax, 51
    shl     rdx, 13
    or      rax, rdx
    mov     [rbx + rcx*8], r10
    mov     r9, rax
    inc     ecx
    cmp     ecx, 5
    jb      .fold

    imul    r9, r9, 19
    add     [rbx], r9

    mov     rcx, rbx
    call    fe_reduce

    add     rsp, 136
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; ---------------------------------------------------------------------------
; void fe_sq(uint64_t *dst, const uint64_t *a)
; ---------------------------------------------------------------------------
fe_sq:
    mov     r8, rdx
    jmp     fe_mul

; ---------------------------------------------------------------------------
; void fe_mul_a24(uint64_t *dst, const uint64_t *a)
; ---------------------------------------------------------------------------
fe_mul_a24:
    mov     r11, rdx
    mov     r8, MASK51
    mov     r10d, 121665
    xor     r9d, r9d

    mov     rax, [r11]
    mul     r10
    add     rax, r9
    adc     rdx, 0
    mov     r9, rax
    and     r9, r8
    shr     rax, 51
    shl     rdx, 13
    or      rax, rdx
    mov     [rcx], r9
    mov     r9, rax

    mov     rax, [r11 + 8]
    mul     r10
    add     rax, r9
    adc     rdx, 0
    mov     r9, rax
    and     r9, r8
    shr     rax, 51
    shl     rdx, 13
    or      rax, rdx
    mov     [rcx + 8], r9
    mov     r9, rax

    mov     rax, [r11 + 16]
    mul     r10
    add     rax, r9
    adc     rdx, 0
    mov     r9, rax
    and     r9, r8
    shr     rax, 51
    shl     rdx, 13
    or      rax, rdx
    mov     [rcx + 16], r9
    mov     r9, rax

    mov     rax, [r11 + 24]
    mul     r10
    add     rax, r9
    adc     rdx, 0
    mov     r9, rax
    and     r9, r8
    shr     rax, 51
    shl     rdx, 13
    or      rax, rdx
    mov     [rcx + 24], r9
    mov     r9, rax

    mov     rax, [r11 + 32]
    mul     r10
    add     rax, r9
    adc     rdx, 0
    mov     r9, rax
    and     r9, r8
    shr     rax, 51
    shl     rdx, 13
    or      rax, rdx
    mov     [rcx + 32], r9
    mov     r9, rax

    imul    r9, r9, 19
    add     [rcx], r9
    jmp     fe_reduce

; ---------------------------------------------------------------------------
; void fe_cswap(uint64_t *a, uint64_t *b, uint64_t bit)
; Constant-time swap when bit == 1.
; ---------------------------------------------------------------------------
fe_cswap:
    neg     r8
    mov     rax, [rcx]
    mov     r9, [rdx]
    xor     r9, rax
    and     r9, r8
    xor     rax, r9
    xor     [rdx], r9
    mov     [rcx], rax

    mov     rax, [rcx + 8]
    mov     r9, [rdx + 8]
    xor     r9, rax
    and     r9, r8
    xor     rax, r9
    xor     [rdx + 8], r9
    mov     [rcx + 8], rax

    mov     rax, [rcx + 16]
    mov     r9, [rdx + 16]
    xor     r9, rax
    and     r9, r8
    xor     rax, r9
    xor     [rdx + 16], r9
    mov     [rcx + 16], rax

    mov     rax, [rcx + 24]
    mov     r9, [rdx + 24]
    xor     r9, rax
    and     r9, r8
    xor     rax, r9
    xor     [rdx + 24], r9
    mov     [rcx + 24], rax

    mov     rax, [rcx + 32]
    mov     r9, [rdx + 32]
    xor     r9, rax
    and     r9, r8
    xor     rax, r9
    xor     [rdx + 32], r9
    mov     [rcx + 32], rax
    ret

; ---------------------------------------------------------------------------
; void fe_frombytes(uint64_t *dst, const uint8_t *src)
; ---------------------------------------------------------------------------
fe_frombytes:
    mov     r8, MASK51
    mov     rax, [rdx]
    and     rax, r8
    mov     [rcx], rax
    mov     rax, [rdx + 6]
    shr     rax, 3
    and     rax, r8
    mov     [rcx + 8], rax
    mov     rax, [rdx + 12]
    shr     rax, 6
    and     rax, r8
    mov     [rcx + 16], rax
    mov     rax, [rdx + 19]
    shr     rax, 1
    and     rax, r8
    mov     [rcx + 24], rax
    mov     rax, [rdx + 24]
    shr     rax, 12
    and     rax, r8
    mov     [rcx + 32], rax
    ret

; ---------------------------------------------------------------------------
; void fe_tobytes(uint8_t *out, const uint64_t *f)
; Canonical little-endian encoding.
; ---------------------------------------------------------------------------
fe_tobytes:
    push    rbp
    mov     rbp, rsp
    push    rbx
    sub     rsp, 48

    mov     rbx, rcx
    mov     rax, [rdx]
    mov     [rsp], rax
    mov     rax, [rdx + 8]
    mov     [rsp + 8], rax
    mov     rax, [rdx + 16]
    mov     [rsp + 16], rax
    mov     rax, [rdx + 24]
    mov     [rsp + 24], rax
    mov     rax, [rdx + 32]
    mov     [rsp + 32], rax

    mov     rcx, rsp
    call    fe_reduce

    mov     rax, [rsp]
    mov     r9, [rsp + 8]
    mov     r8, r9
    shl     r8, 51
    add     r8, rax

    shr     r9, 13
    mov     r10, [rsp + 16]
    mov     rax, r10
    shl     rax, 38
    add     r9, rax

    shr     r10, 26
    mov     r11, [rsp + 24]
    mov     rax, r11
    shl     rax, 25
    add     r10, rax

    shr     r11, 39
    mov     rcx, [rsp + 32]
    shl     rcx, 12
    add     r11, rcx

    add     r8, 19
    adc     r9, 0
    adc     r10, 0
    adc     r11, 0

    mov     rax, r11
    shr     rax, 63
    neg     rax
    not     rax
    and     rax, 19
    sub     r8, rax
    sbb     r9, 0
    sbb     r10, 0
    sbb     r11, 0
    btr     r11, 63

    mov     [rbx], r8
    mov     [rbx + 8], r9
    mov     [rbx + 16], r10
    mov     [rbx + 24], r11

    add     rsp, 48
    pop     rbx
    pop     rbp
    ret

; ---------------------------------------------------------------------------
; void fe_invert(uint64_t *dst, const uint64_t *src)
; dst = src^(p-2) = src^(2^255 - 21)
; ---------------------------------------------------------------------------
fe_invert:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    sub     rsp, 88

    mov     rbx, rcx
    mov     rax, [rdx]
    mov     [rsp], rax
    mov     rax, [rdx + 8]
    mov     [rsp + 8], rax
    mov     rax, [rdx + 16]
    mov     [rsp + 16], rax
    mov     rax, [rdx + 24]
    mov     [rsp + 24], rax
    mov     rax, [rdx + 32]
    mov     [rsp + 32], rax

    lea     r12, [rsp + 48]
    mov     rax, [rsp]
    mov     [r12], rax
    mov     rax, [rsp + 8]
    mov     [r12 + 8], rax
    mov     rax, [rsp + 16]
    mov     [r12 + 16], rax
    mov     rax, [rsp + 24]
    mov     [r12 + 24], rax
    mov     rax, [rsp + 32]
    mov     [r12 + 32], rax

    ; e = 2^255 - 21: bit 254 = 1 (t = a), bits 8..253 = 1, low byte = 0xEB
    mov     r13d, 253
.loop:
    mov     rcx, r12
    mov     rdx, r12
    call    fe_sq
    cmp     r13d, 8
    jae     .mul
    mov     eax, 0EBh
    mov     ecx, r13d
    shr     eax, cl
    test    eax, 1
    jz      .next
.mul:
    mov     rcx, r12
    mov     rdx, r12
    lea     r8, [rsp]
    call    fe_mul
.next:
    dec     r13d
    jns     .loop

    mov     rax, [r12]
    mov     [rbx], rax
    mov     rax, [r12 + 8]
    mov     [rbx + 8], rax
    mov     rax, [r12 + 16]
    mov     [rbx + 16], rax
    mov     rax, [r12 + 24]
    mov     [rbx + 24], rax
    mov     rax, [r12 + 32]
    mov     [rbx + 32], rax

    add     rsp, 88
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; ---------------------------------------------------------------------------
; int x25519_core(uint8_t *out, const uint8_t *scalar, const uint8_t *point)
; ---------------------------------------------------------------------------
x25519_core:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, WS_FRAME

    test    rcx, rcx
    jz      .bad
    test    rdx, rdx
    jz      .bad
    test    r8, r8
    jz      .bad

    mov     rbx, rcx
    mov     r12, rsp
    mov     r15, r8
    lea     r14, [r12 + WS_SCALAR]

    mov     rax, [rdx]
    mov     [r14], rax
    mov     rax, [rdx + 8]
    mov     [r14 + 8], rax
    mov     rax, [rdx + 16]
    mov     [r14 + 16], rax
    mov     rax, [rdx + 24]
    mov     [r14 + 24], rax
    and     byte [r14], 248
    and     byte [r14 + 31], 127
    or      byte [r14 + 31], 64

    lea     rcx, [r12 + FE_X1]
    mov     rdx, r15
    call    fe_frombytes

    mov     qword [r12 + FE_X2], 1
    mov     qword [r12 + FE_X2 + 8], 0
    mov     qword [r12 + FE_X2 + 16], 0
    mov     qword [r12 + FE_X2 + 24], 0
    mov     qword [r12 + FE_X2 + 32], 0

    mov     qword [r12 + FE_Z2], 0
    mov     qword [r12 + FE_Z2 + 8], 0
    mov     qword [r12 + FE_Z2 + 16], 0
    mov     qword [r12 + FE_Z2 + 24], 0
    mov     qword [r12 + FE_Z2 + 32], 0

    mov     rax, [r12 + FE_X1]
    mov     [r12 + FE_X3], rax
    mov     rax, [r12 + FE_X1 + 8]
    mov     [r12 + FE_X3 + 8], rax
    mov     rax, [r12 + FE_X1 + 16]
    mov     [r12 + FE_X3 + 16], rax
    mov     rax, [r12 + FE_X1 + 24]
    mov     [r12 + FE_X3 + 24], rax
    mov     rax, [r12 + FE_X1 + 32]
    mov     [r12 + FE_X3 + 32], rax

    mov     qword [r12 + FE_Z3], 1
    mov     qword [r12 + FE_Z3 + 8], 0
    mov     qword [r12 + FE_Z3 + 16], 0
    mov     qword [r12 + FE_Z3 + 24], 0
    mov     qword [r12 + FE_Z3 + 32], 0

    xor     r15d, r15d
    mov     r13d, 254

.ladder:
    mov     eax, r13d
    mov     ecx, eax
    shr     eax, 3
    and     ecx, 7
    movzx   eax, byte [r14 + rax]
    shr     eax, cl
    and     eax, 1
    mov     [r12 + WS_SIZE + 0], eax

    xor     r15d, eax
    mov     [r12 + WS_SIZE + 4], r15d

    lea     rcx, [r12 + FE_X2]
    lea     rdx, [r12 + FE_X3]
    mov     r8d, [r12 + WS_SIZE + 4]
    call    fe_cswap
    lea     rcx, [r12 + FE_Z2]
    lea     rdx, [r12 + FE_Z3]
    mov     r8d, [r12 + WS_SIZE + 4]
    call    fe_cswap
    mov     r15d, [r12 + WS_SIZE + 0]

    lea     rcx, [r12 + FE_A]
    lea     rdx, [r12 + FE_X2]
    lea     r8, [r12 + FE_Z2]
    call    fe_add

    lea     rcx, [r12 + FE_AA]
    lea     rdx, [r12 + FE_A]
    call    fe_sq

    lea     rcx, [r12 + FE_B]
    lea     rdx, [r12 + FE_X2]
    lea     r8, [r12 + FE_Z2]
    call    fe_sub

    lea     rcx, [r12 + FE_BB]
    lea     rdx, [r12 + FE_B]
    call    fe_sq

    lea     rcx, [r12 + FE_E]
    lea     rdx, [r12 + FE_AA]
    lea     r8, [r12 + FE_BB]
    call    fe_sub

    lea     rcx, [r12 + FE_C]
    lea     rdx, [r12 + FE_X3]
    lea     r8, [r12 + FE_Z3]
    call    fe_add

    lea     rcx, [r12 + FE_D]
    lea     rdx, [r12 + FE_X3]
    lea     r8, [r12 + FE_Z3]
    call    fe_sub

    lea     rcx, [r12 + FE_DA]
    lea     rdx, [r12 + FE_D]
    lea     r8, [r12 + FE_A]
    call    fe_mul

    lea     rcx, [r12 + FE_CB]
    lea     rdx, [r12 + FE_C]
    lea     r8, [r12 + FE_B]
    call    fe_mul

    lea     rcx, [r12 + FE_T0]
    lea     rdx, [r12 + FE_DA]
    lea     r8, [r12 + FE_CB]
    call    fe_add

    lea     rcx, [r12 + FE_X3]
    lea     rdx, [r12 + FE_T0]
    call    fe_sq

    lea     rcx, [r12 + FE_T0]
    lea     rdx, [r12 + FE_DA]
    lea     r8, [r12 + FE_CB]
    call    fe_sub

    lea     rcx, [r12 + FE_T1]
    lea     rdx, [r12 + FE_T0]
    call    fe_sq

    lea     rcx, [r12 + FE_Z3]
    lea     rdx, [r12 + FE_X1]
    lea     r8, [r12 + FE_T1]
    call    fe_mul

    lea     rcx, [r12 + FE_X2]
    lea     rdx, [r12 + FE_AA]
    lea     r8, [r12 + FE_BB]
    call    fe_mul

    lea     rcx, [r12 + FE_T0]
    lea     rdx, [r12 + FE_E]
    call    fe_mul_a24

    lea     rcx, [r12 + FE_T1]
    lea     rdx, [r12 + FE_AA]
    lea     r8, [r12 + FE_T0]
    call    fe_add

    lea     rcx, [r12 + FE_Z2]
    lea     rdx, [r12 + FE_E]
    lea     r8, [r12 + FE_T1]
    call    fe_mul

    dec     r13d
    jns     .ladder

    lea     rcx, [r12 + FE_X2]
    lea     rdx, [r12 + FE_X3]
    mov     r8d, r15d
    call    fe_cswap
    lea     rcx, [r12 + FE_Z2]
    lea     rdx, [r12 + FE_Z3]
    mov     r8d, r15d
    call    fe_cswap

.normalize:
    lea     rcx, [r12 + FE_Z2]
    lea     rdx, [r12 + FE_Z2]
    call    fe_invert

    lea     rcx, [r12 + FE_X2]
    lea     rdx, [r12 + FE_X2]
    lea     r8, [r12 + FE_Z2]
    call    fe_mul

    mov     rcx, rbx
    lea     rdx, [r12 + FE_X2]
    call    fe_tobytes

    xor     eax, eax
    xor     ecx, ecx
.zcheck:
    movzx   edx, byte [rbx + rcx]
    or      eax, edx
    inc     ecx
    cmp     ecx, 32
    jb      .zcheck

    mov     r13d, eax
    test    eax, eax
    jz      .zero_secret
    jmp     .wipe
.zero_secret:
    mov     rcx, rbx
    mov     edx, 32
    call    it_memzero
    mov     r13d, IT_ERR_CRYPTO
.wipe:
    mov     rcx, r12
    mov     edx, WS_SIZE
    call    it_memzero
    mov     eax, r13d
    jmp     .done
.bad:
    mov     eax, IT_ERR_ARGS
.done:
    add     rsp, WS_FRAME
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; ---------------------------------------------------------------------------
; int it_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
; ---------------------------------------------------------------------------
it_x25519:
    jmp     x25519_core

; ---------------------------------------------------------------------------
; int it_x25519_base(uint8_t out[32], const uint8_t scalar[32])
; ---------------------------------------------------------------------------
it_x25519_base:
    lea     r8, [x25519_basepoint]
    jmp     x25519_core
