#ifndef IRONTLS_H
#define IRONTLS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes */
#define IT_OK             0
#define IT_NEED_MORE      1
#define IT_DONE           2

#define IT_ERR_ARGS      (-1)
#define IT_ERR_STATE     (-2)
#define IT_ERR_PROTOCOL  (-3)
#define IT_ERR_CRYPTO    (-4)
#define IT_ERR_BUFFER    (-5)
#define IT_ERR_IO        (-6)

/* Roles */
#define IT_ROLE_CLIENT    0
#define IT_ROLE_SERVER    1

/* TLS 1.3 limits used by this implementation */
#define IT_RX_CAP         16384
#define IT_TX_CAP         16384
#define IT_HS_CAP         32768
#define IT_APP_CAP        16384
#define IT_SCRATCH_CAP    16384
#define IT_MAX_PSK        32
#define IT_MAX_IDENTITY   128

typedef struct {
    uint32_t h[8];        /* 0   */
    uint64_t total;       /* 32  */
    uint32_t buf_len;     /* 40  */
    uint32_t pad;         /* 44  */
    uint8_t  buf[64];     /* 48  */
} it_sha256_ctx;          /* 112 */

typedef struct {
    it_sha256_ctx inner;  /* 0   */
    uint8_t opad[64];     /* 112 */
} it_hmac_ctx;            /* 176 */

typedef struct {
    uint8_t  key[16];     /* 0  */
    uint8_t  iv[12];      /* 16 */
    uint32_t pad;         /* 28 */
    uint64_t seq;         /* 32 */
} it_aead_dir;            /* 40 */

typedef struct {
    uint32_t role;          /* 0   */
    uint32_t state;         /* 4   */
    uint32_t err;           /* 8   */
    uint32_t flags;         /* 12  */
    uint32_t psk_len;       /* 16  */
    uint32_t identity_len;  /* 20  */
    uint32_t rx_len;        /* 24  */
    uint32_t tx_len;        /* 28  */
    uint32_t hs_len;        /* 32  */
    uint32_t app_len;       /* 36  */
    uint32_t app_off;       /* 40  */
    uint32_t pad0;          /* 44  */
    uint8_t  psk[IT_MAX_PSK];             /* 48  */
    uint8_t  identity[IT_MAX_IDENTITY];   /* 80  */
    it_sha256_ctx transcript;             /* 208 */
    it_aead_dir c_hs;                     /* 320 */
    it_aead_dir s_hs;                     /* 360 */
    it_aead_dir c_ap;                     /* 400 */
    it_aead_dir s_ap;                     /* 440 */
    uint8_t  early_secret[32];            /* 480 */
    uint8_t  master_secret[32];           /* 512 */
    uint8_t  c_hs_secret[32];             /* 544 */
    uint8_t  s_hs_secret[32];             /* 576 */
    uint8_t  ephem_priv[32];              /* 608 */
    uint8_t  shared[32];                  /* 640 */
    uint8_t  rx[IT_RX_CAP];               /* 672 */
    uint8_t  tx[IT_TX_CAP];               /* 17056 */
    uint8_t  hs[IT_HS_CAP];               /* 33440 */
    uint8_t  app[IT_APP_CAP];             /* 66208 */
    uint8_t  scratch[IT_SCRATCH_CAP];     /* 82592 */
} it_tls_ctx;                             /* 98976 */

/* Memory utilities */
void  *it_memcpy(void *dst, const void *src, size_t len);
void  *it_memset(void *dst, int value, size_t len);
void  *it_memzero(void *dst, size_t len);
int    it_ct_eq(const void *a, const void *b, size_t len);

/* SHA-256 */
void it_sha256_init(it_sha256_ctx *ctx);
void it_sha256_update(it_sha256_ctx *ctx, const void *data, size_t len);
void it_sha256_final(it_sha256_ctx *ctx, uint8_t out[32]);
void it_sha256(const void *data, size_t len, uint8_t out[32]);

/* HMAC-SHA256 */
void it_hmac_init(it_hmac_ctx *ctx, const void *key, size_t key_len);
void it_hmac_update(it_hmac_ctx *ctx, const void *data, size_t len);
void it_hmac_final(it_hmac_ctx *ctx, uint8_t out[32]);

/* HKDF */
void it_hkdf_extract(const void *salt, size_t salt_len,
                     const void *ikm, size_t ikm_len, uint8_t out[32]);
int  it_hkdf_expand(const void *prk, size_t prk_len,
                    const void *info, size_t info_len,
                    uint8_t *out, size_t out_len);
int  it_hkdf_expand_label(const void *secret, const char *label, size_t label_len,
                          const void *context, size_t context_len,
                          uint8_t *out, size_t out_len);

/* X25519 (curve25519 ECDH) */
int it_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
int it_x25519_base(uint8_t out[32], const uint8_t scalar[32]);

/* AES-128-GCM */
int it_aes128gcm_seal(const uint8_t key[16], const uint8_t nonce[12],
                      const void *aad, size_t aad_len,
                      const void *plaintext, size_t plaintext_len,
                      uint8_t *out, uint8_t tag[16]);
int it_aes128gcm_open(const uint8_t key[16], const uint8_t nonce[12],
                      const void *aad, size_t aad_len,
                      const void *ciphertext, size_t ciphertext_len,
                      uint8_t *out, const uint8_t tag[16]);

/* TLS 1.3 PSK engine */
int it_tls_init(it_tls_ctx *ctx, int role,
                const void *psk, size_t psk_len,
                const void *identity, size_t identity_len);
int it_tls_feed(it_tls_ctx *ctx, const void *data, size_t len);
int it_tls_drain(it_tls_ctx *ctx, void *out, size_t cap);
int it_tls_step(it_tls_ctx *ctx);
int it_tls_handshake_done(const it_tls_ctx *ctx);
int it_tls_write(it_tls_ctx *ctx, const void *data, size_t len);
int it_tls_read(it_tls_ctx *ctx, void *out, size_t cap);
void it_tls_clear(it_tls_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif
