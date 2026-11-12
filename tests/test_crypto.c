#include "../include/irontls.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures = 0;

static void hex2bin(const char *hex, uint8_t *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) { v = 0; }
        out[i] = (uint8_t)v;
    }
}

static void check(const char *name, const uint8_t *got, const uint8_t *want, size_t len)
{
    if (memcmp(got, want, len) != 0) {
        printf("FAIL %s\n  got: ", name);
        for (size_t i = 0; i < len; i++) printf("%02x", got[i]);
        printf("\n  want: ");
        for (size_t i = 0; i < len; i++) printf("%02x", want[i]);
        printf("\n");
        failures++;
    } else {
        printf("ok   %s\n", name);
    }
}

static void test_sha256(void)
{
    uint8_t out[32], want[32];
    const char *abc = "abc";
    const char *fox = "The quick brown fox jumps over the lazy dog";

    it_sha256("", 0, out);
    hex2bin("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", want, 32);
    check("sha256(empty)", out, want, 32);

    it_sha256(abc, strlen(abc), out);
    hex2bin("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", want, 32);
    check("sha256(abc)", out, want, 32);

    it_sha256(fox, strlen(fox), out);
    hex2bin("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", want, 32);
    check("sha256(fox)", out, want, 32);

    it_sha256_ctx ctx;
    uint8_t chunk[1000];
    memset(chunk, 'a', sizeof(chunk));
    it_sha256_init(&ctx);
    for (int i = 0; i < 1000; i++) it_sha256_update(&ctx, chunk, sizeof(chunk));
    it_sha256_final(&ctx, out);
    hex2bin("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", want, 32);
    check("sha256(million a)", out, want, 32);

    it_sha256_init(&ctx);
    it_sha256_update(&ctx, "a", 1);
    it_sha256_update(&ctx, "b", 1);
    it_sha256_update(&ctx, "c", 1);
    it_sha256_final(&ctx, out);
    hex2bin("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", want, 32);
    check("sha256(incremental abc)", out, want, 32);
}

static void test_hmac(void)
{
    uint8_t key[200], data[200], out[32], want[32];

    memset(key, 0x0b, 20);
    it_hmac_ctx ctx;
    it_hmac_init(&ctx, key, 20);
    it_hmac_update(&ctx, "Hi There", 8);
    it_hmac_final(&ctx, out);
    hex2bin("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", want, 32);
    check("hmac rfc4231 case1", out, want, 32);

    it_hmac_init(&ctx, "Jefe", 4);
    it_hmac_update(&ctx, "what do ya want for nothing?", 28);
    it_hmac_final(&ctx, out);
    hex2bin("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", want, 32);
    check("hmac rfc4231 case2", out, want, 32);

    memset(key, 0xaa, 20);
    memset(data, 0xdd, 50);
    it_hmac_init(&ctx, key, 20);
    it_hmac_update(&ctx, data, 50);
    it_hmac_final(&ctx, out);
    hex2bin("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", want, 32);
    check("hmac rfc4231 case3", out, want, 32);

    memset(key, 0xaa, 131);
    it_hmac_init(&ctx, key, 131);
    it_hmac_update(&ctx, "Test Using Larger Than Block-Size Key - Hash Key First", 54);
    it_hmac_final(&ctx, out);
    hex2bin("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", want, 32);
    check("hmac rfc4231 case6", out, want, 32);
}

static void test_hkdf(void)
{
    uint8_t ikm[22], salt[13], info[10], prk[32], out[42], want[42];

    memset(ikm, 0x0b, sizeof(ikm));
    hex2bin("000102030405060708090a0b0c", salt, sizeof(salt));
    hex2bin("f0f1f2f3f4f5f6f7f8f9", info, sizeof(info));

    it_hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk);
    hex2bin("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", want, 32);
    check("hkdf extract rfc5869 case1", prk, want, 32);

    it_hkdf_expand(prk, 32, info, sizeof(info), out, sizeof(out));
    hex2bin("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", want, 42);
    check("hkdf expand rfc5869 case1", out, want, 42);

    uint8_t secret[32];
    for (int i = 0; i < 32; i++) secret[i] = (uint8_t)(i + 1);
    uint8_t ctx4[4];
    hex2bin("aabbccdd", ctx4, 4);
    it_hkdf_expand_label(secret, "test", 4, ctx4, 4, out, sizeof(out));
    hex2bin("bb960f9021d143cba550b7442b5fe4d05460afd3e5b7e2fcd913fa54ec517f6a2e9a3164cd2dd2c854f5", want, 42);
    check("hkdf expand label", out, want, 42);
}

static void test_aes_gcm(void)
{
    uint8_t key[16], nonce[12], out[80], tag[16], want[80], want_tag[16], aad[20];
    int rc;

    memset(key, 0, sizeof(key));
    memset(nonce, 0, sizeof(nonce));
    rc = it_aes128gcm_seal(key, nonce, NULL, 0, NULL, 0, NULL, tag);
    hex2bin("58e2fccefa7e3061367f1d57a4e7455a", want_tag, 16);
    if (rc != 0) { printf("FAIL gcm empty rc=%d\n", rc); failures++; }
    else check("gcm empty tag", tag, want_tag, 16);

    uint8_t pt16[16] = {0};
    rc = it_aes128gcm_seal(key, nonce, NULL, 0, pt16, 16, out, tag);
    hex2bin("0388dace60b6a392f328c2b971b2fe78", want, 16);
    hex2bin("ab6e47d42cec13bdf53a67b21257bddf", want_tag, 16);
    if (rc != 0) { printf("FAIL gcm one block rc=%d\n", rc); failures++; }
    else {
        check("gcm one block ct", out, want, 16);
        check("gcm one block tag", tag, want_tag, 16);
    }

    hex2bin("feffe9928665731c6d6a8f9467308308", key, 16);
    hex2bin("cafebabefacedbaddecaf888", nonce, 12);
    uint8_t pt[64];
    hex2bin("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", pt, 60);
    hex2bin("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad, 20);
    rc = it_aes128gcm_seal(key, nonce, aad, 20, pt, 60, out, tag);
    hex2bin("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", want, 60);
    hex2bin("5bc94fbc3221a5db94fae95ae7121a47", want_tag, 16);
    if (rc != 0) { printf("FAIL gcm multi rc=%d\n", rc); failures++; }
    else {
        check("gcm multi ct", out, want, 60);
        check("gcm multi tag", tag, want_tag, 16);
    }

    uint8_t dec[64];
    rc = it_aes128gcm_open(key, nonce, aad, 20, out, 60, dec, tag);
    if (rc != 0) { printf("FAIL gcm open rc=%d\n", rc); failures++; }
    else check("gcm open roundtrip", dec, pt, 60);

    tag[0] ^= 1;
    rc = it_aes128gcm_open(key, nonce, aad, 20, out, 60, dec, tag);
    if (rc == 0) { printf("FAIL gcm tamper accepted\n"); failures++; }
    else printf("ok   gcm tamper rejected\n");
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_sha256();
    test_hmac();
    test_hkdf();
    test_aes_gcm();
    if (failures) {
        printf("\n%d FAILURE(S)\n", failures);
        return 1;
    }
    printf("\nall crypto tests passed\n");
    return 0;
}
