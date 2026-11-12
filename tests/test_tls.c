#include "irontls.h"
#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond, name) do { \
    if (!(cond)) { printf("FAIL %s\n", name); failures++; } \
    else printf("ok   %s\n", name); \
} while (0)

static int pump(it_tls_ctx *src, it_tls_ctx *dst, unsigned char *buf, size_t cap)
{
    int n = it_tls_drain(src, buf, cap);
    if (n < 0) return n;
    return it_tls_feed(dst, buf, (size_t)n);
}

static void handshake(it_tls_ctx *c, it_tls_ctx *s, const void *psk, size_t psk_len,
                      const void *id, size_t id_len, int *ok)
{
    unsigned char buf[65536];
    int rc;

    memset(c, 0, sizeof(*c));
    memset(s, 0, sizeof(*s));
    *ok = 0;
    if (it_tls_init(c, IT_ROLE_CLIENT, psk, psk_len, id, id_len) != 0) return;
    if (it_tls_init(s, IT_ROLE_SERVER, psk, psk_len, id, id_len) != 0) return;

    rc = it_tls_step(c);
    if (rc < 0) return;
    if (pump(c, s, buf, sizeof(buf)) < 0) return;
    rc = it_tls_step(s);
    if (rc < 0) return;
    if (pump(s, c, buf, sizeof(buf)) < 0) return;
    rc = it_tls_step(c);
    if (rc < 0) return;
    if (pump(c, s, buf, sizeof(buf)) < 0) return;
    rc = it_tls_step(s);
    if (rc < 0) return;
    *ok = it_tls_handshake_done(c) && it_tls_handshake_done(s);
}

static void test_handshake(void)
{
    static it_tls_ctx c, s;
    const unsigned char psk[32] = { 1, 2, 3, 4 };
    const char id[] = "irontls-test";
    unsigned char buf[65536], out[256];
    int ok, rc, n;

    handshake(&c, &s, psk, sizeof(psk), id, sizeof(id) - 1, &ok);
    CHECK(ok, "psk handshake");

    rc = it_tls_write(&c, "hello", 5);
    CHECK(rc == 0, "client write");
    n = it_tls_drain(&c, buf, sizeof(buf));
    CHECK(n > 0 && it_tls_feed(&s, buf, (size_t)n) == 0, "client record");
    rc = it_tls_step(&s);
    CHECK(rc == IT_DONE, "server step app data");
    n = it_tls_read(&s, out, sizeof(out));
    CHECK(n == 5 && memcmp(out, "hello", 5) == 0, "server read");

    rc = it_tls_write(&s, "world!", 6);
    CHECK(rc == 0, "server write");
    n = it_tls_drain(&s, buf, sizeof(buf));
    CHECK(n > 0 && it_tls_feed(&c, buf, (size_t)n) == 0, "server record");
    rc = it_tls_step(&c);
    CHECK(rc == IT_DONE, "client step app data");
    n = it_tls_read(&c, out, sizeof(out));
    CHECK(n == 6 && memcmp(out, "world!", 6) == 0, "client read");

    rc = it_tls_write(&c, "second", 6);
    CHECK(rc == 0, "second write");
    n = it_tls_drain(&c, buf, sizeof(buf));
    CHECK(n > 0 && it_tls_feed(&s, buf, (size_t)n) == 0, "second record");
    it_tls_step(&s);
    n = it_tls_read(&s, out, sizeof(out));
    CHECK(n == 6 && memcmp(out, "second", 6) == 0, "second read");

    it_tls_clear(&c);
    it_tls_clear(&s);
}

static void test_tamper(void)
{
    static it_tls_ctx c, s;
    const unsigned char psk[32] = { 9, 8, 7, 6 };
    const char id[] = "tamper-id";
    unsigned char buf[65536];
    int ok, rc, n;

    handshake(&c, &s, psk, sizeof(psk), id, sizeof(id) - 1, &ok);
    CHECK(ok, "tamper handshake");
    if (!ok) return;
    it_tls_write(&c, "secret", 6);
    n = it_tls_drain(&c, buf, sizeof(buf));
    CHECK(n > 20, "tamper record drained");
    buf[n - 1] ^= 1;
    it_tls_feed(&s, buf, (size_t)n);
    rc = it_tls_step(&s);
    CHECK(rc < 0, "tampered record rejected");
    it_tls_clear(&c);
    it_tls_clear(&s);
}

static void test_bad_binder(void)
{
    static it_tls_ctx c, s;
    const unsigned char psk1[32] = { 1 };
    const unsigned char psk2[32] = { 2 };
    const char id[] = "binder-id";
    unsigned char buf[65536];
    int rc, n;

    memset(&c, 0, sizeof(c));
    memset(&s, 0, sizeof(s));
    it_tls_init(&c, IT_ROLE_CLIENT, psk1, sizeof(psk1), id, sizeof(id) - 1);
    it_tls_init(&s, IT_ROLE_SERVER, psk2, sizeof(psk2), id, sizeof(id) - 1);
    it_tls_step(&c);
    n = it_tls_drain(&c, buf, sizeof(buf));
    it_tls_feed(&s, buf, (size_t)n);
    rc = it_tls_step(&s);
    CHECK(rc == IT_ERR_PROTOCOL, "bad binder rejected");
    it_tls_clear(&c);
    it_tls_clear(&s);
}

static void test_partial(void)
{
    static it_tls_ctx c, s;
    const unsigned char psk[32] = { 5 };
    const char id[] = "partial-id";
    unsigned char buf[65536];
    int rc, n;

    memset(&c, 0, sizeof(c));
    memset(&s, 0, sizeof(s));
    it_tls_init(&c, IT_ROLE_CLIENT, psk, sizeof(psk), id, sizeof(id) - 1);
    it_tls_init(&s, IT_ROLE_SERVER, psk, sizeof(psk), id, sizeof(id) - 1);
    it_tls_step(&c);
    n = it_tls_drain(&c, buf, sizeof(buf));
    CHECK(n > 10, "partial ch drained");
    it_tls_feed(&s, buf, 3);
    rc = it_tls_step(&s);
    CHECK(rc == IT_NEED_MORE, "partial record needs more");
    it_tls_feed(&s, buf + 3, (size_t)n - 3);
    rc = it_tls_step(&s);
    CHECK(rc == IT_OK, "partial record completed");
    it_tls_clear(&c);
    it_tls_clear(&s);
}

static void test_partial_drain(void)
{
    static it_tls_ctx c, s;
    const unsigned char psk[32] = { 6 };
    const char id[] = "drain-id";
    static unsigned char wire[256];
    unsigned char out[64];
    int ok, rc, n = 0, got = 0;

    handshake(&c, &s, psk, sizeof(psk), id, sizeof(id) - 1, &ok);
    CHECK(ok, "drain handshake");
    if (!ok) return;
    CHECK(it_tls_write(&c, "split record", 12) == 0, "drain write");
    n = it_tls_drain(&c, wire, 10);
    CHECK(n == 10, "drain partial");
    CHECK(it_tls_feed(&s, wire, (size_t)n) == 0, "drain partial feed");
    rc = it_tls_step(&s);
    CHECK(rc == IT_DONE, "drain partial step");
    n = it_tls_drain(&c, wire + 10, sizeof(wire) - 10);
    CHECK(n > 0, "drain rest");
    CHECK(it_tls_feed(&s, wire + 10, (size_t)n) == 0, "drain rest feed");
    rc = it_tls_step(&s);
    CHECK(rc == IT_DONE, "drain rest step");
    while ((n = it_tls_read(&s, out + got, sizeof(out) - (size_t)got)) > 0)
        got += n;
    CHECK(got == 12 && memcmp(out, "split record", 12) == 0, "drain rest read");
    it_tls_clear(&c);
    it_tls_clear(&s);
}

static void test_large(void)
{
    static it_tls_ctx c, s;
    const unsigned char psk[32] = { 7 };
    const char id[] = "large-id";
    static unsigned char data[16000], out[20000], wire[65536];
    unsigned char tail[8];
    int ok, rc, n, total;
    size_t i;

    handshake(&c, &s, psk, sizeof(psk), id, sizeof(id) - 1, &ok);
    CHECK(ok, "large handshake");
    if (!ok) return;
    for (i = 0; i < sizeof(data); i++)
        data[i] = (unsigned char)(i * 7u);
    CHECK(it_tls_write(&c, data, sizeof(data)) == 0, "large write");
    n = it_tls_drain(&c, wire, sizeof(wire));
    CHECK(n == 16022, "large record size");
    CHECK(it_tls_feed(&s, wire, (size_t)n) == 0, "large feed");
    rc = it_tls_step(&s);
    CHECK(rc == IT_DONE, "large step");
    n = it_tls_read(&s, out, 7000);
    CHECK(n == 7000, "large read part");
    total = n;

    CHECK(it_tls_write(&c, "tail", 4) == 0, "tail write");
    n = it_tls_drain(&c, wire, sizeof(wire));
    CHECK(n > 0 && it_tls_feed(&s, wire, (size_t)n) == 0, "tail feed");
    rc = it_tls_step(&s);
    CHECK(rc == IT_DONE, "tail step");

    while ((n = it_tls_read(&s, out + total, sizeof(out) - (size_t)total)) > 0)
        total += n;
    CHECK(total == 16004, "large read total");
    CHECK(memcmp(out, data, sizeof(data)) == 0, "large data intact");
    CHECK(memcmp(out + sizeof(data), "tail", 4) == 0, "large tail intact");

    CHECK(it_tls_read(&s, tail, sizeof(tail)) == 0, "large drained empty");
    it_tls_clear(&c);
    it_tls_clear(&s);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_handshake();
    test_tamper();
    test_bad_binder();
    test_partial();
    test_partial_drain();
    test_large();
    if (failures) {
        printf("\n%d FAILURE(S)\n", failures);
        return 1;
    }
    printf("\nall tls tests passed\n");
    return 0;
}
