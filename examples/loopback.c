#include "irontls.h"
#include <stdio.h>
#include <string.h>

static unsigned char wire[65536];

static int push(it_tls_ctx *from, it_tls_ctx *to)
{
    int n = it_tls_drain(from, wire, sizeof(wire));
    if (n < 0) {
        printf("drain failed: %d\n", n);
        return n;
    }
    if (n > 0 && it_tls_feed(to, wire, (size_t)n) < 0) {
        printf("feed failed\n");
        return -1;
    }
    return n;
}

static int run_handshake(it_tls_ctx *c, it_tls_ctx *s)
{
    int i, rc;

    for (i = 0; i < 64; i++) {
        if (it_tls_handshake_done(c) && it_tls_handshake_done(s))
            return 0;
        rc = it_tls_step(c);
        if (rc < 0) {
            printf("client step failed: %d\n", rc);
            return rc;
        }
        push(c, s);
        rc = it_tls_step(s);
        if (rc < 0) {
            printf("server step failed: %d\n", rc);
            return rc;
        }
        push(s, c);
    }
    printf("handshake did not finish\n");
    return -1;
}

static void exchange(it_tls_ctx *from, it_tls_ctx *to, const char *msg, const char *who)
{
    unsigned char buf[256];
    int n;

    if (it_tls_write(from, msg, strlen(msg)) < 0) {
        printf("%s write failed\n", who);
        return;
    }
    push(from, to);
    it_tls_step(to);
    n = it_tls_read(to, buf, sizeof(buf) - 1);
    if (n < 0) {
        printf("%s read failed: %d\n", who, n);
        return;
    }
    buf[n] = 0;
    printf("%-6s sent \"%s\", peer got \"%s\"\n", who, msg, buf);
}

int main(void)
{
    static it_tls_ctx client, server;
    const char psk[] = "example pre-shared key";
    const char identity[] = "irontls-example";

    if (it_tls_init(&client, IT_ROLE_CLIENT, psk, sizeof(psk) - 1,
                    identity, sizeof(identity) - 1) < 0 ||
        it_tls_init(&server, IT_ROLE_SERVER, psk, sizeof(psk) - 1,
                    identity, sizeof(identity) - 1) < 0) {
        printf("init failed\n");
        return 1;
    }

    if (run_handshake(&client, &server) < 0)
        return 1;

    printf("handshake complete: TLS 1.3 PSK, AES-128-GCM-SHA256\n");
    exchange(&client, &server, "ping from client", "client");
    exchange(&server, &client, "pong from server", "server");

    return 0;
}
