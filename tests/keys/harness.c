/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Runs the real key-load handler on the host so tools/p25_keyload.py can be checked
 * against it. stdin, one command per line:
 *   req <hex>     handle a request; prints "<class> <body hex>"
 *   flags <n>     set the flags byte reported to the handler (default FLASH_OK|PERSISTED|NONCE_READY)
 *   blob          prints the serialized store as hex (the flash image)
 *   load <hex>    parse a 256-byte image into the store; prints the parse result
 */
#include "keyload.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    while (*s && *s != '\n' && *s != '\r') {
        int hi = hexval(s[0]), lo = hi < 0 ? -1 : hexval(s[1]);
        if (hi < 0 || lo < 0 || n >= cap) return -1;
        out[n++] = (uint8_t)(hi << 4 | lo);
        s += 2;
    }
    return (int)n;
}

int main(void)
{
    p25_keystore ks;
    uint8_t flags = P25_KL_F_FLASH_OK | P25_KL_F_PERSISTED | P25_KL_F_NONCE_READY;
    char line[1024];
    p25_ks_init(&ks);
    while (fgets(line, sizeof line, stdin)) {
        uint8_t buf[P25_KS_BLOB_BYTES + 8];
        if (!strncmp(line, "req ", 4)) {
            uint8_t body[64];
            size_t bl, i;
            int changed, n = parse_hex(line + 4, buf, sizeof buf);
            int cls = n < 0 ? -1 : p25_keyload_handle(&ks, flags, buf, (size_t)n, body, sizeof body, &bl, &changed);
            printf("%d ", cls);
            if (cls >= 0) for (i = 0; i < bl; ++i) printf("%02x", body[i]);
            printf("\n");
        } else if (!strncmp(line, "flags ", 6)) {
            flags = (uint8_t)atoi(line + 6);
            printf("ok\n");
        } else if (!strncmp(line, "blob", 4)) {
            unsigned i;
            p25_ks_serialize(&ks, buf);
            for (i = 0; i < P25_KS_BLOB_BYTES; ++i) printf("%02x", buf[i]);
            printf("\n");
        } else if (!strncmp(line, "load ", 5)) {
            int n = parse_hex(line + 5, buf, sizeof buf);
            printf("%d\n", n == P25_KS_BLOB_BYTES ? p25_ks_parse(&ks, buf) : -2);
        }
        fflush(stdout);
    }
    return 0;
}
