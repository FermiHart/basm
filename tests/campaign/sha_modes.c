/* W01: independently exercise forced scalar and actual runtime SHA dispatch.
 * The older test_sha.c leaves FORCE_SOFTWARE set for both namespaces. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef SHA256NI_FORCE_SOFTWARE
#define SHA256NI_FORCE_SOFTWARE 1
#define SHA256NI_CTX_TYPE scalar_ctx
#define SHA256NI_PREFIX scalar_
#include "sha256_ni.h"
#ifdef SHA256NI_X86
#error forced software must not compile x86 implementation
#endif

#undef SHA256_NI_H
#undef SHA256NI_FORCE_SOFTWARE
#undef SHA256NI_CTX_TYPE
#undef SHA256NI_PREFIX
#define SHA256NI_FORCE_SOFTWARE 0
#define SHA256NI_CTX_TYPE dispatch_ctx
#define SHA256NI_PREFIX dispatch_
#include "sha256_ni.h"

static void hex(const uint8_t value[32], char output[65]) {
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        output[2*i] = digits[value[i] >> 4];
        output[2*i+1] = digits[value[i] & 15];
    }
    output[64] = 0;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    char *end = NULL;
    unsigned long chunk = strtoul(argv[2], &end, 10);
    if (!end || *end || !chunk || chunk > 65536) return 2;
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 2;
    scalar_ctx scalar; dispatch_ctx dispatch;
    scalar_init(&scalar); dispatch_init(&dispatch);
    unsigned char buffer[65536];
    for (;;) {
        size_t n = fread(buffer, 1, (size_t)chunk, file);
        scalar_update(&scalar, buffer, n);
        dispatch_update(&dispatch, buffer, n);
        if (n < chunk) break;
    }
    if (ferror(file) || fclose(file)) return 2;
    uint8_t a[32], b[32]; char ah[65], bh[65];
    scalar_final(&scalar, a); dispatch_final(&dispatch, b);
    hex(a, ah); hex(b, bh);
    int selected = 0;
#ifdef SHA256NI_X86
    selected = dispatch_has_sha_ni;
    if (selected != dispatch_check_sha_ni()) return 3;
#endif
    printf("{\"software\":\"%s\",\"dispatch\":\"%s\",\"sha_ni_selected\":%s}\n",
           ah, bh, selected ? "true" : "false");
    return memcmp(a, b, sizeof(a)) ? 1 : 0;
}
