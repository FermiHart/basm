/* Host test helper: verify one SHA-256 digest signature with bundled diagnostic
 * crypto. Object parsing, tool/source/section hashes are independently checked
 * in Python; this helper is not a proof of the crypto implementation itself. */
#include "bear_ed25519.h"
#include <stdint.h>
#include <string.h>

static int unhex(const char *text, uint8_t *out, size_t count) {
    if (strlen(text) != count * 2) return -1;
    for (size_t i = 0; i < count; i++) {
        unsigned byte = 0;
        for (int j = 0; j < 2; j++) {
            unsigned char c = (unsigned char)text[2*i+(size_t)j];
            unsigned n;
            if (c >= '0' && c <= '9') n = c-'0';
            else if (c >= 'a' && c <= 'f') n = c-'a'+10;
            else return -1;
            byte = (byte << 4) | n;
        }
        out[i] = (uint8_t)byte;
    }
    return 0;
}

int main(int argc, char **argv) {
    uint8_t pub[32], digest[32], signature[64];
    if (argc != 4 || unhex(argv[1], pub, sizeof(pub)) ||
        unhex(argv[2], digest, sizeof(digest)) || unhex(argv[3], signature, sizeof(signature))) return 2;
    return ed25519_verify(signature, digest, sizeof(digest), pub) ? 1 : 0;
}
