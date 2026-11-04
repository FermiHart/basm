/* Host-only real caller: the checker does not prove this functional property. */
#include <stdint.h>
#include <stdio.h>

extern uint64_t bb_max_u64(uint64_t a, uint64_t b);
extern uint64_t bb_abi_probe(uint64_t a, uint64_t b, uint64_t *saved_rbx);

int main(void) {
    static const uint64_t values[] = {
        0, 1, 2, UINT64_C(0x7fffffffffffffff), UINT64_C(0x8000000000000000),
        UINT64_C(0xffffffff), UINT64_C(0x100000000), UINT64_MAX - 1, UINT64_MAX
    };
    uint64_t seed = UINT64_C(0x8e632da903bb49c1);
    unsigned checks = 0;
    for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        for (unsigned j = 0; j < sizeof(values) / sizeof(values[0]); ++j) {
            uint64_t a = values[i], b = values[j], preserved = 0;
            if (bb_max_u64(a, b) != (a >= b ? a : b)) return 1;
            if (bb_abi_probe(a, b, &preserved) != (a >= b ? a : b)) return 2;
            if (preserved != UINT64_C(0x13579bdf2468ace0)) return 3;
            checks += 3;
        }
    }
    for (unsigned i = 0; i < 10000; ++i) {
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        uint64_t a = seed;
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        uint64_t b = seed;
        if (bb_max_u64(a, b) != (a >= b ? a : b)) return 4;
        ++checks;
    }
    printf("PASS contract consumer: %u functional/ABI observations\n", checks);
    return 0;
}
