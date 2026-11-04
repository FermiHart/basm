/* INV-579/INV-583: exercise the shipping POSIX wrappers, not wrapper doubles. */
#include <stddef.h>
#include "posix/include/errno.h"

int printf(const char *format, ...);
long bear_read(int fd, void *buf, size_t n);
long bear_write(int fd, const void *buf, size_t n);
long read(int fd, void *buf, size_t n);

static const long *results;
static int result_count, calls, failures, expected_nr;
static void *expected_buf;
static size_t expected_n;

long
bear_osif_syscall6(long nr, long fd, long buf, long n,
                   long a4, long a5, long a6)
{
    if (nr != expected_nr || fd != 17 || buf != (long)expected_buf ||
        n != (long)expected_n || a4 || a5 || a6) {
        printf("FAIL raw syscall arguments at call %d\n", calls);
        failures++;
    }
    calls++;
    if (calls > result_count) {
        printf("FAIL unexpected raw syscall %d\n", calls);
        failures++;
        return -EIO;
    }
    /* Deliberately do not set errno: Linux returns the error in the register. */
    return results[calls - 1];
}

static long
invoke(int op, void *buf, size_t n)
{
    if (op == 0) return bear_read(17, buf, n);
    if (op == 1) return bear_write(17, buf, n);
    return read(17, buf, n);
}

int
main(void)
{
    static const long values[] = {-EINTR, -ENOSPC, -1, -4095, -4096, 0, 2, 8};
    static const long retry[] = {-EINTR, -EINTR, 2, -EINTR, 3, 0};
    static const long stop[] = {-EINTR, -EINTR, -ENOSPC};
    static char buf[8];

    /* The literal read symbol is shipped for memstream.c, in addition to bear_*. */
    for (int op = 0; op < 3; op++) {
        expected_nr = op == 1 ? 1 : 0;
        expected_buf = buf;
        expected_n = sizeof buf;
        for (int i = 0; i < 8; i++) {
            long raw = values[i];
            int is_error = raw < 0 && raw >= -4095;
            results = &values[i];
            result_count = 1;
            calls = 0;
            errno = EDOM;
            long r = invoke(op, buf, sizeof buf);
            if (r != (is_error ? -1 : raw) ||
                errno != (is_error ? (int)-raw : EDOM) || calls != 1) {
                printf("FAIL op=%d raw=%ld: result=%ld errno=%d calls=%d\n",
                       op, raw, r, errno, calls);
                failures++;
            }
        }

        /* Consumer-style retries, including short progress between interrupts. */
        for (int terminal_error = 0; terminal_error < 2; terminal_error++) {
            size_t done = 0;
            long r = -1;
            results = terminal_error ? stop : retry;
            result_count = terminal_error ? 3 : 6;
            calls = 0;
            errno = EDOM;
            for (int attempt = 0; attempt < 8; attempt++) {
                expected_buf = buf + done;
                expected_n = sizeof buf - done;
                r = invoke(op, buf + done, sizeof buf - done);
                if (r < 0 && errno == EINTR) continue;
                if (r <= 0) break;
                if ((size_t)r > sizeof buf - done) {
                    failures++;
                    break;
                }
                done += (size_t)r;
            }
            if (r != (terminal_error ? -1 : 0) ||
                errno != (terminal_error ? ENOSPC : EINTR) ||
                done != (terminal_error ? 0u : 5u) || calls != result_count) {
                printf("FAIL retry op=%d terminal_error=%d: result=%ld errno=%d"
                       " bytes=%lu calls=%d\n", op, terminal_error, r, errno,
                       (unsigned long)done, calls);
                failures++;
            }
        }
    }
    if (!failures) printf("runtime-io: 24 result cases + 6 retry loops PASS\n");
    return failures != 0;
}
