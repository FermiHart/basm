/* Host-only linker wrappers. Never link this file into the shipped basm. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern FILE *__real_fopen(const char *, const char *);
extern ssize_t __real_write(int, const void *, size_t);
extern int __real_fclose(FILE *);
extern int __real_rename(const char *, const char *);

static const char *fault, *output, *interloper, *cache;
static FILE *output_stream;
static int output_fd = -1;
static unsigned opens, writes, shorts, interrupts, no_space;
static unsigned closes, close_failures, renames, rename_failures, swaps;
static unsigned open_failures, cache_opens, cache_open_failures;
static size_t written;

static void report(void) {
    fprintf(stderr,
            "BASM_PUBLICATION_SPY mode=%s opens=%u writes=%u bytes=%zu"
            " short=%u eintr=%u enospc=%u closes=%u fclose=%u"
            " renames=%u rename=%u interloper=%u fopen=%u"
            " cache_opens=%u cache_fopen=%u\n",
            fault, opens, writes, written, shorts, interrupts, no_space,
            closes, close_failures, renames, rename_failures, swaps,
            open_failures, cache_opens, cache_open_failures);
}

__attribute__((constructor)) static void configure(void) {
    fault = getenv("BASM_TEST_PUBLISH_FAULT");
    if (!fault) return;
    output = getenv("BASM_TEST_PUBLISH_OUTPUT");
    interloper = getenv("BASM_TEST_PUBLISH_INTERLOPER");
    cache = getenv("BASM_TEST_PUBLISH_CACHE");
    if (!output || output[0] != '/' ||
        (strcmp(fault, "none") && strcmp(fault, "short") &&
         strcmp(fault, "eintr") && strcmp(fault, "retry") &&
         strcmp(fault, "enospc") && strcmp(fault, "fclose") &&
         strcmp(fault, "rename") && strcmp(fault, "interloper") &&
         strcmp(fault, "fopen") && strcmp(fault, "escrow-fopen") &&
         strcmp(fault, "escrow-receipt-fopen")) ||
        (!strcmp(fault, "interloper") && !interloper) ||
        ((!strcmp(fault, "escrow-fopen") || !strcmp(fault, "escrow-receipt-fopen")) &&
         (!cache || cache[0]!='/'))) {
        fputs("publication spy: invalid host-test configuration\n", stderr);
        exit(120);
    }
    if (atexit(report) != 0) exit(120);
}

static int output_temp(const char *path) {
    size_t n;
    if (!output) return 0;
    n = strlen(output);
    return !strncmp(path, output, n) && !strncmp(path + n, ".tmp.", 5);
}

static int cache_temp(const char *path) {
    if (!cache) return 0;
    size_t n=strlen(cache);
    return !strncmp(path,cache,n) && path[n]=='/' && strstr(path+n,".tmp.")!=NULL;
}

FILE *__wrap_fopen(const char *path, const char *mode) {
    /* A FILE allocation failure precedes creation. Do not reproduce failure
     * by retaining incbin inputs: snapshots deliberately close those streams. */
    if (fault && mode[0]=='w') {
        if (!strcmp(fault,"fopen") && output_temp(path)) {
            open_failures++; errno=ENOMEM; return NULL;
        }
        if (cache_temp(path) &&
            ((!strcmp(fault,"escrow-fopen") && cache_opens==0) ||
             (!strcmp(fault,"escrow-receipt-fopen") && cache_opens==1))) {
            cache_open_failures++; errno=ENOMEM; return NULL;
        }
    }
    FILE *stream = __real_fopen(path, mode);
    if (stream && mode[0]=='w' && cache_temp(path)) cache_opens++;
    /* Descriptor write failures target only the final object's temp. */
    if (stream && mode[0] == 'w' && output_temp(path)) {
        output_stream = stream;
        output_fd = fileno(stream);
        opens++;
    }
    return stream;
}

ssize_t __wrap_write(int fd, const void *buf, size_t count) {
    size_t request = count;
    ssize_t result;
    if (fd != output_fd || !fault || !count)
        return __real_write(fd, buf, count);
    writes++;
    if ((!strcmp(fault, "eintr") || !strcmp(fault, "retry")) && !interrupts) {
        interrupts++;
        errno = EINTR;
        return -1;
    }
    if (!strcmp(fault, "enospc")) {
        /* Commit a real prefix, then fail persistently, not before writing. */
        if (written >= 97) {
            no_space++;
            errno = ENOSPC;
            return -1;
        }
        if (count > 97 - written) count = 97 - written;
    }
    if ((!strcmp(fault, "short") || !strcmp(fault, "retry")) && count > 17)
        count = 17;
    result = __real_write(fd, buf, count);
    if (result > 0) {
        written += (size_t)result;
        if ((size_t)result < request) shorts++;
    }
    return result;
}

int __wrap_fclose(FILE *stream) {
    int inject = 0;
    if (stream == output_stream) {
        closes++;
        inject = !strcmp(fault, "fclose") && !close_failures;
        output_stream = NULL;
        output_fd = -1;
    }
    int result = __real_fclose(stream);
    /* fclose consumes the stream even when it reports a late I/O failure. */
    if (inject && result == 0) {
        close_failures++;
        errno = EIO;
        return EOF;
    }
    return result;
}

int __wrap_rename(const char *src, const char *dst) {
    int targeted = output && !strcmp(dst, output) && output_temp(src);
    if (targeted) {
        renames++;
        if (!strcmp(fault, "rename")) {
            rename_failures++;
            errno = EACCES;
            return -1;
        }
    }
    int result = __real_rename(src, dst);
    if (targeted && result == 0 && !strcmp(fault, "interloper") && !swaps) {
        /* Force the other publisher's rename after A lands, before basm
         * resumes. No sleeps: the old rel8_publish(out) now reads object B. */
        if (__real_rename(interloper, dst) != 0) {
            perror("publication spy: interloper rename");
            exit(121);
        }
        swaps++;
    }
    return result;
}
