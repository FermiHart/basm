/* Host-only native measurement launcher. It never executes assembled objects.
 * A small native parent avoids inheriting a Python interpreter's RSS high-water
 * mark in the measured child before exec. wait4 still includes the small launch
 * interval: this is process peak RSS, not a sampled post-exec-only measurement. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t child_pid;
static volatile sig_atomic_t timed_out;

static void expire(int signo) {
    (void)signo;
    timed_out = 1;
    if (child_pid > 0) {
        kill(-(pid_t)child_pid, SIGKILL);
        kill((pid_t)child_pid, SIGKILL);
    }
}

static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
        perror("clock_gettime"); exit(2);
    }
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: measure_process STDOUT STDERR TIMEOUT_SECONDS -- COMMAND [ARGS...]\n");
        return 2;
    }
    char *end = NULL;
    long timeout = strtol(argv[3], &end, 10);
    if (!end || *end || timeout < 1 || timeout > 30 ||
        argv[4][0] != '-' || argv[4][1] != '-' || argv[4][2]) return 2;
    int out = open(argv[1], O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (out < 0) { perror("stdout"); return 2; }
    int err = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (err < 0) { perror("stderr"); close(out); return 2; }
    struct sigaction sa = {0};
    sa.sa_handler = expire;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL)) { perror("sigaction"); return 2; }
    uint64_t begin = now_ns();
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 2; }
    if (!pid) {
        struct rlimit file_limit = {UINT64_C(67108864), UINT64_C(67108864)};
        struct rlimit core_limit = {0, 0};
        if (setpgid(0, 0) || setrlimit(RLIMIT_FSIZE, &file_limit) ||
            setrlimit(RLIMIT_CORE, &core_limit) || dup2(out, STDOUT_FILENO) < 0 ||
            dup2(err, STDERR_FILENO) < 0) _exit(126);
        close(out); close(err);
        execv(argv[5], argv + 5);
        _exit(127);
    }
    child_pid = (sig_atomic_t)pid;
    close(out); close(err);
    if (setpgid(pid, pid) && errno != EACCES && errno != ESRCH) {
        kill(pid, SIGKILL);
        perror("setpgid");
    }
    alarm((unsigned int)timeout);
    int status = 0;
    struct rusage usage = {0};
    pid_t waited;
    do { waited = wait4(pid, &status, 0, &usage); } while (waited < 0 && errno == EINTR);
    uint64_t elapsed = now_ns() - begin;
    alarm(0);
    child_pid = 0;
    if (waited != pid) { perror("wait4"); return 2; }
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
    long long rss_kib = (long long)usage.ru_maxrss;
#ifdef __APPLE__
    rss_kib = (rss_kib + 1023) / 1024;
#endif
    printf("{\"returncode\":%d,\"timed_out\":%s,\"wall_ns\":%llu,"
           "\"user_us\":%llu,\"system_us\":%llu,\"peak_rss_kib\":%lld,"
           "\"minor_faults\":%ld,\"major_faults\":%ld,"
           "\"voluntary_switches\":%ld,\"involuntary_switches\":%ld}\n",
           exit_code, timed_out ? "true" : "false", (unsigned long long)elapsed,
           (unsigned long long)usage.ru_utime.tv_sec * 1000000ULL + usage.ru_utime.tv_usec,
           (unsigned long long)usage.ru_stime.tv_sec * 1000000ULL + usage.ru_stime.tv_usec,
           rss_kib, usage.ru_minflt, usage.ru_majflt, usage.ru_nvcsw, usage.ru_nivcsw);
    return 0;
}
