/* Exercise the canonical ELF implementation without a replacement crypto
 * implementation. --gc-sections discards only unused attestation commands. */
#define main elftool_original_main
#include "../../elftool.c"
#undef main

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    int rc = 0;
    if (!strcmp(argv[1], "diff")) {
        if (argc != 4) return 2;
        rc = cmd_diff(argv[2], argv[3]);
    } else if (!strcmp(argv[1], "digest")) {
        rc = cmd_digest(argv[2]);
    } else {
        load(argv[2]);
        if (!strcmp(argv[1], "audit")) rc = cmd_audit();
        else if (!strcmp(argv[1], "notes")) rc = cmd_notes();
        else if (!strcmp(argv[1], "secs")) cmd_secs();
        else if (!strcmp(argv[1], "syms")) cmd_syms();
        else if (!strcmp(argv[1], "relocs")) cmd_relocs();
        else if (!strcmp(argv[1], "sec") && argc == 4) cmd_sec(argv[3]);
        else rc = 2;
    }
    free(g_secs); g_secs = NULL;
    free(g_buf); g_buf = NULL;
    return rc;
}
