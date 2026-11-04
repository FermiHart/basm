/*
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* INV-596: bounded, opt-in source/byte evidence. Declared effects are not a
 * semantic proof or operand binding; the instruction-span CFG is partial.
 * Included after foundation's types/globals and isa/intent_forms.h. IDs are
 * one-based; 0 is unknown/no parent, serialized as null. Section IDs are foundation IDs. */
#define INTENT_TRACE_MAX 65536
#define INTENT_FILE_MAX 128
#define INTENT_PATH_MAX 1024
#define INTENT_SPAN_MAX 256

typedef struct { char path[INTENT_PATH_MAX]; } IntentFile;
typedef struct { int file, line, parent, definition; } IntentOrigin;
typedef struct {
    int section, offset, size, expanded_line, origin;
    const IntentForm *form;
} IntentRecord;

static const IntentForm *g_intent_form_current = NULL;
static IntentFile *g_intent_files;
static IntentOrigin *g_intent_origins;
static IntentRecord *g_intent_records;
static int *g_intent_expanded;
static int g_intent_nfiles, g_intent_norigins, g_intent_nrecords, g_intent_nexpanded;
static int g_intent_origins_cap, g_intent_records_cap, g_intent_expanded_cap;
static int g_intent_origin_current, g_intent_expanded_line;
static const char *g_intent_raw_file;
static int g_intent_raw_line, g_intent_location_set;

static void *intent_grow(void *ptr, int *capacity, int count, size_t size) {
    if (count < 0 || count > INTENT_TRACE_MAX) die("intent trace limit exceeded (65536)");
    if (count <= *capacity) return ptr;
    int cap = *capacity ? *capacity : 256;
    while (cap < count) cap *= 2;
    if (size > (size_t)-1 / (size_t)cap) die("intent allocation limit exceeded");
    void *p = realloc(ptr, (size_t)cap * size);
    if (!p) die("oom intent trace");
    *capacity = cap;
    return p;
}

static int intent_file_intern(const char *path) {
    if (!g_explain) return -1;
    if (!path || strlen(path) >= INTENT_PATH_MAX) die("intent source path limit exceeded (1023 bytes)");
    for (int i = 0; i < g_intent_nfiles; i++)
        if (!strcmp(g_intent_files[i].path, path)) return i;
    if (g_intent_nfiles >= INTENT_FILE_MAX) die("intent source file limit exceeded (128)");
    /* One opt-in allocation keeps diagnostic path pointers stable. */
    if (!g_intent_files) {
        g_intent_files = malloc(INTENT_FILE_MAX * sizeof(*g_intent_files));
        if (!g_intent_files) die("oom intent source files");
    }
    memcpy(g_intent_files[g_intent_nfiles].path, path, strlen(path)+1);
    return g_intent_nfiles++;
}

static void intent_location_raw(const char *file, int line) {
    if (!g_explain && !g_json_diagnostics) return;
    g_intent_location_set = 1;
    g_intent_raw_file = file;
    g_intent_raw_line = line;
    g_intent_origin_current = 0;
    g_intent_expanded_line = 0;
}

static int intent_origin_add(int file, int line, int parent, int definition) {
    if (!g_explain) return 0;
    if (file < 0 || file >= g_intent_nfiles || line <= 0 ||
        parent < 0 || parent > g_intent_norigins ||
        definition < 0 || definition > g_intent_norigins)
        die("invalid intent source origin");
    g_intent_origins = intent_grow(g_intent_origins, &g_intent_origins_cap,
                                  g_intent_norigins + 1, sizeof(*g_intent_origins));
    IntentOrigin *o = &g_intent_origins[g_intent_norigins++];
    o->file = file; o->line = line; o->parent = parent; o->definition = definition;
    return g_intent_norigins;
}

static void intent_location_origin(int origin) {
    if (!g_explain) return;
    if (origin <= 0 || origin > g_intent_norigins) die("invalid intent current origin");
    IntentOrigin *o = &g_intent_origins[origin - 1];
    intent_location_raw(g_intent_files[o->file].path, o->line);
    g_intent_origin_current = origin;
}

static void intent_expanded_newline(void) {
    if (!g_explain) return;
    if (!g_intent_origin_current) die("intent output line lacks provenance");
    g_intent_expanded = intent_grow(g_intent_expanded, &g_intent_expanded_cap,
                                   g_intent_nexpanded + 1, sizeof(*g_intent_expanded));
    g_intent_expanded[g_intent_nexpanded++] = g_intent_origin_current;
}

static int intent_expanded_origin(int expanded_line) {
    if (!g_explain || expanded_line <= 0 || expanded_line > g_intent_nexpanded) return 0;
    return g_intent_expanded[expanded_line - 1];
}

/* Main calls this BEFORE checking/parsing each expanded line, including lines
 * that fail before reaching an encoder. Use intent_location_raw for raw/no-PP
 * diagnostics; an unmapped expanded line deliberately has no source location. */
static void intent_location_expanded(int expanded_line) {
    if (!g_explain && !g_json_diagnostics) return;
    intent_location_raw(NULL, 0);
    int origin = intent_expanded_origin(expanded_line);
    if (origin) intent_location_origin(origin);
    g_intent_expanded_line = expanded_line;
}

static void intent_trace_reset_pass(void) {
    if (!g_explain) return;
    g_intent_nrecords = 0;
    g_intent_form_current = NULL;
    intent_location_raw(NULL, 0);
}

static const uint8_t *intent_record_bytes(const IntentRecord *r, const char **name) {
    const uint8_t *bytes = NULL;
    int length = 0, capacity = 0;
    *name = NULL;
    if (r->section == SEC_TEXT) {
        bytes = g_text; length = g_textlen; capacity = g_textcap; *name = ".text";
    } else if (r->section == SEC_DATA) {
        bytes = g_data; length = g_datalen; capacity = g_datacap; *name = ".data";
    } else if (r->section == SEC_RODATA) {
        bytes = g_rodata; length = g_rodatalen; capacity = g_rodatacap; *name = ".rodata";
    } else if (r->section >= SEC_CUSTOM0 && r->section - SEC_CUSTOM0 < g_ncustom) {
        int ci = r->section - SEC_CUSTOM0;
        if (g_custom_type[ci] == 8) die("intent instruction in NOBITS section");
        bytes = g_custom_buf[ci]; length = g_custom_len[ci]; capacity = g_custom_cap[ci];
        *name = g_custom_name[ci];
    }
    if (!bytes || !*name || r->offset < 0 || r->offset > length || r->offset > capacity ||
        r->size <= 0 || r->size > length - r->offset || r->size > capacity - r->offset)
        die("intent instruction span outside emitted section");
    return bytes + r->offset;
}

/* Main supplies INSTRUCTIONS ONLY, including unmodeled ones, on EVERY pass.
 * Retain coordinates, not an early byte copy: the writer reads final buffers. */
static void intent_trace_record(int section, int start, int end, int expanded_line,
                                const IntentForm *form) {
    if (!g_explain) return;
    if (start < 0 || end <= start || end - start > INTENT_SPAN_MAX)
        die("intent instruction span limit exceeded (256 bytes)");
    if (form && end - start > 15) die("intent modeled instruction exceeds 15 bytes");
    int origin = intent_expanded_origin(expanded_line);
    if (!origin) die("intent instruction outside traced preprocessor");
    IntentRecord record;
    record.section = section; record.offset = start; record.size = end - start;
    record.expanded_line = expanded_line; record.origin = origin; record.form = form;
    const char *name;
    (void)intent_record_bytes(&record, &name);
    g_intent_records = intent_grow(g_intent_records, &g_intent_records_cap,
                                  g_intent_nrecords + 1, sizeof(*g_intent_records));
    g_intent_records[g_intent_nrecords++] = record;
}

static void intent_json_string(FILE *out, const char *s) {
    if (!s) { fputs("null", out); return; }
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') { fputc('\\', out); fputc(*p, out); }
        else if (*p < 32 || *p == 127) fprintf(out, "\\u%04x", (unsigned)*p);
        else fputc(*p, out);
    }
    fputc('"', out);
}

static void intent_json_id(FILE *out, int id) {
    if (id) fprintf(out, "%d", id); else fputs("null", out);
}

static void intent_origin_write(FILE *out, int id) {
    IntentOrigin *o = &g_intent_origins[id - 1];
    fprintf(out, "{\"id\":%d,\"file\":", id);
    intent_json_string(out, g_intent_files[o->file].path);
    fprintf(out, ",\"line\":%d,\"parent\":", o->line);
    intent_json_id(out, o->parent);
    fputs(",\"definition\":", out); intent_json_id(out, o->definition);
    fputc('}', out);
}

/* Allocation-free so die/die2 can use this even on trace-limit/OOM failures.
 * The expansion chain is leaf-to-caller; definition IDs also link to the
 * definition/include ancestry in the full explanation's origin table. */
static void intent_diagnostic(const char *message, const char *detail) {
    int origin = g_intent_origin_current;
    const char *file = g_intent_location_set ? g_intent_raw_file : g_file;
    int line = g_intent_location_set ? g_intent_raw_line : g_line;
    fputs("{\"schema\":\"basm-diagnostic-v1\",\"severity\":\"error\",\"message\":", stderr);
    intent_json_string(stderr, message);
    fputs(",\"detail\":", stderr); intent_json_string(stderr, detail);
    fputs(",\"file\":", stderr); intent_json_string(stderr, file);
    fputs(",\"line\":", stderr); intent_json_id(stderr, line > 0 ? line : 0);
    fputs(",\"expanded_line\":", stderr); intent_json_id(stderr, g_intent_expanded_line);
    fputs(",\"origin\":", stderr); intent_json_id(stderr, origin);
    fputs(",\"expansion_chain\":[", stderr);
    int first = 1;
    while (origin > 0 && origin <= g_intent_norigins) {
        if (!first) fputc(',', stderr);
        intent_origin_write(stderr, origin);
        first = 0;
        origin = g_intent_origins[origin - 1].parent;
    }
    fputs("]}\n", stderr);
}

#include "cfg.inc"

static void intent_trace_write(FILE *out) {
    if (!g_explain) return;
    int modeled = 0;
    for (int i = 0; i < g_intent_nrecords; i++) {
        const char *name;
        (void)intent_record_bytes(&g_intent_records[i], &name);
        if (g_intent_records[i].form) modeled++;
    }
    fputs("{\"schema\":\"basm-intent-trace-v1\",\"profile\":", out);
    intent_json_string(out, target_profile_name());
    fprintf(out, ",\"coverage\":{\"instructions\":%d,\"modeled\":%d,\"unmodeled\":%d,\"schema_forms\":%d},\"origins\":[",
            g_intent_nrecords, modeled, g_intent_nrecords - modeled,
            (int)(sizeof(g_intent_forms) / sizeof(g_intent_forms[0])));
    for (int i = 0; i < g_intent_norigins; i++) {
        if (i) fputc(',', out);
        intent_origin_write(out, i + 1);
    }
    fputs("],\"records\":[", out);
    for (int i = 0; i < g_intent_nrecords; i++) {
        IntentRecord *r = &g_intent_records[i];
        const IntentForm *f = r->form;
        const char *name;
        const uint8_t *bytes = intent_record_bytes(r, &name);
        if (i) fputc(',', out);
        fprintf(out, "{\"section\":%d,\"section_name\":", r->section);
        intent_json_string(out, name);
        fprintf(out, ",\"offset\":%d,\"size\":%d,\"bytes\":\"", r->offset, r->size);
        for (int j = 0; j < r->size; j++) fprintf(out, "%02x", (unsigned)bytes[j]);
        fprintf(out, "\",\"expanded_line\":%d,\"origin\":%d,\"form\":", r->expanded_line, r->origin);
        intent_json_string(out, f ? f->id : NULL);
        fputs(",\"status\":", out); intent_json_string(out, f ? "modeled" : "unmodeled");
        fputs(",\"mnemonic\":", out); intent_json_string(out, f ? f->mnemonic : NULL);
        fputs(",\"control\":", out); intent_json_string(out, f ? f->control : "unknown");
        fputs(",\"effects\":", out);
        if (!f) fputs("null", out);
        else {
            fputs("{\"operands\":", out); intent_json_string(out, f->operands);
            fputs(",\"reads\":", out); intent_json_string(out, f->reads);
            fputs(",\"writes\":", out); intent_json_string(out, f->writes);
            fputs(",\"flags\":", out); intent_json_string(out, f->flags);
            fputs(",\"features\":", out); intent_json_string(out, f->features);
            fprintf(out, ",\"width\":%d}", f->width);
        }
        fputc('}', out);
    }
    fputs("],\"effect_scope\":\"schema-declared, operand roles not bound to registers\","
          "\"byte_scope\":\"section bytes before link-time relocation\","
          "\"cfg\":", out);
    intent_cfg_write(out);
    fputs(",\"semantic_verification\":\"unimplemented\"}\n", out);
    if (fflush(out) != 0 || ferror(out)) die("cannot write intent explanation");
}

static void intent_trace_free(void) {
    free(g_intent_files); free(g_intent_origins); free(g_intent_records); free(g_intent_expanded);
    g_intent_files = NULL; g_intent_origins = NULL; g_intent_records = NULL; g_intent_expanded = NULL;
    g_intent_nfiles = 0; g_intent_norigins = 0; g_intent_nrecords = 0; g_intent_nexpanded = 0;
    g_intent_origins_cap = 0; g_intent_records_cap = 0; g_intent_expanded_cap = 0;
    g_intent_origin_current = 0; g_intent_expanded_line = 0;
    g_intent_raw_file = NULL; g_intent_raw_line = 0; g_intent_location_set = 0;
    g_intent_form_current = NULL;
}
