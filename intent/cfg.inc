/*
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* INV-596: instruction-span graph only; no full decoder, reachability, or
 * semantic proof. Zero-based record indices fit in 16 bits; bit 16 marks a
 * relocation overlap without allocating a second per-record array. */
enum { ICFG_UNKNOWN, ICFG_NEXT, ICFG_JUMP, ICFG_BRANCH, ICFG_CALL,
       ICFG_RETURN, ICFG_TRAP, ICFG_HALT, ICFG_SYSTEM, ICFG_RELOCATION };
static const char *const g_intent_cfg_kinds[] = {
    "unknown-control", "fallthrough", "jump", "branch", "call",
    "return", "trap", "halt", "system", "relocation"
};

static int intent_cfg_find(const int *index, int lo, int hi, int64_t offset) {
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        int id = index[mid] & (INTENT_TRACE_MAX - 1);
        if (g_intent_records[id].offset < offset) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

static int intent_cfg_control(const IntentRecord *r, int64_t *disp) {
    const char *name;
    const uint8_t *b = intent_record_bytes(r, &name);
    *disp = 0;
    if (r->size == 2 && (b[0] == 0xeb || b[0] == 0xe2 || (b[0] >= 0x70 && b[0] <= 0x7f))) {
        *disp = b[1]; if (*disp >= 128) *disp -= 256;
        return b[0] == 0xeb ? ICFG_JUMP : ICFG_BRANCH;
    }
    if ((r->size == 5 && (b[0] == 0xe9 || b[0] == 0xe8)) ||
        (r->size == 6 && b[0] == 0x0f && b[1] >= 0x80 && b[1] <= 0x8f)) {
        int p = r->size - 4;
        uint32_t u = (uint32_t)b[p] | ((uint32_t)b[p+1] << 8) |
                     ((uint32_t)b[p+2] << 16) | ((uint32_t)b[p+3] << 24);
        *disp = (int64_t)u;
        if (u & 0x80000000U) *disp -= 4294967296LL;
        return b[0] == 0xe8 ? ICFG_CALL : b[0] == 0xe9 ? ICFG_JUMP : ICFG_BRANCH;
    }
    if (!r->form) return ICFG_UNKNOWN;
    const char *control = r->form->control;
    if (!strcmp(control, "next") || !strcmp(control, "barrier")) return ICFG_NEXT;
    for (int i = ICFG_RETURN; i <= ICFG_SYSTEM; i++)
        if (!strcmp(control, g_intent_cfg_kinds[i])) return i;
    return ICFG_UNKNOWN;
}

static void intent_cfg_write(FILE *out) {
    if (!g_explain) return;
    int n = g_intent_nrecords;
    if (n < 0 || n > INTENT_TRACE_MAX || (n && !g_intent_records) ||
        g_nrelocs < 0 || g_nrelocs > RELOC_MAX) die("intent cfg count limit exceeded");
    int base[SEC_MAX+1], cursor[SEC_MAX];
    memset(base, 0, sizeof(base)); memset(cursor, 0, sizeof(cursor));
    /* Validate before allocating. Per-section emission order is monotonic,
     * even when source order switches sections; reject overlaps, do not sort. */
    for (int i = 0; i < n; i++) {
        IntentRecord *r = &g_intent_records[i];
        const char *name;
        if (r->section < 0 || r->section >= SEC_MAX || r->size > INTENT_SPAN_MAX)
            die("intent cfg invalid section or span");
        (void)intent_record_bytes(r, &name);
        if (r->offset < cursor[r->section]) die("intent cfg nonmonotonic instruction spans");
        cursor[r->section] = r->offset + r->size;
        base[r->section+1]++;
    }
    for (int i = 0; i < g_nrelocs; i++) {
        Reloc *r = &g_relocs[i];
        if (r->section < 0 || r->section >= SEC_MAX || r->offset < 0 ||
            (r->reltype != 1 && r->reltype != 2 && r->reltype != 10 && r->reltype != 11))
            die("intent cfg invalid relocation");
    }
    for (int s = 0; s < SEC_MAX; s++) { base[s+1] += base[s]; cursor[s] = base[s]; }
    int *index = n ? malloc((size_t)n * sizeof(*index)) : NULL;
    if (n && !index) die("oom intent cfg index");
    for (int i = 0; i < n; i++) index[cursor[g_intent_records[i].section]++] = i;
    /* Relocations need not be sorted. Find overlapping spans in O(log n)
     * plus at most eight one-byte records per relocation field. Both named
     * and section-symbol targets remain unresolved, regardless of addend. */
    for (int i = 0; i < g_nrelocs; i++) {
        Reloc *rel = &g_relocs[i];
        int lo = base[rel->section], hi = base[rel->section+1];
        int p = intent_cfg_find(index, lo, hi, rel->offset);
        int64_t end = (int64_t)rel->offset + (rel->reltype == 1 ? 8 : 4);
        if (p > lo) p--;
        while (p < hi) {
            IntentRecord *r = &g_intent_records[index[p] & (INTENT_TRACE_MAX - 1)];
            if (r->offset >= end) break;
            if ((int64_t)r->offset + r->size > rel->offset) index[p] |= INTENT_TRACE_MAX;
            p++;
        }
    }
    fprintf(out, "{\"status\":\"partial\",\"complete\":false,\"scope\":\"instruction-spans\",\"node_count\":%d", n);
    for (int phase = 0; phase < 2; phase++) {
        fputs(phase ? ",\"boundaries\":[" : ",\"edges\":[", out);
        int first = 1;
        for (int i = 0; i < n; i++) {
            IntentRecord *r = &g_intent_records[i];
            int64_t disp;
            int kind = intent_cfg_control(r, &disp);
            int lo = base[r->section], hi = base[r->section+1];
            int p = intent_cfg_find(index, lo, hi, r->offset);
            int relocated = index[p] & INTENT_TRACE_MAX;
            if (relocated && (kind == ICFG_NEXT || kind >= ICFG_RETURN)) kind = ICFG_RELOCATION;
            if (kind == ICFG_UNKNOWN || kind >= ICFG_RETURN) {
                if (!phase) continue;
                if (!first) fputc(',', out);
                first = 0;
                fprintf(out, "{\"node\":%d,\"kind\":\"%s\",\"terminal\":%s}", i+1,
                        g_intent_cfg_kinds[kind], kind >= ICFG_RETURN && kind <= ICFG_HALT ? "true" : "false");
                continue;
            }
            if (phase) continue;
            /* A call-continuation is a possible resume address, not proof of return. */
            int count = kind == ICFG_BRANCH || kind == ICFG_CALL ? 2 : 1;
            for (int side = 0; side < count; side++) {
                int direct = !side && kind != ICFG_NEXT;
                int64_t target = (int64_t)r->offset + r->size + (direct ? disp : 0);
                int to = 0;
                const char *reason = NULL;
                if (direct && relocated) reason = "relocation";
                else {
                    p = intent_cfg_find(index, lo, hi, target);
                    if (p < hi) {
                        int id = index[p] & (INTENT_TRACE_MAX - 1);
                        if (g_intent_records[id].offset == target) to = id + 1;
                    }
                    if (!to) reason = "not-instruction-start";
                }
                const char *label = !side ? g_intent_cfg_kinds[kind] :
                                    kind == ICFG_CALL ? "call-continuation" : "fallthrough";
                if (!first) fputc(',', out);
                first = 0;
                fprintf(out, "{\"from\":%d,\"to\":", i+1); intent_json_id(out, to);
                fprintf(out, ",\"kind\":\"%s\",\"target_section\":", label);
                if (direct && relocated) fputs("null,\"target_offset\":null", out);
                else fprintf(out, "%d,\"target_offset\":%lld", r->section, (long long)target);
                fputs(",\"reason\":", out); intent_json_string(out, reason); fputc('}', out);
            }
        }
        fputc(']', out);
    }
    fputc('}', out);
    free(index);
    if (ferror(out)) die("cannot write intent cfg");
}
