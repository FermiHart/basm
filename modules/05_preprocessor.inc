/*
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* INV-801: a job consumes immutable byte snapshots. The same resolved path
 * is read once even when cache preparation, assembly and proof emission all
 * need it. Hashes and emitted incbin bytes therefore describe the same data. */
#define BASM_SOURCE_BYTES_MAX ((size_t)16 * 1024 * 1024)
#define BASM_DEP_BYTES_MAX ((size_t)128 * 1024 * 1024)
/* All source and binary snapshots are charged to the SAME unchanged128MiB
 * aggregate. Do not reserve a fictitious full16MiB source for a tiny blob stub:
 * the actual already-consumed source bytes bound the remaining admission below.
 * Source/aggregate/output ceilings and attestation validation remain intact. */
#define BASM_BINARY_BYTES_MAX BASM_DEP_BYTES_MAX
#define BASM_DEP_COUNT_MAX 4096
static BasmDependency *g_basm_deps;
static size_t g_basm_ndeps, g_basm_dep_cap, g_basm_dep_bytes;
typedef struct { char *name; int kind; size_t index; } BasmDepRequest;
static BasmDepRequest *g_basm_dep_requests;
static size_t g_basm_nrequests, g_basm_request_cap;
/* N16: tiny jobs keep the allocation-free linear lookup. Larger closures use
 * bounded indices (index+1, zero means empty), never pointers into reallocable
 * registries. Insertion order of the authenticated closure stays unchanged. */
typedef struct { uint16_t *slots; size_t cap; } BasmDepIndex;
static BasmDepIndex g_basm_path_index, g_basm_request_index;
#define BASM_DEP_LINEAR_MAX 8

static const char *basm_index_key(size_t index, int requests, int *kind) {
    if (requests) {
        *kind=g_basm_dep_requests[index].kind;
        return g_basm_dep_requests[index].name;
    }
    *kind=0; return g_basm_deps[index].path;
}

static uint32_t basm_index_hash(const char *key, int kind) {
    return str_hash(key,strlen(key)) ^ ((uint32_t)kind*0x9e3779b9u);
}

static void basm_index_place(BasmDepIndex *table, size_t index, int requests) {
    int kind; const char *key=basm_index_key(index,requests,&kind);
    size_t slot=(size_t)basm_index_hash(key,kind)&(table->cap-1);
    while (table->slots[slot]) slot=(slot+1)&(table->cap-1);
    table->slots[slot]=(uint16_t)(index+1);
}

static void basm_index_insert(BasmDepIndex *table, size_t count, int requests) {
    if (count<=BASM_DEP_LINEAR_MAX && !table->cap) return;
    if (count>BASM_DEP_COUNT_MAX) die("dependency lookup budget exceeded");
    if (!table->cap || count>table->cap/2) {
        size_t cap=table->cap ? table->cap*2 : 32;
        uint16_t *slots=(uint16_t *)calloc(cap,sizeof(*slots));
        if (!slots) die("oom dependency lookup index");
        free(table->slots); table->slots=slots; table->cap=cap;
        for (size_t i=0; i<count; i++) basm_index_place(table,i,requests);
    } else basm_index_place(table,count-1,requests);
}

static size_t basm_index_find(const BasmDepIndex *table, const char *key,
                              int kind, size_t count, int requests) {
    if (!table->cap) {
        for (size_t i=0; i<count; i++) {
            int entry_kind; const char *entry=basm_index_key(i,requests,&entry_kind);
            if (entry_kind==kind && !strcmp(entry,key)) return i;
        }
    } else {
        size_t slot=(size_t)basm_index_hash(key,kind)&(table->cap-1);
        while (table->slots[slot]) {
            size_t i=(size_t)table->slots[slot]-1;
            int entry_kind; const char *entry=basm_index_key(i,requests,&entry_kind);
            if (entry_kind==kind && !strcmp(entry,key)) return i;
            slot=(slot+1)&(table->cap-1);
        }
    }
    return (size_t)-1;
}

static void basm_budget_input(size_t len, int kind) {
    size_t limit = kind == BASM_DEP_INCBIN ? BASM_BINARY_BYTES_MAX : BASM_SOURCE_BYTES_MAX;
    if (len > limit) die("input byte budget exceeded");
}

static size_t basm_dependency_count(void) { return g_basm_ndeps; }
static const BasmDependency *basm_dependency_at(size_t index) {
    if (index >= g_basm_ndeps) die("invalid dependency index");
    return &g_basm_deps[index];
}

static const BasmDependency *basm_snapshot_find(const char *path) {
    size_t index=basm_index_find(&g_basm_path_index,path,0,g_basm_ndeps,0);
    return index==(size_t)-1 ? NULL : &g_basm_deps[index];
}

static const BasmDependency *basm_snapshot_adopt(const char *path, unsigned char *data,
                                                  size_t len, int kind) {
    size_t pathlen=strlen(path);
    if (!pathlen || pathlen>=1024) { free(data); die("dependency path exceeds 1023 bytes"); }
    basm_budget_input(len,kind);
    if (kind != BASM_DEP_INCBIN) basm_validate_source_bytes((const char *)data,len);
    const BasmDependency *old=basm_snapshot_find(path);
    if (old) { free(data); return old; }
    if (g_basm_ndeps>=BASM_DEP_COUNT_MAX) { free(data); die("dependency count budget exceeded"); }
    if (len>BASM_DEP_BYTES_MAX-g_basm_dep_bytes) { free(data); die("dependency byte budget exceeded"); }
    if (g_basm_ndeps==g_basm_dep_cap) {
        size_t cap=g_basm_dep_cap ? g_basm_dep_cap*2 : 32;
        BasmDependency *p=(BasmDependency *)realloc(g_basm_deps,cap*sizeof(*p));
        if (!p) { free(data); die("oom dependency registry"); }
        g_basm_deps=p; g_basm_dep_cap=cap;
    }
    char *name=(char *)malloc(pathlen+1);
    if (!name) { free(data); die("oom dependency path"); }
    memcpy(name,path,pathlen+1);
    BasmDependency *dep=&g_basm_deps[g_basm_ndeps++];
    dep->path=name; dep->data=data; dep->len=len; dep->kind=kind;
    g_basm_dep_bytes+=len;
    basm_index_insert(&g_basm_path_index,g_basm_ndeps,0);
    return dep;
}

static const BasmDependency *basm_snapshot_record(const char *path, const void *data,
                                                   size_t len, int kind) {
    basm_budget_input(len,kind);
    if (kind != BASM_DEP_INCBIN) basm_validate_source_bytes((const char *)data,len);
    const BasmDependency *old=basm_snapshot_find(path);
    if (old) return old;
    if (len>BASM_DEP_BYTES_MAX-g_basm_dep_bytes) die("dependency byte budget exceeded");
    unsigned char *copy=(unsigned char *)malloc(len+1);
    if (!copy) die("oom dependency snapshot");
    if (len) memcpy(copy,data,len);
    copy[len]=0;
    return basm_snapshot_adopt(path,copy,len,kind);
}

/* INV-N19: callers hand over a freshly opened regular stream at byte zero.
 * Read directly into the immutable snapshot, without seek/stdio staging. A
 * single extra byte detects growth; short reads and EINTR remain explicit.
 * Takes ownership of stream, including on all diagnostic exits. */
static const BasmDependency *basm_snapshot_file(FILE *stream, const char *path, int kind) {
    const BasmDependency *old=basm_snapshot_find(path);
    if (old) {
        if (fclose(stream)!=0) die2("cannot close dependency",path);
        basm_budget_input(old->len,kind);
        if (kind != BASM_DEP_INCBIN) basm_validate_source_bytes((const char *)old->data,old->len);
        return old;
    }
    int fd=fileno(stream);
    struct stat st;
    if (fd<0 || fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || st.st_size<0) {
        fclose(stream); die2("cannot size regular dependency",path);
    }
    size_t limit=kind==BASM_DEP_INCBIN ? BASM_BINARY_BYTES_MAX : BASM_SOURCE_BYTES_MAX;
    if ((uint64_t)st.st_size>(uint64_t)limit ||
        (uint64_t)st.st_size>(uint64_t)(BASM_DEP_BYTES_MAX-g_basm_dep_bytes)) {
        fclose(stream); die("input or dependency byte budget exceeded");
    }
    size_t len=(size_t)st.st_size;
    unsigned char *data=(unsigned char *)malloc(len+1);
    if (!data) { fclose(stream); die("oom dependency snapshot"); }
    size_t got=0;
    int failed=0;
    while (got<=len) {
        long n;
        do { n=(long)read(fd,data+got,len+1-got); }
        while (n<0 && errno==EINTR);
        if (n<0) { failed=1; break; }
        if (!n) break;
        got+=(size_t)n;
    }
    int closed=fclose(stream);
    if (got!=len || failed || closed!=0) {
        free(data); die2("dependency changed size or could not be read",path);
    }
    data[len]=0;
    return basm_snapshot_adopt(path,data,len,kind);
}

static const BasmDependency *basm_snapshot_open(const char *name, int kind) {
    size_t found=basm_index_find(&g_basm_request_index,name,kind,g_basm_nrequests,1);
    if (found!=(size_t)-1)
        return basm_dependency_at(g_basm_dep_requests[found].index);
    FILE *f=incbin_open(name);
    if (!f) die2("cannot open dependency",name);
    if (!g_last_open_path[0]) { fclose(f); die("dependency lacks resolved path"); }
    const BasmDependency *dep=basm_snapshot_file(f,g_last_open_path,kind);
    size_t index=(size_t)(dep-g_basm_deps), namelen=strlen(name);
    if (namelen>=1024 || g_basm_nrequests>=BASM_DEP_COUNT_MAX)
        die("dependency lookup budget exceeded");
    if (g_basm_nrequests==g_basm_request_cap) {
        size_t cap=g_basm_request_cap ? g_basm_request_cap*2 : 32;
        BasmDepRequest *p=(BasmDepRequest *)realloc(g_basm_dep_requests,cap*sizeof(*p));
        if (!p) die("oom dependency lookup registry");
        g_basm_dep_requests=p; g_basm_request_cap=cap;
    }
    char *copy=(char *)malloc(namelen+1);
    if (!copy) die("oom dependency lookup name");
    memcpy(copy,name,namelen+1);
    BasmDepRequest *request=&g_basm_dep_requests[g_basm_nrequests++];
    request->name=copy; request->kind=kind; request->index=index;
    basm_index_insert(&g_basm_request_index,g_basm_nrequests,1);
    return &g_basm_deps[index];
}

static void basm_dependencies_reset(void) {
    for (size_t i=0; i<g_basm_ndeps; i++) {
        free((void *)g_basm_deps[i].path); free((void *)g_basm_deps[i].data);
    }
    for (size_t i=0; i<g_basm_nrequests; i++) free(g_basm_dep_requests[i].name);
    free(g_basm_deps); free(g_basm_dep_requests);
    free(g_basm_path_index.slots); free(g_basm_request_index.slots);
    memset(&g_basm_path_index,0,sizeof(g_basm_path_index));
    memset(&g_basm_request_index,0,sizeof(g_basm_request_index));
    g_basm_deps=NULL; g_basm_dep_requests=NULL;
    g_basm_ndeps=g_basm_dep_cap=g_basm_dep_bytes=0;
    g_basm_nrequests=g_basm_request_cap=0;
}

/* INV-802: bounded preprocessing is part of input admission. Counts cover
 * work even when a macro emits no bytes; multiplication is checked before rep. */
#define PP_OUTPUT_BYTES_MAX ((size_t)64 * 1024 * 1024)
#define PP_ARENA_BYTES_MAX ((size_t)64 * 1024 * 1024)
#define PP_WORK_BYTES_MAX ((size_t)128 * 1024 * 1024)
#define PP_WORK_STEPS_MAX ((size_t)4 * 1024 * 1024)
static size_t pp_work_bytes, pp_work_steps, pp_arena_bytes;
static void pp_charge_work(size_t bytes) {
    if (pp_work_steps>=PP_WORK_STEPS_MAX || bytes>PP_WORK_BYTES_MAX-pp_work_bytes)
        die("preprocessor work budget exceeded");
    pp_work_steps++; pp_work_bytes+=bytes;
}

/* Linear memory arena for bounded preprocessor scratch allocations. */
#define ARENA_BLK 65536
typedef struct Arena { char *base; size_t used, cap; struct Arena *next; } Arena;
static Arena *g_pp_arena = NULL;
static void pp_reset_state(void);

static void *arena_alloc(size_t n) {
    if (n > ((size_t)-1) - 7) die("arena allocation too large");
    n = (n + 7) & ~(size_t)7; /* 8-byte alignment */
    if (!g_pp_arena || n > g_pp_arena->cap - g_pp_arena->used) {
        size_t cap = n > ARENA_BLK ? n : ARENA_BLK; /* INV-540 */
        if (cap>PP_ARENA_BYTES_MAX-pp_arena_bytes) die("preprocessor arena budget exceeded");
        /* N18: one owned allocation for the header and its aligned payload. */
        Arena *blk = (Arena*)malloc(sizeof(Arena)+cap);
        if (!blk) die("oom arena block");
        blk->base = (char *)(blk+1);
        blk->used = 0; blk->cap = cap; blk->next = g_pp_arena;
        g_pp_arena = blk;
        pp_arena_bytes+=cap;
    }
    void *p = g_pp_arena->base + g_pp_arena->used;
    g_pp_arena->used += n;
    return p;
}

static void arena_reset(void) {
    Arena *blk = g_pp_arena;
    while (blk) { Arena *next = blk->next; free(blk); blk = next; }
    g_pp_arena = NULL;
    pp_arena_bytes=0;
    pp_reset_state();
}

static char *pp_copy_text(const char *text, size_t len) {
    if (len>=BASM_LINE_CAP) die("preprocessor token exceeds 1023 bytes");
    char *copy=(char *)arena_alloc(len+1);
    memcpy(copy,text,len); copy[len]=0; return copy;
}

/* ------------------------------------------------------------------ */
/* NASM-subset preprocessor                                           */
/* ------------------------------------------------------------------ */
/* Runs once over the source before assembly, emitting an expanded source
 * the existing parser consumes verbatim. Supports exactly the minimal NASM
 * preprocessor constructs the SigilOS kernel asm uses (and nothing more):
 *
 *   %define NAME value            whole-word text substitution
 *   %macro NAME n ... %endmacro   positional (%1..%64) multi-line macros,
 *                                 with %N pasted even INSIDE identifiers
 *                                 (NASM token paste, e.g. isr_%1 -> isr_0)
 *   %if 0 / %if <nonero> ... [%else] ... %endif   constant conditional
 *   [BITS 64]                     no-op (basm is 64-bit only); [BITS 16/32]
 *                                 are a clear error (separate later task).
 *
 * Precedent: this is the documented behaviour of NASM's own preprocessor
 * (NASM manual ch.4 "The NASM Preprocessor"). Tables, line buffers, arena,
 * dependency snapshots and expansion work have explicit finite limits. */
#define PP_MAXDEF 256
#define PP_MAXMAC 64
/* PPDef: object-like (%define X val) OR function-like (%define P(a,b) body).
 * nparam<0 means object-like; >=0 means function-like with that many params.
 * Author: F E R M I ∞ H A R T. */
typedef struct { char name[NAME_MAX]; char *value;
                 int nparam; char params[4][NAME_MAX]; } PPDef;
/* argc is the minimum; variadic permits more, within PP_MAX_ARGS. */
typedef struct { char name[NAME_MAX]; int argc; int variadic; char *body;
                 int definition_origin; /* INV-596 */ } PPMac;
static PPDef pp_defs[PP_MAXDEF]; static int pp_ndef=0;
static PPMac pp_macs[PP_MAXMAC]; static int pp_nmac=0;
static int pp_llabel=0;

#define PPDEF_HT_CAP  512
#define PPMAC_HT_CAP  128
/* INV-582: single-%rep expansion ceiling. Largest real use is 256
 * (isr stubs); anything past 2^20 is a hang-bomb, refused up front. */
#define PP_REP_MAX 1048576L
#define PP_MAX_ARGS 64
static HTEntry pp_def_ht[PPDEF_HT_CAP];
static HTEntry pp_mac_ht[PPMAC_HT_CAP];

static char  *pp_out; static size_t pp_len, pp_cap;
static void pp_reserve(size_t add){
    if (add > PP_OUTPUT_BYTES_MAX-pp_len) die("preprocessor output byte budget exceeded");
    size_t need=pp_len+add;
    if (need > pp_cap) {
        size_t new_cap = pp_cap ? pp_cap : 4096;
        while (new_cap < need) {
            if (new_cap > PP_OUTPUT_BYTES_MAX/2) { new_cap=PP_OUTPUT_BYTES_MAX; break; }
            new_cap *= 2;
        }
        char *p = (char*)realloc(pp_out, new_cap);
        if (!p) die("oom in preprocessor");
        pp_out = p; pp_cap = new_cap;
    }
}
static void pp_emit_ch(char c){
    if (g_explain && c=='\n') intent_expanded_newline(); /* INV-596 */
    pp_reserve(1);
    pp_out[pp_len++] = c;
}
static void pp_emit_str(const char *s){
    if (g_explain)
        for (const char *p=s; *p; p++) if (*p=='\n') intent_expanded_newline();
    size_t n=strlen(s); pp_reserve(n);
    memcpy(pp_out+pp_len,s,n); pp_len+=n; /* INV-549 */
}
/* N17: an ordinary line and its terminator share one capacity check. */
static void pp_emit_line(const char *s) {
    size_t n=strlen(s); pp_reserve(n+1);
    if (g_explain) {
        for (size_t i=0; i<n; i++) if (s[i]=='\n') intent_expanded_newline();
        intent_expanded_newline();
    }
    memcpy(pp_out+pp_len,s,n); pp_len+=n; pp_out[pp_len++]='\n';
}

static int pp_is_ident(int c){ return isalnum(c)||c=='_'; }

/* INV-803: substitutions operate on tokens, never on quoted strings or
 * comments. Every append either fits completely or reports a bounded error. */
static void pp_append(char *out, size_t outsz, size_t *used, const char *text, size_t len) {
    if (!outsz || *used>=outsz || len>outsz-1-*used)
        die("preprocessor expansion exceeds line capacity");
    memcpy(out+*used,text,len); *used+=len; out[*used]=0;
}

static const char *pp_quoted_end(const char *p) {
    char quote=*p++;
    while (*p && *p!=quote) {
        if (quote=='`' && *p=='\\' && p[1]) p++;
        p++;
    }
    if (*p!=quote) die("unterminated preprocessor string");
    return p+1;
}

static const char *pp_comment_end(const char *text) {
    const char *p=text;
    while (*p && *p!=';') {
        if (char_in(*p,"\"'`")) p=pp_quoted_end(p);
        else p++;
    }
    return p;
}

static void pp_validate_line_quotes(const char *text) {
    if (strchr(text,'"') || strchr(text,'\'') || strchr(text,'`'))
        (void)pp_comment_end(text);
}

static char *pp_copy_trimmed(const char *start, const char *end) {
    while (start<end && char_in(*start," \t")) start++;
    while (end>start && char_in(end[-1]," \t\r")) end--;
    return pp_copy_text(start,(size_t)(end-start));
}

/* N15: invocation arguments borrow spans of the caller's live line. Macro
 * expansion is synchronous, including recursion and rotation, so no span
 * outlives that caller. Persistent definitions/bodies still own arena bytes. */
typedef struct { const char *text; size_t len; } PPArg;
static PPArg pp_arg_trimmed(const char *start, const char *end) {
    while (start<end && char_in(*start," \t")) start++;
    while (end>start && char_in(end[-1]," \t\r")) end--;
    size_t len=(size_t)(end-start);
    if (len>=BASM_LINE_CAP) die("preprocessor token exceeds 1023 bytes");
    PPArg result={start,len}; return result;
}

/* Definitions own their values. Reassignment to a same-size or shorter value
 * can reuse that storage; no invocation span aliases a stored definition. */
static void pp_store_value(PPDef *def, const char *start, const char *end) {
    PPArg value=pp_arg_trimmed(start,end);
    if (def->value && strlen(def->value)>=value.len) {
        memmove(def->value,value.text,value.len); def->value[value.len]=0;
    } else def->value=pp_copy_text(value.text,value.len);
}

/* Delimiters inside nested expressions and quoted strings cannot create
 * arguments. The caller passes the first byte inside a function's opening (. */
static int pp_parse_args(const char **cursor, PPArg *args, int maximum, int function) {
    const char *p=*cursor;
    while (char_in(*p," \t")) p++;
    if (function && *p==')') { *cursor=p+1; return 0; }
    if (!function && (!*p || *p==';')) { *cursor=p; return 0; }
    const char *start=p;
    char delimiters[64]; int depth=0, count=0;
    for (;;) {
        if (char_in(*p,"\"'`")) { p=pp_quoted_end(p); continue; }
        if (char_in(*p,"([{")) {
            if (depth>=64) die("macro argument nesting too deep");
            delimiters[depth++]=*p++; continue;
        }
        if (char_in(*p,")]}")) {
            if (function && !depth && *p==')') {
                if (count>=maximum) die("too many macro arguments");
                args[count++]=pp_arg_trimmed(start,p); *cursor=p+1; return count;
            }
            if (!depth || !((delimiters[depth-1]=='(' && *p==')') ||
                           (delimiters[depth-1]=='[' && *p==']') ||
                           (delimiters[depth-1]=='{' && *p=='}')))
                die("mismatched macro argument delimiter");
            depth--; p++; continue;
        }
        if (!*p || *p==';' || *p=='\n' || *p=='\r') {
            if (function || depth) die("unterminated macro argument delimiter");
            if (count>=maximum) die("too many macro arguments");
            args[count++]=pp_arg_trimmed(start,p); *cursor=p; return count;
        }
        if (*p==',' && !depth) {
            if (count>=maximum) die("too many macro arguments");
            args[count++]=pp_arg_trimmed(start,p); start=++p; continue;
        }
        p++;
    }
}

static void pp_subst_parameters(const PPDef *def, const PPArg *args, char *out,
                                 size_t outsz, size_t *used) {
    const char *p=def->value;
    while (*p) {
        if (*p==';') { pp_append(out,outsz,used,p,strlen(p)); return; }
        if (char_in(*p,"\"'`")) {
            const char *end=pp_quoted_end(p);
            pp_append(out,outsz,used,p,(size_t)(end-p)); p=end; continue;
        }
        if (pp_is_ident((unsigned char)*p)) {
            const char *start=p;
            while (pp_is_ident((unsigned char)*p) || *p=='.') p++;
            size_t len=(size_t)(p-start); int matched=-1;
            for (int k=0; k<def->nparam; k++)
                if (strlen(def->params[k])==len && !memcmp(def->params[k],start,len)) {
                    matched=k; break;
                }
            if (matched>=0) pp_append(out,outsz,used,args[matched].text,args[matched].len);
            else pp_append(out,outsz,used,start,len);
        } else pp_append(out,outsz,used,p++,1);
    }
}

/* Whole identifier substitution with an explicit arity and size contract. */
static void pp_subst_defines(const char *in, char *out, int outsz) {
    size_t used=0; const char *p=in; out[0]=0;
    if (!pp_ndef) {
        pp_validate_line_quotes(in);
        pp_append(out,(size_t)outsz,&used,in,strlen(in)); return;
    }
    while (*p) {
        if (*p==';') { pp_append(out,(size_t)outsz,&used,p,strlen(p)); break; }
        if (char_in(*p,"\"'`")) {
            const char *end=pp_quoted_end(p);
            pp_append(out,(size_t)outsz,&used,p,(size_t)(end-p)); p=end; continue;
        }
        if (pp_is_ident((unsigned char)*p) &&
            !(p>in && (pp_is_ident((unsigned char)p[-1]) || p[-1]=='.'))) {
            const char *start=p;
            while (pp_is_ident((unsigned char)*p) || *p=='.') p++;
            size_t len=(size_t)(p-start); int didx=-1;
            if (len<NAME_MAX) {
                uint32_t hash=str_hash(start,len);
                int slot=(int)(hash & (PPDEF_HT_CAP-1));
                while (pp_def_ht[slot].hash) {
                    int idx=pp_def_ht[slot].idx;
                    if (pp_def_ht[slot].hash==hash && pp_def_ht[slot].len==len &&
                        !memcmp(pp_defs[idx].name,start,len)) { didx=idx; break; }
                    slot=(slot+1)&(PPDEF_HT_CAP-1);
                }
            }
            int matched=0;
            if (didx>=0) {
                const PPDef *def=&pp_defs[didx];
                if (def->nparam<0) {
                    pp_append(out,(size_t)outsz,&used,def->value,strlen(def->value)); matched=1;
                } else {
                    const char *q=p; while (char_in(*q," \t")) q++;
                    if (*q=='(') {
                        PPArg args[4]; q++;
                        int nargs=pp_parse_args(&q,args,4,1);
                        if (nargs!=def->nparam) die2("function-like define argument count mismatch",def->name);
                        pp_subst_parameters(def,args,out,(size_t)outsz,&used);
                        p=q; matched=1;
                    }
                }
            }
            if (!matched) pp_append(out,(size_t)outsz,&used,start,len);
        } else pp_append(out,(size_t)outsz,&used,p++,1);
    }
}

static void pp_process_line(const char *line, int depth);
static const char *pp_trim(const char *q);  /* fwd */
static int pp_parse_ident(const char **pp, char *out, size_t outs);
static void pp_require_end(const char *p, const char *message) {
    while (char_in(*p," \t\r")) p++;
    if (*p && *p!=';') die(message);
}

/* Lookup a %define by name. Returns index or -1. */
static int pp_def_find(const char *name) {
    size_t nl = strlen(name);
    if (nl >= NAME_MAX) nl = NAME_MAX - 1;
    uint32_t h = str_hash(name, nl);
    int mask = PPDEF_HT_CAP - 1;
    int i = (int)(h & (uint32_t)mask);
    while (pp_def_ht[i].hash) {
        int idx = pp_def_ht[i].idx;
        if (pp_def_ht[i].hash == h && pp_def_ht[i].len == nl &&
            memcmp(pp_defs[idx].name, name, nl) == 0)
            return idx;
        i = (i + 1) & mask;
    }
    return -1;
}

/* INV-588: open-addressing entries store indices into pp_defs, so removing
 * one definition must compact the array and rebuild every indexed slot. */
static void pp_def_remove(const char *name) {
    int idx = pp_def_find(name);
    if (idx < 0) return;
    if (idx + 1 < pp_ndef) {
        memmove(&pp_defs[idx], &pp_defs[idx + 1],
                (size_t)(pp_ndef - idx - 1) * sizeof(pp_defs[0]));
    }
    pp_ndef--;
    memset(&pp_defs[pp_ndef], 0, sizeof(pp_defs[0]));
    memset(pp_def_ht, 0, sizeof(pp_def_ht));
    for (int i = 0; i < pp_ndef; i++) {
        size_t n = strlen(pp_defs[i].name);
        ht_insert(pp_def_ht, PPDEF_HT_CAP, str_hash(pp_defs[i].name, n),
                  (uint8_t)n, i);
    }
}

static void pp_define_offset(const char *name, long value) {
    size_t len=strlen(name);
    if (!len || len>=NAME_MAX) die("structure constant name too long");
    int found=pp_def_find(name);
    if (found<0) {
        if (pp_ndef>=PP_MAXDEF) die("structure definition budget exceeded");
        found=pp_ndef++;
        memcpy(pp_defs[found].name,name,len+1);
        ht_insert(pp_def_ht,PPDEF_HT_CAP,str_hash(name,len),(uint8_t)len,found);
    }
    char text[32]; snprintf(text,sizeof(text),"%ld",value);
    pp_store_value(&pp_defs[found],text,text+strlen(text));
    pp_defs[found].nparam=-1;
}

/* expand macro `mac` with the given args, recursively processing each body
 * line (so %define and nested macros still apply inside the expansion). */
static void pp_expand_macro(PPMac *mac, const PPArg *args, int nargs, int depth) {
    if (depth>256) die("macro expansion too deep");
    if ((!mac->variadic && nargs!=mac->argc) || (mac->variadic && nargs<mac->argc))
        die2("macro argument count mismatch",mac->name);
    if (nargs>PP_MAX_ARGS) die("too many macro arguments");
    int argbase=0;
    const char *body=mac->body;
    int caller=0, file=-1, definition_line=0, body_line=0;
    if (g_explain) {
        caller=g_intent_origin_current;
        if (mac->definition_origin<=0 || mac->definition_origin>g_intent_norigins)
            die("intent macro lacks definition provenance");
        IntentOrigin *o=&g_intent_origins[mac->definition_origin-1];
        file=o->file; definition_line=o->line;
    }
    while (*body) {
        if (g_explain) {
            body_line++;
            intent_location_origin(intent_origin_add(file,definition_line+body_line,
                                                       caller,mac->definition_origin));
        }
        const char *eol=strchr(body,'\n');
        int len=checked_source_line_len(body,eol);
        pp_charge_work((size_t)len+1);
        char raw[BASM_LINE_CAP]; memcpy(raw,body,(size_t)len); raw[len]=0;
        const char *p=raw; size_t used=0; char expanded[BASM_LINE_CAP]; expanded[0]=0;
        while (*p) {
            if (*p==';') { pp_append(expanded,sizeof(expanded),&used,p,strlen(p)); break; }
            if (char_in(*p,"\"'`")) {
                const char *end=pp_quoted_end(p);
                pp_append(expanded,sizeof(expanded),&used,p,(size_t)(end-p)); p=end; continue;
            }
            if (*p=='%' && isdigit((unsigned char)p[1])) {
                p++; unsigned index=0;
                do {
                    unsigned digit=(unsigned)(*p-'0');
                    if (index>(PP_MAX_ARGS-digit)/10) die("macro parameter exceeds argument budget");
                    index=index*10+digit; p++;
                } while (isdigit((unsigned char)*p));
                if (!index) {
                    char count[32]; snprintf(count,sizeof(count),"%d",nargs);
                    pp_append(expanded,sizeof(expanded),&used,count,strlen(count));
                } else {
                    if (index>(unsigned)nargs) die2("macro parameter has no argument",mac->name);
                    const PPArg *arg=&args[((int)index-1+argbase)%nargs];
                    pp_append(expanded,sizeof(expanded),&used,arg->text,arg->len);
                }
            } else pp_append(expanded,sizeof(expanded),&used,p++,1);
        }
        const char *t=pp_trim(expanded);
        if (!strncmp(t,"%rotate",7) && (!t[7] || char_in(t[7]," \t"))) {
            char value[BASM_LINE_CAP]; pp_subst_defines(pp_trim(t+7),value,sizeof(value));
            if (!*value || *value==';') die("%rotate needs a count");
            long rotation=parse_expr(value);
            if (nargs) {
                int shift=(int)(rotation%nargs); if (shift<0) shift+=nargs;
                argbase=(argbase+shift)%nargs;
            }
        } else pp_process_line(expanded,depth+1);
        if (!eol) break;
        body=eol+1;
    }
    if (g_explain) intent_location_origin(caller);
}

/* Apply %define substitution to one line, then either expand a macro
 * invocation or emit the line verbatim. */
static void pp_process_line(const char *line, int depth){
    size_t line_len=strlen(line);
    pp_charge_work(line_len+1);
    if (line_len>=BASM_LINE_CAP) die("preprocessor expansion exceeds line capacity");
    /* Handle %assign on the RAW line first — before define substitution would
     * clobber the target name (e.g. `%assign vec vec+1` must not have the
     * leading `vec` replaced by its current value). The RHS is substituted
     * explicitly below. Author: F E R M I ∞ H A R T. */
    {
        const char *t=line; while(char_in(*t, " \t"))t++;
        size_t tlen = strlen(t);
        if(tlen >= 7 && !strncmp(t,"%assign",7) && (tlen == 7 || char_in(t[7], " \t"))){
            const char *c=pp_trim(t+7);
            char nm[NAME_MAX];
            if (!pp_parse_ident(&c,nm,sizeof(nm))) die("%assign needs a name");
            const char *v=pp_trim(c);
            const char *end=pp_comment_end(v);
            char *raw=pp_copy_trimmed(v,end);
            if (!*raw) die("%assign needs an expression");
            char sub[BASM_LINE_CAP]; pp_subst_defines(raw, sub, sizeof(sub));
            long val = parse_expr(sub);
            char vbuf[32]; snprintf(vbuf,sizeof(vbuf),"%ld",val);
            int found = pp_def_find(nm);
            if(found<0){ if(pp_ndef>=PP_MAXDEF)die("too many %assign"); found=pp_ndef++;
                         basm_name_copy(pp_defs[found].name,nm);
                         ht_insert(pp_def_ht, PPDEF_HT_CAP, str_hash(pp_defs[found].name, strlen(nm)), (uint8_t)strlen(nm), found); }
            pp_store_value(&pp_defs[found],vbuf,vbuf+strlen(vbuf));
            pp_defs[found].nparam=-1;
            return;
        }
    }
    char exp0[BASM_LINE_CAP]; const char *expanded=line;
    if (pp_ndef) {
        pp_subst_defines(line, exp0, sizeof(exp0)); expanded=exp0;
    }
    /* Even without paste, a substitution may have introduced new quote
     * boundaries. Keep the validation formerly performed by the paste scan. */
    pp_validate_line_quotes(expanded);

    /* NASM token paste `%+`: collapse `A %+ B` -> `AB` (used by isr_stubs.S
     * `dq isr %+ vec` to build isr0..isr255). Done after define substitution
     * so the operands are already expanded. Author: F E R M I ∞ H A R T. */
    char exp[BASM_LINE_CAP];
    if (strstr(expanded,"%+")) {
        size_t used=0; const char *p=expanded; exp[0]=0;
        while (*p) {
            if (*p==';') { pp_append(exp,sizeof(exp),&used,p,strlen(p)); break; }
            if (char_in(*p,"\"'`")) {
                const char *end=pp_quoted_end(p);
                pp_append(exp,sizeof(exp),&used,p,(size_t)(end-p)); p=end; continue;
            }
            if (p[0]=='%' && p[1]=='+') {
                while (used && char_in(exp[used-1]," \t")) used--;
                exp[used]=0; p+=2;
                while (char_in(*p," \t")) p++;
            } else pp_append(exp,sizeof(exp),&used,p++,1);
        }
        expanded=exp;
    }

    const char *p=expanded; while(char_in(*p, " \t"))p++;
    /* INV-596: includes emitted by a macro/define/rep would be opened later
     * by the assembler, outside this provenance closure. Never invent a map. */
    if (g_explain && !strncmp(p,"%include",8) &&
        strchr(" \t\r", p[8]))
        die("intent include outside traced preprocessor");
    if (pp_nmac && *p && *p!=';'){
        const char *s=p;
        while(*p && !char_in(*p, " \t,;\n\r"))p++;
        int nlen=(int)(p-s);
        if (nlen>0 && nlen<NAME_MAX){
            char name[NAME_MAX]; memcpy(name,s,nlen); name[nlen]=0;
            PPMac *mac=NULL;
            uint32_t mh = str_hash(name, (size_t)nlen);
            int mmask = PPMAC_HT_CAP - 1;
            int mhi = (int)(mh & (uint32_t)mmask);
            while (pp_mac_ht[mhi].hash) {
                int idx = pp_mac_ht[mhi].idx;
                if (pp_mac_ht[mhi].hash == mh && pp_mac_ht[mhi].len == (uint8_t)nlen &&
                    memcmp(pp_macs[idx].name, name, (size_t)nlen) == 0) {
                    mac = &pp_macs[idx]; break;
                }
                mhi = (mhi + 1) & mmask;
            }
            if(mac){
                PPArg args[PP_MAX_ARGS];
                const char *a=p;
                int nargs=pp_parse_args(&a,args,PP_MAX_ARGS,0);
                pp_expand_macro(mac,args,nargs,depth);
                return;
            }
        }
    }
    pp_emit_line(expanded);
}

/* trimmed start of a line buffer */
static const char *pp_trim(const char *q){ while(char_in(*q, " \t"))q++; return q; }

/* Conditional-assembly frame.  active==1 means the current branch is being
 * emitted; matched==1 means some earlier branch in this %if was true, so
 * later %elif/%else must stay off. */
typedef struct { int active; int matched; int else_seen; } PPFrame;

/* True if `name` is a currently-defined preprocessor symbol (%define or
 * %assign). */
static int pp_is_defined(const char *name){
    return pp_def_find(name) >= 0;
}

/* Parse one identifier from *pp into out; returns 1 if an identifier was
 * parsed.  Advances *pp past trailing spaces. */
static int pp_parse_ident(const char **pp, char *out, size_t outs){
    const char *p = pp_trim(*pp);
    size_t n = 0;
    while (*p && (pp_is_ident((unsigned char)*p) || *p=='.')) {
        if (n+1>=outs) die("preprocessor identifier too long");
        out[n++]=*p++;
    }
    if (n == 0) return 0;
    out[n] = 0;
    *pp = pp_trim(p);
    return 1;
}

/* INV-572: share prefix/boundary checks without broadening whitespace or
 * accepting a keyword prefix. Some directives allow NUL; others require space. */
static int pp_keyword(const char *p, const char *word, int allow_nul) {
    size_t n=strlen(word);
    if (strncmp(p,word,n)) return 0;
    if (!p[n]) return allow_nul;
    return char_in(p[n]," \t");
}

/* Evaluate a preprocessor conditional expression (after the directive name).
 * The leading '%' has already been stripped, so the body for "%ifdef FOO"
 * arrives as "def FOO".  Supports:
 *   <number>                truthy if nonero
 *   <name>                  truthy if defined
 *   def name                true if name defined
 *   ndef name               true if name not defined
 *   idn a, b                true if token a == token b
 *   nidn a, b               true if token a != token b
 */
static int pp_eval_cond(const char *expr){
    const char *p = pp_trim(expr);
    if (!*p || *p == ';') return 0;

    /* def / ndef */
    if (pp_keyword(p,"def",1)){
        char nm[NAME_MAX];
        const char *q = pp_trim(p+3);
        if (!pp_parse_ident(&q, nm, sizeof(nm))) die("%ifdef needs identifier");
        pp_require_end(q,"%ifdef takes one identifier");
        return pp_is_defined(nm);
    }
    if (pp_keyword(p,"ndef",1)){
        char nm[NAME_MAX];
        const char *q = pp_trim(p+4);
        if (!pp_parse_ident(&q, nm, sizeof(nm))) die("%ifndef needs identifier");
        pp_require_end(q,"%ifndef takes one identifier");
        return !pp_is_defined(nm);
    }
    /* Exactly two complete arguments, with commas inside quotes preserved. */
    if (pp_keyword(p,"idn",1) || pp_keyword(p,"nidn",1)) {
        int invert=(*p=='n');
        const char *q=pp_trim(p+(invert ? 4 : 3));
        PPArg args[2]; int count=pp_parse_args(&q,args,2,0);
        if (count!=2 || !args[0].len || !args[1].len)
            die("%ifidn/%ifnidn needs two comma-separated tokens");
        pp_require_end(q,"trailing conditional tokens");
        return (args[0].len==args[1].len &&
                !memcmp(args[0].text,args[1].text,args[0].len)) != invert;
    }

    /* INV-703: evaluate the complete condition, not just its first token.
     * Keep undefined bare configuration names false; compound forms fail closed. */
    char nm[NAME_MAX], sub[BASM_LINE_CAP];
    const char *q=p;
    /* INV-741: a bare literal such as %if 1 is not an undefined identifier. */
    if (!isdigit((unsigned char)*p) && pp_parse_ident(&q,nm,sizeof(nm))) {
        q=pp_trim(q);
        if ((!*q || *q==';') && pp_def_find(nm)<0) return 0;
    }
    pp_subst_defines(p,sub,sizeof(sub));
    for (int pass=0;pass<32;pass++) {
        char next[BASM_LINE_CAP]; pp_subst_defines(sub,next,sizeof(next));
        if(!strcmp(next,sub))return parse_condition(sub);
        memcpy(sub,next,strlen(next)+1);
    }
    die("condition expansion did not converge");
    return 0;
}

static const char *pp_read_include_file(const char *fname, long *out_size, int *out_file) {
    const BasmDependency *dep=basm_snapshot_open(fname,BASM_DEP_INCLUDE);
    if (g_explain) *out_file=intent_file_intern(dep->path);
    *out_size=(long)dep->len;
    /* Snapshot byte allocations never move, even when the registry grows.
     * The read-only scanner borrows them until job cleanup. */
    return (const char *)dep->data;
}

typedef struct { PPFrame frame[64]; int fsp,nfalse; } PPContext;

/* INV-596: scanners jump over macro/rep/struc bodies. Count physical newlines
 * with one monotonic cursor, including body scans that can themselves fail. */
static void pp_trace_raw(const char **cursor,int *line,const char *at,int file,int parent){
    if (!g_explain) return;
    while (*cursor<at) { if (**cursor=='\n') (*line)++; (*cursor)++; }
    intent_location_raw(g_intent_files[file].path,*line);
    intent_location_origin(intent_origin_add(file,*line,parent,0));
}

/* INV-586: macro, structure and repetition bodies have identical scan rules. */
static char *pp_read_body(const char *start, const char *ending, const char **after,
                          const char **trace_cursor, int *trace_line, int file, int parent) {
    const char *scan=start, *body_end=NULL;
    *after=NULL;
    while(scan && *scan){
        if (g_explain) pp_trace_raw(trace_cursor,trace_line,scan,file,parent);
        const char *se=strchr(scan,'\n'); const char *snext=se?se+1:NULL;
        char lb[BASM_LINE_CAP]; int ll=checked_source_line_len(scan,se);
        memcpy(lb,scan,ll); lb[ll]=0;
        const char *t=pp_trim(lb);
        if(pp_keyword(t,ending,1)) {
            pp_require_end(t+strlen(ending),"trailing tokens after body terminator");
            body_end=scan; *after=snext; break;
        }
        if(!snext) break;
        scan=snext;
    }
    if(!body_end)return NULL;
    size_t blen=(size_t)(body_end-start);
    char *body=(char*)arena_alloc(blen+1);
    memcpy(body,start,blen); body[blen]=0;
    return body;
}

static void pp_process_buffer(const char *src,int include_depth,PPContext *ctx,int file,int parent){
    if(include_depth>INCLUDE_DEPTH)die("include depth exceeded");
    const char *p=src;
    const char *trace_cursor=src; int trace_line=1;
    while(*p){
        g_line++;
        if (g_explain) pp_trace_raw(&trace_cursor,&trace_line,p,file,parent);
        const char *eol=strchr(p,'\n');
        const char *next = eol?eol+1:NULL;
        char buf[BASM_LINE_CAP];
        int len = checked_source_line_len(p, eol);
        pp_charge_work((size_t)len+1);
        memcpy(buf,p,len); buf[len]=0;
        const char *q=pp_trim(buf);

        /* ---- conditional assembly: track %if/%elif/%else/%endif even while skipping */
        int is_if_directive = 0, is_elif = 0;
        if (!strncmp(q, "%if", 3)) {
            const char *r = q + 3;
            if (strchr(" \t", *r)) { is_if_directive = 1; is_elif = 0; }
            else if (pp_keyword(r,"def",1)) { is_if_directive = 1; is_elif = 0; }
            else if (pp_keyword(r,"ndef",1)) { is_if_directive = 1; is_elif = 0; }
            else if (pp_keyword(r,"idn",1)) { is_if_directive = 1; is_elif = 0; }
            else if (pp_keyword(r,"nidn",1)) { is_if_directive = 1; is_elif = 0; }
        }
        if (!is_if_directive && !strncmp(q, "%elif", 5)) {
            const char *r = q + 5;
            if (strchr(" \t", *r)) { is_if_directive = 1; is_elif = 1; }
            else if (pp_keyword(r,"def",1)) { is_if_directive = 1; is_elif = 1; }
            else if (pp_keyword(r,"ndef",1)) { is_if_directive = 1; is_elif = 1; }
            else if (pp_keyword(r,"idn",1)) { is_if_directive = 1; is_elif = 1; }
            else if (pp_keyword(r,"nidn",1)) { is_if_directive = 1; is_elif = 1; }
        }
        if(is_if_directive){
            const char *body = pp_trim(q + (is_elif ? 5 : 3));
            int cond = pp_eval_cond(body);
            /* Parent frames must all be active for this branch to fire. */
            int parent_active = (ctx->nfalse == 0);
            if(!is_elif){
                if(ctx->fsp>=64) die("%if nesting too deep");
                ctx->frame[ctx->fsp].active = parent_active && cond;
                ctx->frame[ctx->fsp].matched = ctx->frame[ctx->fsp].active;
                ctx->frame[ctx->fsp].else_seen=0;
                ctx->fsp++;
                if(!ctx->frame[ctx->fsp-1].active) ctx->nfalse++;
            } else {
                if(ctx->fsp<=0) die("%elif without %if");
                PPFrame *fr = &ctx->frame[ctx->fsp-1];
                if (fr->else_seen) die("%elif after %else");
                /* Ancestors active?  The current frame itself may be inactive,
                 * in which case nfalse counts it; allow that one. */
                int ancestors_active = (ctx->nfalse == 0) || (ctx->nfalse == 1 && !fr->active);
                if(fr->matched || !ancestors_active){
                    if(fr->active){ fr->active = 0; ctx->nfalse++; }
                } else {
                    fr->active = ancestors_active && cond;
                    if(fr->active){ fr->matched = 1; if(ctx->nfalse>0) ctx->nfalse--; }
                }
            }
            if(!next)break; p=next; continue;
        }
        if(pp_keyword(q,"%else",1)){
            pp_require_end(q+5,"%else takes no arguments");
            if(ctx->fsp<=0) die("%else without %if");
            PPFrame *fr = &ctx->frame[ctx->fsp-1];
            if (fr->else_seen) die("duplicate %else");
            fr->else_seen=1;
            int parent_active = (ctx->nfalse == 0 || (!fr->active && ctx->nfalse == 1));
            if(fr->matched){
                if(fr->active){ fr->active = 0; ctx->nfalse++; }
            } else {
                if(parent_active){
                    if(!fr->active){ fr->active = 1; if(ctx->nfalse>0) ctx->nfalse--; }
                }
            }
            fr->matched = 1;
            if(!next)break; p=next; continue;
        }
        if(pp_keyword(q,"%endif",1)){
            pp_require_end(q+6,"%endif takes no arguments");
            if(ctx->fsp<=0) die("%endif without %if");
            ctx->fsp--;
            PPFrame *fr = &ctx->frame[ctx->fsp];
            if(!fr->active) ctx->nfalse--;
            if(!next)break; p=next; continue;
        }
        if(ctx->nfalse>0){ if(!next)break; p=next; continue; } /* inside a dead block */
        if(pp_keyword(q,"%error",1)) {
            char message[BASM_LINE_CAP];
            pp_subst_defines(pp_trim(q+6),message,sizeof(message));
            source_error(message);
        }

        /* INV-588: %define lives in this preprocessing table, so %undef must
         * remove it here, before ordinary-line substitution. */
        if(pp_keyword(q,"%undef",0)){
            const char *c=pp_trim(q+6); char nm[NAME_MAX];
            if(!pp_parse_ident(&c,nm,sizeof(nm)))die("%undef needs a name");
            pp_require_end(c,"%undef takes one identifier");
            pp_def_remove(nm);
            if(!next)break; p=next; continue;
        }

        /* INV-561: only active includes touch the filesystem, and included
         * definitions share this preprocessor state with their caller. */
        if(pp_keyword(q,"%include",0)){
            char expanded[BASM_LINE_CAP], fname[1024];
            pp_subst_defines(pp_trim(q+8),expanded,sizeof(expanded));
            const char *r=pp_trim(expanded), *start=r; size_t n;
            if (char_in(*r,"\"'")) {
                const char *end=pp_quoted_end(r);
                start=r+1; n=(size_t)(end-start-1); r=end;
            } else {
                while (*r && !char_in(*r," \t;\r")) r++;
                n=(size_t)(r-start);
            }
            if (!n || n>=sizeof(fname)) die("invalid %include name");
            pp_require_end(r,"%include takes one filename");
            memcpy(fname,start,n); fname[n]=0;
            long inc_sz=0; int inc_file=-1;
            int caller=g_explain ? g_intent_origin_current : 0;
            const char *inc=pp_read_include_file(fname,&inc_sz,&inc_file);
            pp_process_buffer(inc,include_depth+1,ctx,inc_file,caller);
            if (g_explain) intent_location_origin(caller);
            if(!next)break; p=next; continue;
        }

        /* ---- %define ---- */
        if(pp_keyword(q,"%define",0)){
            const char *c=pp_trim(q+7), *start=c;
            while (pp_is_ident((unsigned char)*c) || *c=='.') c++;
            size_t namelen=(size_t)(c-start); char nm[NAME_MAX];
            if (!namelen || namelen>=sizeof(nm)) die("invalid %define name");
            memcpy(nm,start,namelen); nm[namelen]=0;
            int nparam=-1; char params[4][NAME_MAX];
            if (*c=='(') {
                c=pp_trim(c+1); nparam=0;
                while (*c!=')') {
                    if (nparam>=4) die("%define supports at most 4 parameters");
                    if (!pp_parse_ident(&c,params[nparam],sizeof(params[nparam])))
                        die("invalid %define parameter");
                    for (int k=0; k<nparam; k++)
                        if (!strcmp(params[k],params[nparam])) die("duplicate %define parameter");
                    nparam++;
                    if (*c==')') break;
                    if (*c!=',') die("%define parameters require commas and a closing parenthesis");
                    c=pp_trim(c+1);
                    if (*c==')') die("empty %define parameter");
                }
                if (*c!=')') die("%define missing )");
                c++;
            }
            const char *v=pp_trim(c), *end=pp_comment_end(v);
            int found=pp_def_find(nm);
            if (found<0) {
                if (pp_ndef>=PP_MAXDEF) die("too many %define");
                found=pp_ndef++;
                memcpy(pp_defs[found].name,nm,namelen+1);
                ht_insert(pp_def_ht,PPDEF_HT_CAP,str_hash(nm,namelen),(uint8_t)namelen,found);
            }
            pp_store_value(&pp_defs[found],v,end);
            pp_defs[found].nparam=nparam;
            for (int k=0; k<nparam; k++)
                memcpy(pp_defs[found].params[k],params[k],strlen(params[k])+1);
            if(!next)break; p=next; continue;
        }

        /* ---- %assign NAME expr : reassignable numeric (NASM). Evaluated now;
         * stored as a decimal-string object-like define. Used by isr_stubs.S
         * to generate vectored stubs. Author: F E R M I ∞ H A R T. ---- */
        if(pp_keyword(q,"%assign",0)){
            const char *c=pp_trim(q+7);
            char nm[NAME_MAX];
            if (!pp_parse_ident(&c,nm,sizeof(nm))) die("%assign needs a name");
            const char *v=pp_trim(c);
            const char *end=pp_comment_end(v);
            char *raw=pp_copy_trimmed(v,end);
            if (!*raw) die("%assign needs an expression");
            char sub[BASM_LINE_CAP]; pp_subst_defines(raw, sub, sizeof(sub));
            long val = parse_expr(sub);
            char vbuf[32]; snprintf(vbuf,sizeof(vbuf),"%ld",val);
            int found = pp_def_find(nm);
            if(found<0){ if(pp_ndef>=PP_MAXDEF)die("too many %assign"); found=pp_ndef++;
                         basm_name_copy(pp_defs[found].name,nm);
                         ht_insert(pp_def_ht, PPDEF_HT_CAP, str_hash(pp_defs[found].name, strlen(nm)), (uint8_t)strlen(nm), found); }
            pp_store_value(&pp_defs[found],vbuf,vbuf+strlen(vbuf));
            pp_defs[found].nparam=-1;
            if(!next)break; p=next; continue;
        }

        /* ---- %macro NAME argc ... %endmacro ---- */
        if(pp_keyword(q,"%macro",1)){
            int definition_origin=g_explain ? g_intent_origin_current : 0;
            const char *c=pp_trim(q+6);
            char nm[NAME_MAX];
            if (!pp_parse_ident(&c,nm,sizeof(nm))) die("%macro needs a name");
            uint64_t argc=0; int variadic=0;
            if (*c=='*') { variadic=1; c++; }
            else {
                if (!isdigit((unsigned char)*c)) die("%macro needs an argument count");
                argc=basm_parse_u64(&c);
                if (*c=='-' && c[1]=='*') { variadic=1; c+=2; }
                else if (char_in(*c,"+*")) { variadic=1; c++; }
            }
            if (argc>PP_MAX_ARGS) die("macro argument count exceeds budget");
            pp_require_end(c,"invalid %macro argument specification");
            if(pp_nmac>=PP_MAXMAC) die("too many %macro");
            const char *after=NULL;
            char *body=pp_read_body(next,"%endmacro",&after,&trace_cursor,&trace_line,file,parent);
            if(!body) die("%macro without %endmacro");
            basm_name_copy(pp_macs[pp_nmac].name,nm);
            pp_macs[pp_nmac].argc=(int)argc; pp_macs[pp_nmac].variadic=variadic; pp_macs[pp_nmac].body=body;
            pp_macs[pp_nmac].definition_origin=definition_origin;
            ht_insert(pp_mac_ht, PPMAC_HT_CAP, str_hash(pp_macs[pp_nmac].name, strlen(nm)), (uint8_t)strlen(nm), pp_nmac);
            pp_nmac++;
            if(!after) break; p=after; continue;
        }

        /* ---- struc NAME ... endstruc ---- */
        if(pp_keyword(q,"struc",1)){
            const char *c=pp_trim(q+5); char nm[NAME_MAX];
            if (!pp_parse_ident(&c,nm,sizeof(nm))) die("struc needs a name");
            pp_require_end(c,"struc takes one name");
            if (find_struct(nm)>=0) die2("duplicate structure",nm);
            if (g_nstructs>=MAX_STRUCTS) die("too many structures");
            const char *after=NULL;
            char *body=pp_read_body(next,"endstruc",&after,&trace_cursor,&trace_line,file,parent);
            if (!body) die("struc without endstruc");
            StructDef *structure=&g_structs[g_nstructs];
            memcpy(structure->name,nm,strlen(nm)+1); structure->nfields=0;
            long offset=0;
            char *line=body;
            while (*line) {
                char *eol=strchr(line,'\n');
                int len=checked_source_line_len(line,eol);
                pp_charge_work((size_t)len+1);
                char raw[BASM_LINE_CAP]; memcpy(raw,line,(size_t)len); raw[len]=0;
                const char *t=pp_trim(raw);
                if (*t && *t!=';') {
                    if (*t=='.') t++;
                    char field[NAME_MAX];
                    if (!pp_parse_ident(&t,field,sizeof(field))) die("structure field needs a name");
                    if (*t==':') t=pp_trim(t+1);
                    int unit=0;
                    if (pp_keyword(t,"resb",0)) unit=1;
                    else if (pp_keyword(t,"resw",0)) unit=2;
                    else if (pp_keyword(t,"resd",0)) unit=4;
                    else if (pp_keyword(t,"resq",0)) unit=8;
                    if (!unit) die("structure field requires resb/resw/resd/resq and a count");
                    char count_text[BASM_LINE_CAP];
                    pp_subst_defines(pp_trim(t+4),count_text,sizeof(count_text));
                    long count=basm_parse_count(count_text,2147483647L/unit,"structure field count");
                    long size=count*unit;
                    if (size>2147483647L-offset) die("structure size exceeds supported range");
                    if (structure->nfields>=MAX_FIELDS) die("too many structure fields");
                    for (int k=0; k<structure->nfields; k++)
                        if (!strcmp(structure->fields[k].name,field)) die("duplicate structure field");
                    char defname[NAME_MAX*2];
                    int written=snprintf(defname,sizeof(defname),"%s.%s",nm,field);
                    if (written<0 || written>=(int)sizeof(defname)) die("structure constant name too long");
                    pp_define_offset(defname,offset);
                    StructField *slot=&structure->fields[structure->nfields++];
                    memcpy(slot->name,field,strlen(field)+1);
                    slot->offset=(int)offset; slot->size=(int)size;
                    offset+=size;
                }
                if (!eol) break;
                line=eol+1;
            }
            char size_name[NAME_MAX+8];
            int written=snprintf(size_name,sizeof(size_name),"%s_size",nm);
            if (written<0 || written>=(int)sizeof(size_name)) die("structure size name too long");
            pp_define_offset(size_name,offset);
            structure->total_size=(int)offset; g_nstructs++;
            if(!after) break; p=after; continue;
        }

        /* ---- %rep N ... %endrep ---- */
        if(pp_keyword(q,"%rep",0)){
            int rep_origin=g_explain ? g_intent_origin_current : 0;
            int rep_line=trace_line;
            const char *c=pp_trim(q+4);
            char count_text[BASM_LINE_CAP];
            pp_subst_defines(c,count_text,sizeof(count_text));
            long count=basm_parse_count(count_text,BASM_LONG_MAX,"%rep count");
            if (count>PP_REP_MAX) die("excessive %rep count"); /* INV-582 */
            /* body spans from next line up to (not including) the %endrep line */
            const char *after=NULL;
            char *body=pp_read_body(next,"%endrep",&after,&trace_cursor,&trace_line,file,parent);
            if(!body) die("%rep without %endrep");
            /* Refuse work amplification before entering the loop, including
             * comment-only bodies whose emitted bytes are semantically empty. */
            size_t body_bytes=strlen(body), body_steps=0;
            for (const char *scan=body; *scan; scan++) if (*scan=='\n') body_steps++;
            if (body_bytes && body[body_bytes-1]!='\n') body_steps++;
            if (count>0 && ((body_bytes && (size_t)count>(PP_WORK_BYTES_MAX-pp_work_bytes)/body_bytes) ||
                            (body_steps && (size_t)count>(PP_WORK_STEPS_MAX-pp_work_steps)/body_steps)))
                die("preprocessor repetition exceeds work budget");
            for(long i=0;i<count;i++){
                char *l=body;
                int body_line=rep_line;
                while(*l){
                    if (g_explain) {
                        body_line++;
                        intent_location_origin(intent_origin_add(file,body_line,rep_origin,0));
                    }
                    char *eol=strchr(l,'\n');
                    int ll=checked_source_line_len(l,eol);
                    char tmp[BASM_LINE_CAP];
                    memcpy(tmp,l,(size_t)ll); tmp[ll]=0;
                    pp_process_line(tmp, 0);
                    if(!eol) break;
                    l=eol+1;
                }
            }
            if (g_explain) intent_location_origin(rep_origin);
            if(!after) break; p=after; continue;
        }

        /* ---- anonymous local labels: @@ / @F / @B ----
         * Replace "@@:" with a unique synthetic label, and @F/@B with the
         * corresponding synthetic name.  This gives NASM-compatible anonymous
         * local labels without changing the assembler's symbol table.
         * Author: F E R M I ∞ H A R T. */
        pp_validate_line_quotes(buf);
        if (strchr(buf,'@')) {
            char expanded[BASM_LINE_CAP]; size_t used=0;
            const char *text=buf; int changed=0; expanded[0]=0;
            while (*text) {
                if (*text==';') { pp_append(expanded,sizeof(expanded),&used,text,strlen(text)); break; }
                if (char_in(*text,"\"'`")) {
                    const char *end=pp_quoted_end(text);
                    pp_append(expanded,sizeof(expanded),&used,text,(size_t)(end-text)); text=end; continue;
                }
                int number=-1, skip=0;
                if (text[0]=='@' && text[1]=='@' && strchr(": \t\n\r",text[2])) {
                    number=pp_llabel++; skip=2;
                } else if (text[0]=='@' && text[1]=='F') {
                    number=pp_llabel; skip=2;
                } else if (text[0]=='@' && text[1]=='B') {
                    number=pp_llabel ? pp_llabel-1 : 0; skip=2;
                }
                if (skip) {
                    char label[32]; int len=snprintf(label,sizeof(label),"..@L.%d",number);
                    if (len<0 || len>=(int)sizeof(label)) die("local label overflow");
                    pp_append(expanded,sizeof(expanded),&used,label,(size_t)len);
                    text+=skip; changed=1;
                } else pp_append(expanded,sizeof(expanded),&used,text++,1);
            }
            if (changed) { memcpy(buf,expanded,used+1); q=pp_trim(buf); }
        }

        /* ---- [BITS n] : emit a bare `bits N` line so the ASSEMBLY-time
         * directive handler updates g_bits each pass. The preprocessor runs
         * once, but assemble_pass() resets g_bits=64 and re-scans the emitted
         * stream every pass; if we swallowed [BITS n] here, the bracketed form
         * (used by ap_trampoline's [BITS 16]/[BITS 32]) would never set the
         * mode at emission time -> wrong 0x66/0x67 prefixes and addressing.
         * Author: F E R M I ∞ H A R T. */
        if(!g_target_profile && strlen(q) >= 6 && q[0]=='[' && char_in(q[1], "bB") && char_in(q[2], "iI") &&
           char_in(q[3], "tT") && char_in(q[4], "sS")){
            const char *c=pp_trim(q+5);
            uint64_t mode=basm_parse_u64(&c); c=pp_trim(c);
            if (*c!=']') die("BITS directive requires a closing bracket");
            pp_require_end(c+1,"trailing BITS directive tokens");
            if (mode==64) pp_emit_str("bits 64\n");
            else if (mode==32) pp_emit_str("bits 32\n");
            else if (mode==16) pp_emit_str("bits 16\n");
            else die2("unsupported BITS directive",q);
            if(!next)break; p=next; continue;
        }

        /* ---- ordinary line: defines + macro invocation ---- */
        pp_process_line(buf, 0);
        if (!next) break;
        p = next;
    }
}

/* N18: arena release ends the lifetime of all definition/body pointers. Only
 * touched tables are cleared, so ordinary jobs do not dirty their unused BSS
 * pages. The expanded result has been transferred to its caller separately.
 * This resets preprocessing state; it is not a claim that main is reentrant. */
static void pp_reset_state(void) {
    if (pp_ndef) {
        memset(pp_defs,0,(size_t)pp_ndef*sizeof(pp_defs[0]));
        memset(pp_def_ht,0,sizeof(pp_def_ht));
    }
    if (pp_nmac) {
        memset(pp_macs,0,(size_t)pp_nmac*sizeof(pp_macs[0]));
        memset(pp_mac_ht,0,sizeof(pp_mac_ht));
    }
    pp_ndef=pp_nmac=pp_llabel=0;
    g_nstructs=0;
    pp_out=NULL; pp_len=pp_cap=0;
    pp_work_bytes=pp_work_steps=0;
}

/* N14: brackets in operands are not preprocessor directives. Keep the
 * original no-marker shortcut, then admit this narrower zero-copy case only
 * when expansion would preserve every byte (including its final newline).
 * Quotes, macro markers, anonymous labels and structures stay on the full
 * scanner. A bracket at the start of a line also stays there, including BITS.
 * Work admission is identical to the two charges of each ordinary line. */
static int pp_plain_bracket_source(const char *src, size_t size) {
    if (!size || src[size-1]!='\n' || strchr(src,'%') || strchr(src,'@') ||
        strchr(src,'"') || strchr(src,'\'') || strchr(src,'`') || strstr(src,"struc"))
        return 0;
    for (const char *p=src; *p;) {
        if (*pp_trim(p)=='[') return 0;
        const char *eol=strchr(p,'\n');
        if (!eol) return 0;
        p=eol+1;
    }
    g_line=0;
    for (const char *p=src; *p;) {
        g_line++;
        const char *eol=strchr(p,'\n');
        size_t bytes=(size_t)checked_source_line_len(p,eol)+1;
        pp_charge_work(bytes);
        pp_charge_work(bytes);
        p=eol+1;
    }
    return 1;
}

/* Main preprocessor pass. Returns the owned input or a new owned expansion. */
static char *preprocess(char *src,long sz){
    if (sz<0) die("invalid source size");
    basm_snapshot_record(g_srcname,src,(size_t)sz,BASM_DEP_SOURCE);
    pp_work_bytes=pp_work_steps=0;
    if(!g_explain && pp_ndef==0 && pp_nmac==0 && !strchr(src,'%') && !strchr(src,'[') &&
       !strchr(src,'@') && !strstr(src,"struc"))
        return src; /* INV-555: ordinary assembly needs no preprocessing copy. */
    if(!g_explain && pp_ndef==0 && pp_nmac==0 && pp_plain_bracket_source(src,(size_t)sz))
        return src;
    pp_cap=(size_t)sz+4096;
    if (pp_cap>PP_OUTPUT_BYTES_MAX) pp_cap=PP_OUTPUT_BYTES_MAX;
    pp_out=malloc(pp_cap); if(!pp_out)die("oom in preprocessor");
    pp_len=0; g_line=0;
    PPContext ctx; memset(&ctx,0,sizeof(ctx));
    int file=intent_file_intern(g_srcname);
    pp_process_buffer(src,0,&ctx,file,0);
    if(ctx.fsp!=0)die("unterminated %if");
    pp_emit_ch(0);
    free(src);
    char *result=pp_out;
    pp_out=NULL; pp_len=pp_cap=0;
    return result;
}
