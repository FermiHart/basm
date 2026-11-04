/* elftool.c — Sovereign ELF64 inspector for the Bear/basm toolchain.
 *
 * Replaces GNU objcopy/readelf in the acceptance gates so the whole
 * verification pipeline runs natively on macOS and Linux with nothing
 * beyond a C compiler. Clean-room: written from the ELF64 spec, no
 * code taken from binutils.
 *
 * Usage:
 *   elftool secs   <obj>            list sections (name offset size)
 *   elftool sec    <obj> <name>     write raw section bytes to stdout
 *   elftool syms   <obj>            normalized symbol table dump
 *   elftool relocs <obj>            normalized relocation dump
 *
 * Output is a stable, platform-independent text format: two objects
 * dumped by the same elftool can be compared with cmp/diff for
 * byte-parity gates (basm vs reference assembler).
 *
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <limits.h>

static uint8_t *g_buf;
static size_t   g_len;

static void die(const char *msg) {
    fprintf(stderr, "elftool: %s\n", msg);
    exit(1);
}

/* Check the operands before adding them. Offsets remain uint64_t until
 * validated, including on hosts where size_t is narrower than ELF64. */
static int span_ok(uint64_t off, uint64_t len) {
    return off <= g_len && len <= (uint64_t)g_len - off;
}

static void require_span(uint64_t off, uint64_t len, const char *msg) {
    if (!span_ok(off, len)) die(msg);
}

static uint16_t rd16(uint64_t off) {
    require_span(off, 2, "truncated file (u16)");
    return (uint16_t)(g_buf[off] | (g_buf[off + 1] << 8));
}

static uint32_t rd32(uint64_t off) {
    require_span(off, 4, "truncated file (u32)");
    return (uint32_t)g_buf[off] | ((uint32_t)g_buf[off + 1] << 8) |
           ((uint32_t)g_buf[off + 2] << 16) | ((uint32_t)g_buf[off + 3] << 24);
}

static uint64_t rd64(uint64_t off) {
    require_span(off, 8, "truncated file (u64)");
    return (uint64_t)rd32(off) | ((uint64_t)rd32(off + 4) << 32);
}

/* ELF64 layout constants (from the spec, not from elf.h, so the tool
 * also builds on hosts without ELF system headers). */
enum {
    EH_SHOFF     = 0x28,
    EH_SHENTSIZE = 0x3a,
    EH_SHNUM     = 0x3c,
    EH_SHSTRNDX  = 0x3e,
    SH_NAME      = 0x00,
    SH_TYPE      = 0x04,
    SH_FLAGS     = 0x08,
    SH_OFFSET    = 0x18,
    SH_SIZE      = 0x20,
    SH_LINK      = 0x28,
    SH_INFO      = 0x2c,
    SH_ALIGN     = 0x30,
    SH_ENTSIZE   = 0x38,
    SHT_NULL     = 0,
    SHT_SYMTAB   = 2,
    SHT_STRTAB   = 3,
    SHT_RELA     = 4,
    SHT_NOTE     = 7,
    SHT_NOBITS   = 8,
    SHT_REL      = 9,
    SHT_DYNSYM   = 11,
    SYM_ENTSZ    = 24,
    RELA_ENTSZ   = 24,
    REL_ENTSZ    = 16
};

typedef struct {
    const char *name;
    uint32_t    type;
    uint64_t    flags;
    uint64_t    off;
    uint64_t    size;
    uint32_t    link;
    uint32_t    info;
    uint64_t    align;
    uint64_t    entsize;
} Sec;

static Sec     *g_secs;
static uint16_t g_nsecs;

static const char *str_at(uint64_t tab_off, uint64_t tab_size, uint32_t idx) {
    require_span(tab_off, tab_size, "string table out of file");
    if (tab_size == 0 && idx == 0) return "";
    if ((uint64_t)idx >= tab_size) die("string index out of range");
    const char *s = (const char *)(g_buf + (size_t)tab_off + idx);
    if (!memchr(s, 0, (size_t)(tab_size - idx))) die("unterminated ELF string");
    return s;
}

/* All callers, including audit and the comparison commands, receive a
 * validated structural view. Policy checks (W^X, ET_REL, overlap, dynamic
 * linkage) remain in audit; malformed tables are never an AUDIT OK. */
static int is_symtab(const Sec *s) {
    return s->type == SHT_SYMTAB || s->type == SHT_DYNSYM;
}

static int is_reloc(const Sec *s) {
    return s->type == SHT_RELA || s->type == SHT_REL;
}

typedef struct {
    const char *owner;
    const uint8_t *desc;
    uint32_t type, descsz;
    uint64_t next;
} Note;

static Note note_at(const Sec *s, uint64_t pos) {
    Note n;
    require_span(s->off, s->size, "note section exceeds file");
    if (pos > s->size || s->size - pos < 12) die("truncated note header");
    uint64_t b = s->off + pos;
    uint32_t namesz = rd32(b), descsz = rd32(b + 4);
    uint64_t namepad = ((uint64_t)namesz + 3) & ~UINT64_C(3);
    uint64_t descpad = ((uint64_t)descsz + 3) & ~UINT64_C(3);
    uint64_t remaining = s->size - pos - 12;
    if (namepad > remaining || descpad > remaining - namepad)
        die("truncated note entry");
    uint64_t noff = b + 12, doff = noff + namepad;
    n.owner = "";
    if (namesz) {
        if (g_buf[noff + namesz - 1] != 0) die("note name not terminated");
        n.owner = (const char *)g_buf + noff;
    }
    n.type = rd32(b + 8);
    n.descsz = descsz;
    n.desc = g_buf + doff;
    n.next = pos + 12 + namepad + descpad;
    return n;
}

static void validate_notes(const Sec *s) {
    uint64_t pos = 0;
    while (pos < s->size) pos = note_at(s, pos).next;
}

/* Minimum field extent for the standard AMD64 relocation encodings. A
 * marker has no field; unknown machine-specific encodings still require a
 * target byte, without pretending to validate their runtime semantics. */
static unsigned relocation_extent(uint16_t machine, uint32_t type) {
    if (type == 0) return 0;
    if (machine != 62) return 1;
    switch (type) {
        case 1: case 6: case 7: case 8: case 16: case 17: case 18:
        case 24: case 25: case 27: case 28: case 29: case 30: case 31:
        case 33: case 37: case 38: return 8;
        case 2: case 3: case 4: case 9: case 10: case 11:
        case 19: case 20: case 21: case 22: case 23: case 26:
        case 32: case 34: case 41: case 42: return 4;
        case 12: case 13: return 2;
        case 35: return 0; /* TLSDESC_CALL: marker, not a stored field. */
        default: return 1;
    }
}

static void validate_tables(void) {
    for (uint16_t i = 0; i < g_nsecs; i++) {
        Sec *s = &g_secs[i];
        if (s->type == SHT_STRTAB && s->size &&
            (g_buf[s->off] != 0 || g_buf[s->off + s->size - 1] != 0))
            die("string table must start and end with NUL");
        if (s->type == SHT_NOTE) validate_notes(s);
        if (!is_symtab(s)) continue;
        if (s->entsize != SYM_ENTSZ || s->size % SYM_ENTSZ)
            die("bad symbol table entry size");
        if (s->link >= g_nsecs || g_secs[s->link].type != SHT_STRTAB)
            die("symtab has bad strtab link");
        uint64_t count = s->size / SYM_ENTSZ;
        if (!count || s->info == 0 || s->info > count)
            die("bad symbol table local boundary");
        for (uint64_t j = 0; j < count; j++) {
            uint64_t e = s->off + j * SYM_ENTSZ;
            Sec *str = &g_secs[s->link];
            (void)str_at(str->off, str->size, rd32(e));
            uint16_t ndx = rd16(e + 6);
            if (ndx == 0xffff) die("extended symbol section indices unsupported");
            if (ndx < 0xff00 && ndx >= g_nsecs) die("symbol has bad section index");
            if (((g_buf[e + 4] >> 4) == 0) != (j < s->info))
                die("symbol binding disagrees with local boundary");
            if (j == 0) {
                for (unsigned k = 0; k < SYM_ENTSZ; k++)
                    if (g_buf[e + k]) die("nonzero null symbol");
            }
        }
    }
    for (uint16_t i = 0; i < g_nsecs; i++) {
        Sec *s = &g_secs[i];
        if (!is_reloc(s)) continue;
        uint64_t stride = s->type == SHT_RELA ? RELA_ENTSZ : REL_ENTSZ;
        if (s->entsize != stride || s->size % stride)
            die("bad relocation entry size");
        /* Do not narrow sh_link to uint16_t before validating it. */
        if (s->link >= g_nsecs || !is_symtab(&g_secs[s->link]))
            die("relocation has bad symtab link");
        if (s->info >= g_nsecs || (rd16(0x10) == 1 && s->info == 0))
            die("relocation has bad target section");
        uint64_t nsym = g_secs[s->link].size / SYM_ENTSZ;
        for (uint64_t j = 0; j < s->size / stride; j++) {
            uint64_t e = s->off + j * stride, info = rd64(e + 8);
            if ((info >> 32) >= nsym)
                die("relocation symbol index out of range");
            if (rd16(0x10) == 1) {
                Sec *target = &g_secs[s->info];
                uint64_t off = rd64(e);
                unsigned extent = relocation_extent(rd16(0x12), (uint32_t)info);
                if (target->type == SHT_NULL || (extent &&
                    (off > target->size || extent > target->size - off)))
                    die("relocation field exceeds target section");
            }
        }
    }
}

static void load(const char *path) {
    free(g_secs); g_secs = NULL; g_nsecs = 0;
    free(g_buf); g_buf = NULL; g_len = 0;
    FILE *f = fopen(path, "rb");
    if (!f) die("cannot open input");
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); die("cannot seek input"); }
    long sz = ftell(f);
    if (sz < 0x40 || (uintmax_t)sz > SIZE_MAX || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f); die("not a readable ELF64 object (too small or too large)");
    }
    g_len = (size_t)sz;
    g_buf = malloc(g_len);
    if (!g_buf) { fclose(f); die("out of memory"); }
    int read_bad = fread(g_buf, 1, g_len, f) != g_len || ferror(f);
    if (fclose(f) != 0) read_bad = 1;
    if (read_bad) die("read failed");

    if (memcmp(g_buf, "\x7f" "ELF", 4) != 0) die("bad ELF magic");
    if (g_buf[4] != 2) die("not 64-bit ELF");
    if (g_buf[5] != 1) die("not little-endian ELF");
    if (g_buf[6] != 1 || rd32(0x14) != 1) die("bad ELF version");
    if (rd16(0x34) != 0x40) die("bad e_ehsize");

    uint64_t shoff = rd64(EH_SHOFF);
    uint16_t shentsize = rd16(EH_SHENTSIZE);
    g_nsecs = rd16(EH_SHNUM);
    uint16_t shstrndx = rd16(EH_SHSTRNDX);
    if (shentsize < 0x40) die("bad e_shentsize");
    if (!g_nsecs || shstrndx == 0xffff)
        die("missing or extended section numbering unsupported");
    if (shstrndx >= g_nsecs) die("bad e_shstrndx");
    if (shoff < 0x40) die("section table overlaps ELF header");
    require_span(shoff, (uint64_t)g_nsecs * shentsize, "section table out of file");
    for (unsigned k = 0; k < 0x40; k++)
        if (g_buf[shoff + k]) die("nonzero null section header");

    uint16_t phnum = rd16(0x38), phentsize = rd16(0x36);
    if (phnum == 0xffff) die("extended program-header numbering unsupported");
    if (phnum) {
        uint64_t phoff = rd64(0x20);
        if (phentsize < 56 || phoff < 0x40) die("bad program header table");
        require_span(phoff, (uint64_t)phnum * phentsize, "program header table out of file");
        for (uint16_t i = 0; i < phnum; i++) {
            uint64_t p = phoff + (uint64_t)i * phentsize;
            require_span(rd64(p + 8), rd64(p + 32), "segment out of file");
        }
    }

    if (rd32(shoff + (uint64_t)shstrndx * shentsize + SH_TYPE) != SHT_STRTAB)
        die("section names do not reference a string table");
    uint64_t str_off  = rd64(shoff + (uint64_t)shstrndx * shentsize + SH_OFFSET);
    uint64_t str_size = rd64(shoff + (uint64_t)shstrndx * shentsize + SH_SIZE);

    g_secs = calloc(g_nsecs, sizeof(Sec));
    if (!g_secs) die("out of memory");
    for (uint16_t i = 0; i < g_nsecs; i++) {
        uint64_t b = shoff + (uint64_t)i * shentsize;
        g_secs[i].name  = str_at(str_off, str_size, rd32(b + SH_NAME));
        g_secs[i].type  = rd32(b + SH_TYPE);
        g_secs[i].flags = rd64(b + SH_FLAGS);
        g_secs[i].off   = rd64(b + SH_OFFSET);
        g_secs[i].size = rd64(b + SH_SIZE);
        g_secs[i].link = rd32(b + SH_LINK);
        g_secs[i].info = rd32(b + SH_INFO);
        g_secs[i].align = rd64(b + SH_ALIGN);
        g_secs[i].entsize = rd64(b + SH_ENTSIZE);
        if (g_secs[i].align && (g_secs[i].align & (g_secs[i].align - 1)))
            die("section alignment is not a power of two");
        if (g_secs[i].type != SHT_NOBITS && g_secs[i].type != SHT_NULL)
            require_span(g_secs[i].off, g_secs[i].size, "section out of file");
    }
    validate_tables();
}

static int find_sec(const char *name) {
    for (uint16_t i = 0; i < g_nsecs; i++)
        if (!strcmp(g_secs[i].name, name)) return i;
    return -1;
}

static const char *sym_name(uint32_t symtab_idx, uint64_t sym_idx) {
    if (symtab_idx >= g_nsecs || !is_symtab(&g_secs[symtab_idx]))
        die("invalid symbol table index");
    Sec *st = &g_secs[symtab_idx];
    if (sym_idx >= st->size / SYM_ENTSZ) die("symbol index out of range");
    uint64_t e = st->off + (uint64_t)sym_idx * SYM_ENTSZ;
    uint32_t nameoff = rd32(e);
    if (st->link >= g_nsecs) die("symtab has bad strtab link");
    Sec *str = &g_secs[st->link];
    return str_at(str->off, str->size, nameoff);
}

static void cmd_secs(void) {
    for (uint16_t i = 0; i < g_nsecs; i++)
        printf("%-20s off=%llu size=%llu\n", g_secs[i].name,
               (unsigned long long)g_secs[i].off,
               (unsigned long long)g_secs[i].size);
}

static void cmd_sec(const char *name) {
    int i = find_sec(name);
    if (i < 0) return; /* absent section == empty extraction, like objcopy */
    Sec *s = &g_secs[i];
    if (s->type == SHT_NOBITS || s->type == SHT_NULL) return;
    require_span(s->off, s->size, "section out of file");
    if (fwrite(g_buf + s->off, 1, (size_t)s->size, stdout) != s->size)
        die("section output failed");
}

static void cmd_syms(void) {
    for (uint16_t i = 0; i < g_nsecs; i++) {
        if (g_secs[i].type != SHT_SYMTAB) continue;
        uint64_t n = g_secs[i].size / SYM_ENTSZ;
        for (uint64_t j = 0; j < n; j++) {
            uint64_t e = g_secs[i].off + j * SYM_ENTSZ;
            uint8_t  info  = g_buf[e + 4];
            uint8_t  other = g_buf[e + 5];
            uint16_t shndx = rd16(e + 6);
            uint64_t value = rd64(e + 8);
            uint64_t size  = rd64(e + 16);
            const char *sname = (shndx < g_nsecs && rd32(e) == 0 &&
                                 (info & 0xf) == 3 /* STT_SECTION */)
                                ? g_secs[shndx].name
                                : sym_name(i, j);
            printf("%016llx %llu type=%u bind=%u vis=%u ndx=%u %s\n",
                   (unsigned long long)value, (unsigned long long)size,
                   info & 0xf, info >> 4, other & 0x3, shndx, sname);
        }
    }
}

static void cmd_relocs(void) {
    for (uint16_t i = 0; i < g_nsecs; i++) {
        if (!is_reloc(&g_secs[i])) continue;
        uint32_t symtab = g_secs[i].link;
        if (symtab >= g_nsecs) die("rela has bad symtab link");
        uint64_t stride = g_secs[i].entsize;
        uint64_t n = g_secs[i].size / stride;
        for (uint64_t j = 0; j < n; j++) {
            uint64_t e = g_secs[i].off + j * stride;
            uint64_t off    = rd64(e);
            uint64_t info   = rd64(e + 8);
            int64_t  addend = g_secs[i].type == SHT_RELA ? (int64_t)rd64(e + 16) : 0;
            uint32_t sym  = (uint32_t)(info >> 32);
            uint32_t type = (uint32_t)info;
            const char *sname = sym_name(symtab, sym);
            if (!sname[0]) {
                /* STT_SECTION symbols are unnamed: show the section. */
                uint64_t se = g_secs[symtab].off + (uint64_t)sym * SYM_ENTSZ;
                uint16_t shndx = rd16(se + 6);
                if (shndx < g_nsecs) sname = g_secs[shndx].name;
            }
            printf("%s %016llx type=%u %s%+lld%s\n", g_secs[i].name,
                   (unsigned long long)off, type, sname, (long long)addend,
                   g_secs[i].type == SHT_REL ? " (implicit addend)" : "");
        }
    }
}

/* ---------------------------------------------------------------- diff --
 * Normalized structural comparison of two ELF64 objects. Layout details that do not
 * change meaning (file offsets, section order, symbol-table order, string
 * table packing) are ignored.  What is compared:
 *   - ELF type, machine, ABI, flags and entry address;
 *   - set of sections by name: type, flags, alignment, size, raw contents (except symtab/
 *     strtab/rela/nobits, whose meaning is covered by the normalized
 *     symbol and relocation views);
 *   - normalized symbol lines (value size type bind vis sec name), as a
 *     sorted multiset;
 *   - normalized relocation lines (sec offset type sym addend), as a
 *     sorted multiset.
 * Exit: 0 equal in this view, 1 different or invalid, 2 usage error.
 * This view is not a proof of behavioral equivalence of arbitrary programs.
 */

typedef struct {
    char    *name;
    uint32_t type;
    uint64_t flags;
    uint64_t align;
    uint64_t size;
    uint8_t *bytes;   /* NULL when contents are not raw-compared */
} DSec;

typedef struct {
    uint64_t header[5];
    DSec  *secs;   size_t nsecs;
    char **syms;   size_t nsyms;
    char **relocs; size_t nrelocs;
} Snap;

static int cmp_dsec_name(const void *a, const void *b);

static char *dstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (!p) die("out of memory");
    memcpy(p, s, n);
    return p;
}

/* Never truncate a name in a comparison or fingerprint. Escape separators
 * and control bytes so an ELF string cannot impersonate normalized fields. */
static char *norm_name(const char *s) {
    static const char hex[] = "0123456789abcdef";
    size_t len = strlen(s);
    if (len > (SIZE_MAX - 1) / 4) die("ELF name too large");
    char *out = malloc(len * 4 + 1), *p = out;
    if (!out) die("out of memory");
    while (*s) {
        unsigned char c = (unsigned char)*s++;
        if (c > 0x20 && c < 0x7f && c != '\\') *p++ = (char)c;
        else { *p++ = '\\'; *p++ = 'x'; *p++ = hex[c >> 4]; *p++ = hex[c & 15]; }
    }
    *p = 0;
    return out;
}

static char *format_line(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (len < 0 || (uintmax_t)len >= SIZE_MAX) die("comparison line too large");
    char *out = malloc((size_t)len + 1);
    if (!out) die("out of memory");
    va_start(ap, fmt);
    int written = vsnprintf(out, (size_t)len + 1, fmt, ap);
    va_end(ap);
    if (written != len) die("comparison formatting failed");
    return out;
}

static void append_line(char ***lines, size_t *count, size_t *cap, char *line) {
    if (*count == *cap) {
        if (*cap > SIZE_MAX / sizeof(char *) / 2) die("too many comparison records");
        size_t next = *cap ? *cap * 2 : 64;
        char **p = realloc(*lines, next * sizeof(char *));
        if (!p) die("out of memory");
        *lines = p; *cap = next;
    }
    (*lines)[(*count)++] = line;
}

static const char *shndx_name(uint16_t shndx) {
    static char reserved[32];
    if (shndx == 0)      return "UND";
    if (shndx == 0xfff1) return "ABS";
    if (shndx == 0xfff2) return "COMMON";
    if (shndx < g_nsecs) return g_secs[shndx].name;
    snprintf(reserved, sizeof(reserved), "RESERVED:%u", shndx);
    return reserved;
}

static void snap_take(const char *path, Snap *sn) {
    load(path);
    sn->header[0] = rd16(0x10);
    sn->header[1] = rd16(0x12);
    sn->header[2] = (uint64_t)g_buf[7] | ((uint64_t)g_buf[8] << 8);
    sn->header[3] = rd32(0x30);
    sn->header[4] = rd64(0x18);
    sn->nsecs = 0;
    sn->secs  = calloc(g_nsecs ? g_nsecs : 1, sizeof(DSec));
    if (!sn->secs) die("out of memory");
    for (uint16_t i = 0; i < g_nsecs; i++) {
        if (g_secs[i].type == SHT_NULL) continue;
        if (!g_secs[i].name[0]) die("unnamed sections unsupported by comparator");
        DSec *d = &sn->secs[sn->nsecs++];
        d->name = dstrdup(g_secs[i].name);
        d->type = g_secs[i].type;
        d->flags = g_secs[i].flags;
        d->align = g_secs[i].align;
        d->size = g_secs[i].size;
        d->bytes = NULL;
        if (g_secs[i].type != SHT_SYMTAB && g_secs[i].type != 3 /*STRTAB*/ &&
            !is_reloc(&g_secs[i]) && g_secs[i].type != 8 /*NOBITS*/ &&
            g_secs[i].size > 0) {
            require_span(g_secs[i].off, g_secs[i].size, "section out of file");
            d->bytes = malloc(g_secs[i].size);
            if (!d->bytes) die("out of memory");
            memcpy(d->bytes, g_buf + g_secs[i].off, g_secs[i].size);
        }
    }
    qsort(sn->secs, sn->nsecs, sizeof(DSec), cmp_dsec_name);
    for (size_t i = 1; i < sn->nsecs; i++)
        if (!strcmp(sn->secs[i - 1].name, sn->secs[i].name))
            die("duplicate section names unsupported by comparator");

    /* normalized symbols */
    size_t cap = 64; sn->nsyms = 0;
    sn->syms = malloc(cap * sizeof(char *));
    if (!sn->syms) die("out of memory");
    for (uint16_t i = 0; i < g_nsecs; i++) {
        if (g_secs[i].type != SHT_SYMTAB) continue;
        uint64_t n = g_secs[i].size / SYM_ENTSZ;
        for (uint64_t j = 0; j < n; j++) {
            uint64_t e = g_secs[i].off + j * SYM_ENTSZ;
            uint8_t  info  = g_buf[e + 4];
            uint8_t  other = g_buf[e + 5];
            uint16_t shndx = rd16(e + 6);
            uint64_t value = rd64(e + 8);
            uint64_t size  = rd64(e + 16);
            const char *nm = (shndx < g_nsecs && rd32(e) == 0 &&
                              (info & 0xf) == 3 /* STT_SECTION */)
                             ? g_secs[shndx].name
                             : sym_name(i, j);
            char *sec = norm_name(shndx_name(shndx)), *name = norm_name(nm);
            const char *kind = shndx && shndx < g_nsecs ? "section" : "special";
            char *line = format_line(
                     "%016llx %llu type=%u bind=%u vis=%u sec_kind=%s sec=%s %s",
                     (unsigned long long)value, (unsigned long long)size,
                     info & 0xf, info >> 4, other & 0x3, kind, sec, name);
            free(sec); free(name);
            append_line(&sn->syms, &sn->nsyms, &cap, line);
        }
    }

    /* normalized relocations */
    cap = 64; sn->nrelocs = 0;
    sn->relocs = malloc(cap * sizeof(char *));
    if (!sn->relocs) die("out of memory");
    for (uint16_t i = 0; i < g_nsecs; i++) {
        if (!is_reloc(&g_secs[i])) continue;
        uint32_t symtab = g_secs[i].link;
        if (symtab >= g_nsecs) die("rela has bad symtab link");
        uint64_t stride = g_secs[i].entsize;
        uint64_t n = g_secs[i].size / stride;
        for (uint64_t j = 0; j < n; j++) {
            uint64_t e = g_secs[i].off + j * stride;
            uint64_t off    = rd64(e);
            uint64_t info   = rd64(e + 8);
            int64_t  addend = g_secs[i].type == SHT_RELA ? (int64_t)rd64(e + 16) : 0;
            uint32_t sym  = (uint32_t)(info >> 32);
            uint32_t type = (uint32_t)info;
            const char *nm = sym_name(symtab, sym);
            if (!nm[0]) {
                uint64_t se = g_secs[symtab].off + (uint64_t)sym * SYM_ENTSZ;
                uint16_t shndx = rd16(se + 6);
                if (shndx < g_nsecs) nm = g_secs[shndx].name;
            }
            char *sec = norm_name(g_secs[i].name), *name = norm_name(nm);
            char *target = norm_name(g_secs[g_secs[i].info].name);
            uint64_t se = g_secs[symtab].off + (uint64_t)sym * SYM_ENTSZ;
            uint16_t ndx = rd16(se + 6);
            char *symsec = norm_name(shndx_name(ndx));
            const char *kind = ndx && ndx < g_nsecs ? "section" : "special";
            /* A referenced LOCAL is not merely bookkeeping: its definition
             * contributes to relocation meaning even though diff ignores
             * unreferenced local declarations. */
            char *line = format_line(
                     "%s target=%s %016llx type=%u %s%+lld ref=%u/%u/%s/%s/%016llx/%llu",
                     sec, target, (unsigned long long)off, type, name, (long long)addend,
                     g_buf[se + 4], g_buf[se + 5], kind, symsec,
                     (unsigned long long)rd64(se + 8), (unsigned long long)rd64(se + 16));
            free(sec); free(name); free(target); free(symsec);
            append_line(&sn->relocs, &sn->nrelocs, &cap, line);
        }
    }
}

static void snap_free(Snap *sn) {
    for (size_t i = 0; i < sn->nsecs; i++) { free(sn->secs[i].name); free(sn->secs[i].bytes); }
    for (size_t i = 0; i < sn->nsyms; i++) free(sn->syms[i]);
    for (size_t i = 0; i < sn->nrelocs; i++) free(sn->relocs[i]);
    free(sn->secs); free(sn->syms); free(sn->relocs);
    memset(sn, 0, sizeof(*sn));
}

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static DSec *dsec_find(Snap *sn, const char *name) {
    for (size_t i = 0; i < sn->nsecs; i++)
        if (!strcmp(sn->secs[i].name, name)) return &sn->secs[i];
    return NULL;
}

/* Report lines present in one sorted multiset and not the other. */
static int diff_lines(const char *tag, char **a, size_t na, char **b, size_t nb) {
    int diffs = 0;
    size_t i = 0, j = 0;
    qsort(a, na, sizeof(char *), cmp_str);
    qsort(b, nb, sizeof(char *), cmp_str);
    while (i < na || j < nb) {
        int c = (i >= na) ? 1 : (j >= nb) ? -1 : strcmp(a[i], b[j]);
        if (c < 0)      { printf("%s only in A: %s\n", tag, a[i++]); diffs = 1; }
        else if (c > 0) { printf("%s only in B: %s\n", tag, b[j++]); diffs = 1; }
        else            { i++; j++; }
    }
    return diffs;
}

/* Normalized linkage view (looser than `digest`, which includes all locals):
 *  - an EMPTY section missing on the other side is not a divergence
 *    (e.g. basm emits a zero-size .note.GNU-stack marker; nasm does not);
 *  - unreferenced LOCAL declarations are omitted; GLOBAL/WEAK symbols are
 *    compared, and every relocation binds its referenced symbol definition;
 *  - section bytes, metadata and normalized relocations are compared.
 * digest-equal ⇒ diff-equal still holds. Author: F E R M I ∞ H A R T. */
static int sym_is_local(const char *line) {
    const char *bind = strstr(line, " bind=");
    return bind && !strncmp(bind, " bind=0 ", 8);
}

static size_t filter_global_syms(char **syms, size_t n) {
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        if (!sym_is_local(syms[i])) syms[k++] = syms[i];
        else free(syms[i]);
    }
    return k;
}

static int cmd_diff(const char *pa, const char *pb) {
    Snap A, B;
    snap_take(pa, &A);
    snap_take(pb, &B);
    int diffs = 0;
    static const char *header_fields[] = {"type", "machine", "ABI", "flags", "entry"};
    for (unsigned i = 0; i < 5; i++)
        if (A.header[i] != B.header[i]) {
            printf("ELF %s: %llu != %llu\n", header_fields[i],
                   (unsigned long long)A.header[i], (unsigned long long)B.header[i]);
            diffs++;
        }

    for (size_t i = 0; i < A.nsecs; i++) {
        DSec *a = &A.secs[i], *b = dsec_find(&B, a->name);
        if (!b) {
            if (a->size == 0) continue;   /* empty marker section */
            printf("section only in A: %s\n", a->name); diffs++; continue;
        }
        if (a->type != b->type) {
            printf("section %s: type %u != %u\n", a->name, a->type, b->type);
            diffs++;
            continue;
        }
        if (a->flags != b->flags) {
            printf("section %s: flags 0x%llx != 0x%llx\n", a->name,
                   (unsigned long long)a->flags, (unsigned long long)b->flags);
            diffs++;
        }
        if (a->align != b->align) {
            printf("section %s: alignment %llu != %llu\n", a->name,
                   (unsigned long long)a->align, (unsigned long long)b->align);
            diffs++;
        }
        /* String/table packing remains normalized, but BSS and empty
         * file-backed sections have meaningful sizes even without bytes. */
        int sized = a->type != SHT_SYMTAB && a->type != SHT_STRTAB &&
                    a->type != SHT_RELA && a->type != SHT_REL;
        if (sized && a->size != b->size) {
                printf("section %s: size %llu != %llu\n", a->name,
                       (unsigned long long)a->size, (unsigned long long)b->size);
                diffs++;
        } else if (a->bytes && b->bytes) {
            if (a->size && memcmp(a->bytes, b->bytes, a->size) != 0) {
                uint64_t k = 0;
                while (k < a->size && a->bytes[k] == b->bytes[k]) k++;
                printf("section %s: byte 0x%llx: %02x != %02x\n", a->name,
                       (unsigned long long)k, a->bytes[k], b->bytes[k]);
                diffs++;
            }
        }
    }
    for (size_t i = 0; i < B.nsecs; i++)
        if (!dsec_find(&A, B.secs[i].name)) {
            if (B.secs[i].size == 0) continue;   /* empty marker section */
            printf("section only in B: %s\n", B.secs[i].name);
            diffs++;
        }

    A.nsyms = filter_global_syms(A.syms, A.nsyms);
    B.nsyms = filter_global_syms(B.syms, B.nsyms);
    diffs += diff_lines("sym",   A.syms,   A.nsyms,   B.syms,   B.nsyms);
    diffs += diff_lines("reloc", A.relocs, A.nrelocs, B.relocs, B.nrelocs);

    snap_free(&A); snap_free(&B);
    return diffs ? 1 : 0;
}

/* -------------------------------------------------------------- digest --
 * Canonical per-section fingerprint.  SHA-256 implemented clean-room from
 * FIPS 180-4; no OpenSSL, no system crypto.  Hashes the same normalized
 * views in name-sorted order. Version 2 also binds section type, flags,
 * alignment and non-normalized size (including NOBITS). This is a
 * structural fingerprint of this documented view, not an equivalence
 * proof of arbitrary executable programs.
 */

typedef struct {
    uint32_t h[8];
    uint64_t nbits;
    uint8_t  blk[64];
    size_t   blen;
} Sha256;

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_init(Sha256 *s) {
    static const uint32_t iv[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    memcpy(s->h, iv, sizeof iv);
    s->nbits = 0;
    s->blen  = 0;
}

static void sha256_block(Sha256 *s, const uint8_t *p) {
    uint32_t w[64], a, b, c, d, e, f, g, h;
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15],7) ^ rotr32(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2],17) ^ rotr32(w[i-2],19)  ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=s->h[0]; b=s->h[1]; c=s->h[2]; d=s->h[3];
    e=s->h[4]; f=s->h[5]; g=s->h[6]; h=s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d;
    s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}

static void sha256_update(Sha256 *s, const void *data, size_t n) {
    const uint8_t *p = data;
    s->nbits += (uint64_t)n * 8;
    while (n) {
        size_t take = 64 - s->blen;
        if (take > n) take = n;
        memcpy(s->blk + s->blen, p, take);
        s->blen += take; p += take; n -= take;
        if (s->blen == 64) { sha256_block(s, s->blk); s->blen = 0; }
    }
}

static void sha256_final(Sha256 *s, uint8_t out[32]) {
    uint64_t nbits = s->nbits;
    uint8_t pad = 0x80;
    sha256_update(s, &pad, 1);
    uint8_t z = 0;
    while (s->blen != 56) sha256_update(s, &z, 1);
    uint8_t len[8];
    for (int i = 0; i < 8; i++) len[i] = (uint8_t)(nbits >> (56 - 8*i));
    sha256_update(s, len, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(s->h[i] >> 24);
        out[i*4+1] = (uint8_t)(s->h[i] >> 16);
        out[i*4+2] = (uint8_t)(s->h[i] >> 8);
        out[i*4+3] = (uint8_t)(s->h[i]);
    }
}

static void hex32(const uint8_t d[32], char out[65]) {
    static const char *hx = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i*2]   = hx[d[i] >> 4];
        out[i*2+1] = hx[d[i] & 0xf];
    }
    out[64] = 0;
}

static int cmp_dsec_name(const void *a, const void *b) {
    return strcmp(((const DSec *)a)->name, ((const DSec *)b)->name);
}

static void sha256_u64(Sha256 *s, uint64_t v) {
    uint8_t bytes[8];
    for (unsigned i = 0; i < 8; i++) bytes[i] = (uint8_t)(v >> (i * 8));
    sha256_update(s, bytes, sizeof(bytes));
}

static int cmd_digest(const char *path) {
    Snap sn;
    snap_take(path, &sn);
    qsort(sn.secs,  sn.nsecs,  sizeof(DSec),   cmp_dsec_name);
    qsort(sn.syms,  sn.nsyms,  sizeof(char *), cmp_str);
    qsort(sn.relocs,sn.nrelocs,sizeof(char *), cmp_str);

    Sha256 total;
    sha256_init(&total);
    sha256_update(&total, "elftool-structural-digest-v2", sizeof("elftool-structural-digest-v2"));
    for (unsigned i = 0; i < 5; i++) sha256_u64(&total, sn.header[i]);
    uint8_t d[32]; char hx[65];

    for (size_t i = 0; i < sn.nsecs; i++) {
        DSec *s = &sn.secs[i];
        sha256_update(&total, s->name, strlen(s->name) + 1);
        sha256_u64(&total, s->type);
        sha256_u64(&total, s->flags);
        sha256_u64(&total, s->align);
        if (s->type != SHT_SYMTAB && s->type != SHT_STRTAB &&
            s->type != SHT_RELA && s->type != SHT_REL)
            sha256_u64(&total, s->size);
        if (!s->bytes) continue;   /* symtab/strtab/rela/nobits: normalized below */
        Sha256 c; sha256_init(&c);
        sha256_update(&c, s->bytes, s->size);
        sha256_final(&c, d); hex32(d, hx);
        printf("%-20s %s %llu\n", s->name, hx, (unsigned long long)s->size);
        sha256_update(&total, d, 32);
    }

    Sha256 c; sha256_init(&c);
    for (size_t i = 0; i < sn.nsyms; i++)
        sha256_update(&c, sn.syms[i], strlen(sn.syms[i]) + 1);
    sha256_final(&c, d); hex32(d, hx);
    printf("%-20s %s %zu\n", "<syms>", hx, sn.nsyms);
    sha256_update(&total, d, 32);

    sha256_init(&c);
    for (size_t i = 0; i < sn.nrelocs; i++)
        sha256_update(&c, sn.relocs[i], strlen(sn.relocs[i]) + 1);
    sha256_final(&c, d); hex32(d, hx);
    printf("%-20s %s %zu\n", "<relocs>", hx, sn.nrelocs);
    sha256_update(&total, d, 32);

    sha256_final(&total, d); hex32(d, hx);
    printf("%-20s %s\n", "TOTAL", hx);
    snap_free(&sn);
    return 0;
}

/* --------------------------------------------------------------- audit --
 * Institutional invariants from ADR-000 checked on every object:
 *   A1  relocatable ET_REL (a sovereign build links its own world)
 *   A2  zero dynamic-linking machinery (.dynsym/.dynamic/.interp/PLT/GOT)
 *   A3  W^X: no section both writable and executable
 *   A4  every non-NOBITS section lies inside the file, and none overlap
 *   A5  every symbol references a valid section (or ABS/UND)
 *   A6  every relocation references a valid symbol and target section
 * Undefined global symbols are reported as INFO (legitimate in objects,
 * resolved by the sovereign linker), never as failure.
 * Exit: 0 all invariants hold, 1 violation.
 */

static int cmd_audit(void) {
    int fails = 0;

    /* A1: relocatable */
    if (rd16(0x10) != 1) {
        printf("AUDIT FAIL A1: e_type=%u is not ET_REL\n", rd16(0x10));
        fails++;
    }

    /* A2: sovereignty — no dynamic machinery by name or type */
    static const char *banned[] = {
        ".dynsym", ".dynstr", ".dynamic", ".interp",
        ".plt", ".got", ".got.plt", ".hash", ".gnu.hash", NULL
    };
    for (uint16_t i = 0; i < g_nsecs; i++) {
        for (int b = 0; banned[b]; b++)
            if (!strcmp(g_secs[i].name, banned[b])) {
                printf("AUDIT FAIL A2: dynamic section %s present\n",
                       g_secs[i].name);
                fails++;
            }
        if (g_secs[i].type == 6 /*DYNAMIC*/ || g_secs[i].type == 11 /*DYNSYM*/) {
            printf("AUDIT FAIL A2: section %s has dynamic type %u\n",
                   g_secs[i].name, g_secs[i].type);
            fails++;
        }
    }

    /* A3: W^X */
    for (uint16_t i = 0; i < g_nsecs; i++)
        if ((g_secs[i].flags & 0x1) && (g_secs[i].flags & 0x4)) {
            printf("AUDIT FAIL A3: section %s is writable+executable\n",
                   g_secs[i].name);
            fails++;
        }

    /* A4: bounds and overlap of file-backed sections */
    for (uint16_t i = 0; i < g_nsecs; i++) {
        Sec *a = &g_secs[i];
        if (a->type == 8 /*NOBITS*/ || a->size == 0) continue;
        if (!span_ok(a->off, a->size)) {
            printf("AUDIT FAIL A4: section %s exceeds file\n", a->name);
            fails++;
            continue;
        }
        for (uint16_t j = (uint16_t)(i + 1); j < g_nsecs; j++) {
            Sec *b = &g_secs[j];
            if (b->type == 8 || b->size == 0 || !span_ok(b->off, b->size)) continue;
            if (a->off < b->off + b->size && b->off < a->off + a->size) {
                printf("AUDIT FAIL A4: sections %s and %s overlap\n",
                       a->name, b->name);
                fails++;
            }
        }
    }

    /* A5 + INFO undefined globals */
    for (uint16_t i = 0; i < g_nsecs; i++) {
        if (g_secs[i].type != SHT_SYMTAB) continue;
        if (g_secs[i].link >= g_nsecs) {
            printf("AUDIT FAIL A5: symtab has bad strtab link\n");
            fails++;
            continue;
        }
        uint64_t n = g_secs[i].size / SYM_ENTSZ;
        for (uint64_t j = 0; j < n; j++) {
            uint64_t e = g_secs[i].off + j * SYM_ENTSZ;
            uint8_t  info  = g_buf[e + 4];
            uint16_t shndx = rd16(e + 6);
            const char *nm = sym_name(i, j);
            if (shndx != 0 && shndx != 0xfff1 && shndx >= g_nsecs) {
                printf("AUDIT FAIL A5: symbol %s has bad shndx %u\n", nm, shndx);
                fails++;
            }
            if (shndx == 0 && nm[0] && (info >> 4) == 1 /*GLOBAL*/)
                printf("AUDIT INFO: undefined global %s\n", nm);
        }
    }

    /* A6: relocation integrity */
    for (uint16_t i = 0; i < g_nsecs; i++) {
        if (!is_reloc(&g_secs[i])) continue;
        uint32_t symtab = g_secs[i].link;
        uint32_t target = g_secs[i].info;
        if (symtab >= g_nsecs || g_secs[symtab].type != SHT_SYMTAB) {
            printf("AUDIT FAIL A6: %s has bad symtab link\n", g_secs[i].name);
            fails++;
            continue;
        }
        if (target >= g_nsecs) {
            printf("AUDIT FAIL A6: %s has bad target section\n", g_secs[i].name);
            fails++;
        }
        uint64_t nsym = g_secs[symtab].size / SYM_ENTSZ;
        uint64_t stride = g_secs[i].entsize;
        uint64_t n = g_secs[i].size / stride;
        for (uint64_t j = 0; j < n; j++) {
            uint64_t e = g_secs[i].off + j * stride;
            uint32_t sym = (uint32_t)(rd64(e + 8) >> 32);
            if (sym >= nsym) {
                printf("AUDIT FAIL A6: %s reloc %llu has bad symbol index %u\n",
                       g_secs[i].name, (unsigned long long)j, sym);
                fails++;
            }
        }
    }

    if (fails) {
        printf("AUDIT FAIL: %d violation(s)\n", fails);
        return 1;
    }
    printf("AUDIT OK: A1-A6 hold (%u sections)\n", g_nsecs);
    return 0;
}

/* --------------------------------------------------------------- notes --
 * Walk every SHT_NOTE / ".note*" section and print each entry:
 * owner name, type, and descriptor (hex, plus ASCII when printable).
 * This is how auditors read the toolchain DNA embedded in objects.
 */

static void print_desc(const uint8_t *d, uint32_t n) {
    int printable = n > 0;
    for (uint32_t i = 0; i < n; i++)
        if (d[i] < 0x20 || d[i] > 0x7e) { printable = 0; break; }
    printf("    desc(%u) = ", n);
    for (uint32_t i = 0; i < n; i++) printf("%02x", d[i]);
    if (printable) {
        printf("  \"");
        fwrite(d, 1, n, stdout);
        printf("\"");
    }
    printf("\n");
}

static int cmd_notes(void) {
    int found = 0;
    /* Historical BearBasm sources use PROGBITS sections named .note.*.
     * Validate those only for this explicitly requested interpretation;
     * arbitrary PROGBITS payloads are not ELF note records in other commands.
     * Validate the complete view before printing any successful records. */
    for (uint16_t i = 0; i < g_nsecs; i++) {
        Sec *s = &g_secs[i];
        if (s->type == SHT_NOTE || strncmp(s->name, ".note", 5) == 0)
            validate_notes(s);
    }
    for (uint16_t i = 0; i < g_nsecs; i++) {
        Sec *s = &g_secs[i];
        if (s->type != 7 /*SHT_NOTE*/ && strncmp(s->name, ".note", 5) != 0)
            continue;
        found++;
        printf("%s:\n", s->name);
        if (s->size == 0) { printf("    (empty)\n"); continue; }
        uint64_t p = 0;
        while (p < s->size) {
            Note n = note_at(s, p);
            printf("  owner=\"%s\" type=%u\n", n.owner, n.type);
            print_desc(n.desc, n.descsz);
            p = n.next;
        }
    }
    if (!found) {
        printf("no note sections\n");
        return 1;
    }
    return 0;
}

/* ---- attest: independent parsing of the attestation chain ----------------
 * Hashes are recomputed with elftool's separate SHA-256 implementation and
 * Ed25519 signatures use the shared signer API. This checks recorded evidence,
 * not assembler semantics or the independence of the underlying crypto.
 * --trusted-key pins an external signer; without it a signature only checks
 * integrity against the public key carried inside the proof itself.
 * Given several proofs in toolchain order, also checks custody linkage:
 * proof[i].output_sha256 must equal proof[i+1].tool_sha256 (the binary a
 * stage produced is exactly the tool the next stage ran).
 * Author: F E R M I ∞ H A R T. */
#include "sign.h"
#include <sys/stat.h>
#include <unistd.h>

#define ATTEST_ARTIFACT_MAX ((uint64_t)1 << 30)
#define ATTEST_SOURCE_MAX ((uint64_t)16 * 1024 * 1024)
#define ATTEST_BINARY_MAX ((uint64_t)64 * 1024 * 1024)
#define ATTEST_CLOSURE_MAX ((uint64_t)128 * 1024 * 1024)

/* Bounded regular-file input, including a preflight to reject static FIFOs.
 * Concurrent hostile directory/inode replacement before fopen is outside this
 * pathname contract; it is not a race-proof open primitive. */
static FILE *attest_open_regular(const char *path,uint64_t limit,uint64_t *size) {
    struct stat before,after;
    if(!path || stat(path,&before)!=0 || !S_ISREG(before.st_mode) || before.st_size<0 ||
       (uint64_t)before.st_size>limit)return NULL;
    FILE *f=fopen(path,"rb");if(!f)return NULL;
    if(fstat(fileno(f),&after)!=0 || !S_ISREG(after.st_mode) || after.st_size<0 ||
       (uint64_t)after.st_size>limit || before.st_dev!=after.st_dev || before.st_ino!=after.st_ino){
        fclose(f);return NULL;
    }
    if(size)*size=(uint64_t)after.st_size;
    return f;
}

static char *attest_read(const char *path, size_t *n_out) {
    FILE *f = attest_open_regular(path,SIGN_ATTESTATION_MAX_BYTES,NULL);
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0 || (unsigned long long)n > SIGN_ATTESTATION_MAX_BYTES ||
        fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char *b = malloc((size_t)n + 1);
    if (!b) { fclose(f); return NULL; }
    size_t got = fread(b, 1, (size_t)n, f);
    int extra = fgetc(f), bad = ferror(f);
    if (fclose(f) != 0) bad = 1;
    if (got != (size_t)n || extra != EOF || bad) { free(b); return NULL; }
    b[n] = 0;
    if (n_out) *n_out = (size_t)n;
    return b;
}

/* Fetch "key: value" from the proof body into val (NUL-terminated). */
static int attest_value(const char *body, const char *key, char *val, size_t cap) {
    size_t klen = strlen(key);
    for (const char *p = body; *p;) {
        const char *end = strchr(p, '\n');
        if (!end) return 0;
        size_t n = (size_t)(end-p);
        if (n >= klen+2 && !memcmp(p, key, klen) && p[klen] == ':' && p[klen+1] == ' ') {
            size_t len = n-klen-2;
            if (!len || len >= cap) return 0;
            memcpy(val, p+klen+2, len); val[len] = 0;
            return 1;
        }
        p = end+1;
    }
    return 0;
}

static int attest_hex32(const char *hex, uint8_t out[32]) {
    if (strlen(hex) != 64) return 0;
    for (int i = 0; i < 32; i++) {
        unsigned v = 0;
        for (int j = 0; j < 2; j++) {
            char c = hex[i*2+j]; v <<= 4;
            if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
            else return 0;
        }
        out[i] = (uint8_t)v;
    }
    return 1;
}

/* INV-589: independent v3 schema check, before the permissive v2 reader.
 * Reject duplicate/unknown fields and truncation; no evidence may follow the
 * signature boundary. sign.c's optional PQC trailer is only a placeholder. */
static int attest_v3_fields(const char *body) {
    static const char *keys[] = {
        "tool", "tool_sha256", "source_path", "source_sha256", "output_path",
        "output_sha256", "output_format", "merkle_node_id", "build_epoch",
        "policy", "target_profile", "bootstrap", "signature",
        "ddc_compiler_sha256", "ddc_compiler_path", "signature_alg", "signature_pub",
        "signature_pqc_alg", "signature_pqc_pub", "signature_pqc"
    };
    static const size_t limits[] = {4,64,1023,64,1023,64,63,64,20,63,31,31,128,64,1023,31,64,31,64,128};
    int present[20]={0}, in_signature=0, is_unsigned=0;
    const char *line=strchr(body,'\n')+1;
    while(*line){
        const char *end=strchr(line,'\n');
        if(!end)return 0;
        int field=-1;
        for(int i=0;i<20;i++){
            size_t k=strlen(keys[i]);
            if((size_t)(end-line)>k+2 && !memcmp(line,keys[i],k) && line[k]==':' && line[k+1]==' '){
                field=i; break;
            }
        }
        if(field<0 || present[field])return 0;
        const char *v=line+strlen(keys[field])+2;
        size_t len=(size_t)(end-v);
        if(len>limits[field])return 0;
        char value[1024]; memcpy(value,v,len); value[len]=0;
        if(value[0]==' ')return 0;
        for(size_t i=0;i<len;i++)if((unsigned char)value[i]<32 || value[i]==127)return 0;
        int tail=field==12 || field>=15;
        if(in_signature && !tail)return 0;
        if(tail)in_signature=1;
        int hexlen=0;
        if(field==1||field==3||field==5||field==7||field==13||field==16||field==18)hexlen=64;
        if(field==12){is_unsigned=!strcmp(value,"unsigned"); if(!is_unsigned)hexlen=128;}
        if(field==19)hexlen=128;
        if(hexlen){
            if(len!=(size_t)hexlen)return 0;
            for(size_t i=0;i<len;i++)if(!((value[i]>='0'&&value[i]<='9')||(value[i]>='a'&&value[i]<='f')))return 0;
        }
        if(field==0 && strcmp(value,"basm"))return 0;
        if(field==8){
            for(size_t i=0;i<len;i++)if(value[i]<'0'||value[i]>'9')return 0;
            if(len==20 && strcmp(value,"18446744073709551615")>0)return 0;
        }
        if(field==15 && (strcmp(value,"ed25519-over-sha256") || present[12]))return 0;
        if(field==16 && !present[15])return 0;
        if(field==12 && !is_unsigned && (!present[15]||!present[16]))return 0;
        if(field>=17 && !present[12])return 0;
        if(field==17 && strcmp(value,"dilithium3-placeholder"))return 0;
        present[field]=1; line=end+1;
    }
    for(int i=0;i<13;i++)if(!present[i])return 0;
    if(is_unsigned){for(int i=15;i<20;i++)if(present[i])return 0;}
    else if(!present[15] || !present[16])return 0;
    return present[17]==present[18] && present[18]==present[19];
}

static int attest_sha_file_limit(const char *path,uint64_t limit,uint8_t out[32]) {
    uint64_t remaining=0;
    FILE *f = attest_open_regular(path,limit,&remaining);
    if (!f) return 0;
    Sha256 s; sha256_init(&s);
    uint8_t buf[65536];int bad=0;
    while(remaining){
        size_t want=remaining>sizeof(buf)?sizeof(buf):(size_t)remaining;
        size_t n=fread(buf,1,want,f);if(n!=want){bad=1;break;}
        sha256_update(&s,buf,n);remaining-=n;
    }
    if(!bad && fgetc(f)!=EOF)bad=1;
    if(ferror(f))bad=1;
    if(fclose(f)!=0)bad=1;
    if(bad)return 0;
    sha256_final(&s, out);
    return 1;
}
static int attest_sha_file(const char *path,uint8_t out[32]) {
    return attest_sha_file_limit(path,ATTEST_ARTIFACT_MAX,out);
}

typedef struct {
    uint64_t count;
    uint8_t root[32],expanded[32],configuration[32];
} AttestV4;

static int attest_decimal(const char *p,size_t n,uint64_t *out) {
    if(!n || n>20 || (n>1 && *p=='0'))return 0;
    uint64_t value=0;
    for(size_t i=0;i<n;i++){
        if(p[i]<'0' || p[i]>'9')return 0;
        unsigned digit=(unsigned)(p[i]-'0');
        if(value>(UINT64_MAX-digit)/10)return 0;
        value=value*10+digit;
    }
    *out=value;return 1;
}

static int attest_hex_bytes(const char *p,size_t n,uint8_t *out,size_t bytes) {
    if(n!=bytes*2)return 0;
    for(size_t i=0;i<bytes;i++){
        unsigned value=0;
        for(unsigned j=0;j<2;j++){
            char c=p[2*i+j];value<<=4;
            if(c>='0' && c<='9')value|=(unsigned)(c-'0');
            else if(c>='a' && c<='f')value|=(unsigned)(c-'a'+10);
            else return 0;
        }
        out[i]=(uint8_t)value;
    }
    return 1;
}

static void attest_sha_u64(Sha256 *s,uint64_t value) {
    uint8_t le[8];for(unsigned i=0;i<8;i++)le[i]=(uint8_t)(value>>(i*8));
    sha256_update(s,le,sizeof(le));
}

static int attest_dependency_record(const char *p,size_t n,uint8_t *kind,
                                    uint64_t *size,uint8_t hash[32],char path[1024]) {
    if(n<71 || p[0]<'1' || p[0]>'3' || p[1]!=' ')return 0;
    *kind=(uint8_t)(p[0]-'0');p+=2;n-=2;
    const char *space=(const char*)memchr(p,' ',n);if(!space)return 0;
    size_t digits=(size_t)(space-p);
    if(!attest_decimal(p,digits,size))return 0;
    p=space+1;n-=digits+1;
    if(n<67 || p[64]!=' ' || !attest_hex_bytes(p,64,hash,32))return 0;
    p+=65;n-=65;
    if(!n || (n&1) || n>2046 || !attest_hex_bytes(p,n,(uint8_t*)path,n/2) ||
       memchr(path,0,n/2))return 0;
    path[n/2]=0;return 1;
}

static int attest_dependency_sha(const char *path,uint64_t size,uint8_t hash[32]) {
    uint64_t actual_size=0;
    FILE *f=attest_open_regular(path,size,&actual_size);if(!f)return 0;
    if(actual_size!=size){fclose(f);return 0;}
    Sha256 s;sha256_init(&s);uint8_t buf[65536];int ok=1;
    while(size){
        size_t want=size>sizeof(buf)?sizeof(buf):(size_t)size;
        size_t n=fread(buf,1,want,f);if(n!=want){ok=0;break;}
        sha256_update(&s,buf,n);size-=n;
    }
    if(ok && fgetc(f)!=EOF)ok=0;
    if(ferror(f))ok=0;
    if(fclose(f)!=0)ok=0;
    if(ok)sha256_final(&s,hash);
    return ok;
}

/* V4 records the locally consumed input closure. It does not establish source
 * semantics, a hermetic whole toolchain, or the truth of optional DDC metadata.
 * The root source must be first; all sizes/paths/hashes use canonical encodings. */
static int attest_v4_fields(const char *body,AttestV4 *proof) {
    char *base=(char*)malloc(32768);if(!base)return 0;
    memcpy(base,body,20);size_t used=20;int ok=1,seen=0,trailer=0;
    uint64_t records=0,total_bytes=0;Sha256 closure;uint8_t actual[32];
    char source_path[1024],source_hex[65];uint8_t source_digest[32];
    if(!attest_value(body,"source_path",source_path,sizeof(source_path)) ||
       !attest_value(body,"source_sha256",source_hex,sizeof(source_hex)) ||
       !attest_hex32(source_hex,source_digest))ok=0;
    const char *p=body+20;
    while(ok && *p){
        const char *end=strchr(p,'\n');if(!end){ok=0;break;}
        size_t n=(size_t)(end-p);const char *v=NULL;size_t vn=0;int field=0;
        if(n>=18 && !memcmp(p,"dependency_count: ",18)){field=1;v=p+18;vn=n-18;}
        else if(n>=17 && !memcmp(p,"dependency_root: ",17)){field=2;v=p+17;vn=n-17;}
        else if(n>=17 && !memcmp(p,"expanded_sha256: ",17)){field=3;v=p+17;vn=n-17;}
        else if(n>=22 && !memcmp(p,"configuration_sha256: ",22)){field=4;v=p+22;vn=n-22;}
        else if(n>=12 && !memcmp(p,"dependency: ",12)){field=5;v=p+12;vn=n-12;}
        if(field){
            if(trailer){ok=0;break;}
            if(field==1){
                if(seen || !attest_decimal(v,vn,&proof->count) || !proof->count || proof->count>4096){ok=0;break;}
                seen=1;sha256_init(&closure);
                sha256_update(&closure,"basm-input-closure-v1",sizeof("basm-input-closure-v1"));
                attest_sha_u64(&closure,proof->count);
            }else if(field<=4){
                int expected=(1<<(field-1))-1;
                uint8_t *dest=field==2?proof->root:field==3?proof->expanded:proof->configuration;
                if(seen!=expected || !attest_hex_bytes(v,vn,dest,32)){ok=0;break;}
                seen|=1<<(field-1);
            }else{
                uint8_t kind,digest[32];uint64_t size;char path[1024];
                if(seen!=15 || records>=proof->count ||
                   !attest_dependency_record(v,vn,&kind,&size,digest,path)){ok=0;break;}
                uint64_t limit=kind==3?ATTEST_BINARY_MAX:ATTEST_SOURCE_MAX;
                if(size>limit || size>ATTEST_CLOSURE_MAX-total_bytes){ok=0;break;}
                total_bytes+=size;
                if(records==0){
                    if(kind!=1 || strcmp(path,source_path) || memcmp(digest,source_digest,32)){ok=0;break;}
                }else if(kind==1){ok=0;break;}
                sha256_update(&closure,&kind,1);attest_sha_u64(&closure,size);
                sha256_update(&closure,path,strlen(path)+1);sha256_update(&closure,digest,32);
                records++;
                uint8_t file_digest[32];
                if(!attest_dependency_sha(path,size,file_digest) || memcmp(file_digest,digest,32)){ok=0;break;}
            }
        }else{
            if(n>=10 && (!memcmp(p,"signature:",10) || !memcmp(p,"signature_",10)))trailer=1;
            if(n>=13 && !memcmp(p,"signature_pqc",13)){ok=0;break;}
            if(n+1>32767-used){ok=0;break;}
            memcpy(base+used,p,n+1);used+=n+1;
        }
        p=end+1;
    }
    if(ok && (seen!=15 || records!=proof->count))ok=0;
    if(ok){sha256_final(&closure,actual);if(memcmp(actual,proof->root,32))ok=0;}
    base[used]=0;
    if(ok && !attest_v3_fields(base))ok=0;
    free(base);return ok;
}

static void attest_hexprint(const uint8_t h[32]) {
    for (int i = 0; i < 32; i++) printf("%02x", h[i]);
}

/* Verify one proof file.  prev_out: output hash of the previous proof in the
 * chain (or NULL).  Returns 0 ok, 1 fail; stores this proof's recorded output
 * hash into out_link on success. */
static int attest_one(const char *path,int strict,const uint8_t *prev_out,
                      const uint8_t *trusted_pub,const uint8_t *expected_tool,
                      uint8_t out_link[32]) {
    size_t n = 0;
    char *body = attest_read(path, &n);
    int fails = 0;
    if (!body) { printf("ATTEST FAIL %s: cannot read\n", path); return 1; }
    int v3=n>=20 && !memcmp(body,"basm attestation v3\n",20);
    int v4=n>=20 && !memcmp(body,"basm attestation v4\n",20);
    int signed_state=sign_attestation_signature_state(body,n);
    AttestV4 closure;memset(&closure,0,sizeof(closure));
    if (n<20 || strlen(body)!=n || signed_state<0 || (!v3 && !v4 &&
        memcmp(body,"basm attestation v2\n",20) && memcmp(body,"bear attestation v2\n",20))) {
        printf("ATTEST FAIL %s: bad header\n", path);
        free(body); return 1;
    }
    /* The signature and parsed fields always refer to this one snapshot. Verify
     * it before opening any source/output/dependency path named by the proof. */
    if(!signed_state && (strict || trusted_pub)){
        printf("ATTEST FAIL %s: unsigned proof rejected\n",path);free(body);return 1;
    }
    if(signed_state){
        uint8_t pub[32];
        if(sign_verify_attestation_buffer(body,n,trusted_pub,pub)!=0){
            printf("ATTEST FAIL %s: signature invalid or signer untrusted\n",path);free(body);return 1;
        }
        printf("ATTEST SIGNER %s: ed25519 pub ",path);attest_hexprint(pub);
        printf(trusted_pub?" (external anchor)\n":" (integrity only)\n");
    }else printf("ATTEST NOTE %s: unsigned proof\n",path);
    if ((v4 && !attest_v4_fields(body,&closure)) || (v3 && !attest_v3_fields(body)) ||
        (!v3 && !v4 && (strstr(body,"\npolicy") || strstr(body,"\ntarget_profile") || strstr(body,"\nbootstrap") ||
                        strstr(body,"\ndependency") || strstr(body,"\nexpanded_sha256") || strstr(body,"\nconfiguration_sha256")))) {
        printf("ATTEST FAIL %s: invalid attestation fields\n",path);
        free(body); return 1;
    }
    char tool_hex[80], src_path[1024], src_hex[80], out_path[1024], out_hex[80];
    char merkle_hex[80], sig[160];
    char fmt[64]="", policy[64]="", profile[32]="", bootstrap[32]="";
    if (!attest_value(body, "tool_sha256", tool_hex, sizeof(tool_hex)) ||
        !attest_value(body, "source_path", src_path, sizeof(src_path)) ||
        !attest_value(body, "source_sha256", src_hex, sizeof(src_hex)) ||
        !attest_value(body, "output_path", out_path, sizeof(out_path)) ||
        !attest_value(body, "output_sha256", out_hex, sizeof(out_hex)) ||
        !attest_value(body, "merkle_node_id", merkle_hex, sizeof(merkle_hex)) ||
        !attest_value(body, "signature", sig, sizeof(sig))) {
        printf("ATTEST FAIL %s: incomplete proof\n", path);
        free(body); return 1;
    }
    if(v3 || v4){
        if(!attest_value(body,"output_format",fmt,sizeof(fmt)) ||
           !attest_value(body,"policy",policy,sizeof(policy)) ||
           !attest_value(body,"target_profile",profile,sizeof(profile)) ||
           !attest_value(body,"bootstrap",bootstrap,sizeof(bootstrap)) ||
           (strcmp(fmt,"elf64") && strcmp(fmt,"bin")) || strcmp(policy,"basm-profile-v1") ||
           (strcmp(profile,"beyond") && strcmp(profile,"public")) ||
           (strcmp(bootstrap,"none") && strcmp(bootstrap,"ap-trampoline-v1")) ||
           (!strcmp(bootstrap,"ap-trampoline-v1") && strcmp(profile,"beyond"))) {
            printf("ATTEST FAIL %s: invalid attestation policy\n",path);
            free(body); return 1;
        }
    }
    uint8_t th[32], sh[32], oh[32], mh[32], calc[32];
    if (!attest_hex32(tool_hex, th) || !attest_hex32(src_hex, sh) ||
        !attest_hex32(out_hex, oh) || !attest_hex32(merkle_hex, mh)) {
        printf("ATTEST FAIL %s: malformed hash\n", path);
        free(body); return 1;
    }

    /* The --tool anchor is compared to the tool hash from the same authenticated
     * proof bytes. No second pathname read can substitute another proof. */
    if(expected_tool){
        if(memcmp(expected_tool,th,32)){
            printf("ATTEST FAIL %s: --tool hash mismatch\n",path);fails++;
        }else printf("ATTEST ANCHOR %s: tool binary matches\n",path);
    }

    /* V2 stays H(tool || src || out). V3 binds policy strings. V4 also binds
     * expanded/configuration hashes and the local dependency closure root. */
    Sha256 s; sha256_init(&s);
    if(v4)sha256_update(&s,"basm-attestation-v4",sizeof("basm-attestation-v4"));
    else if(v3)sha256_update(&s,"basm-attestation-v3",sizeof("basm-attestation-v3"));
    sha256_update(&s, th, 32); sha256_update(&s, sh, 32); sha256_update(&s, oh, 32);
    if(v3 || v4){
        sha256_update(&s,fmt,strlen(fmt)+1);
        sha256_update(&s,policy,strlen(policy)+1);
        sha256_update(&s,profile,strlen(profile)+1);
        sha256_update(&s,bootstrap,strlen(bootstrap)+1);
    }
    if(v4){
        sha256_update(&s,closure.expanded,32);sha256_update(&s,closure.configuration,32);
        sha256_update(&s,closure.root,32);
    }
    sha256_final(&s, calc);
    if (memcmp(calc, mh, 32)) { printf("ATTEST FAIL %s: merkle_node_id inconsistent\n", path); fails++; }

    /* 2. Recompute source/output hashes from disk when present. */
    uint8_t fh[32];
    if (attest_sha_file_limit(src_path,ATTEST_SOURCE_MAX,fh)) {
        if (memcmp(fh, sh, 32)) { printf("ATTEST FAIL %s: source hash mismatch (%s)\n", path, src_path); fails++; }
    } else if (strict) { printf("ATTEST FAIL %s: source missing (%s)\n", path, src_path); fails++; }
    else printf("ATTEST NOTE %s: source not on disk, recorded hash only (%s)\n", path, src_path);
    if (attest_sha_file(out_path, fh)) {
        if (memcmp(fh, oh, 32)) { printf("ATTEST FAIL %s: output hash mismatch (%s)\n", path, out_path); fails++; }
    } else if (strict) { printf("ATTEST FAIL %s: output missing (%s)\n", path, out_path); fails++; }
    else printf("ATTEST NOTE %s: output not on disk, recorded hash only (%s)\n", path, out_path);

    /* 3. Chain custody: previous stage's output must be this stage's tool. */
    if (prev_out) {
        if (memcmp(prev_out, th, 32)) { printf("ATTEST FAIL %s: chain broken (tool != previous output)\n", path); fails++; }
        else printf("ATTEST CHAIN %s: link ok\n", path);
    }

    memcpy(out_link, oh, 32);
    free(body);
    if (!fails) printf("ATTEST OK %s\n", path);
    return fails ? 1 : 0;
}

static int cmd_attest(int argc, char **argv) {
    int strict = 0; const char *toolbin = NULL,*trusted_path=NULL;
    const char *proofs[32]; int nproofs = 0;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--strict")) strict = 1;
        else if (!strcmp(argv[i], "--tool")) { if (++i >= argc) die("--tool needs a path"); toolbin = argv[i]; }
        else if (!strcmp(argv[i], "--trusted-key")) {
            if (++i >= argc) die("--trusted-key needs a public-key path");
            trusted_path=argv[i];strict=1;
        }
        else if(argv[i][0]=='-' && argv[i][1]=='-')die("unknown attest option");
        else { if (nproofs >= 32) die("too many proofs"); proofs[nproofs++] = argv[i]; }
    }
    if (!nproofs) die("attest requires at least one proof file");
    uint8_t trusted_pub[32],tool_hash[32];
    if(trusted_path && sign_load_public_key(trusted_path,trusted_pub)!=0)die("cannot load trusted public key");
    if(toolbin && !attest_sha_file(toolbin,tool_hash))die("cannot hash --tool regular file within 1 GiB limit");
    int rc = 0; uint8_t link[32]; int have_link = 0;
    for (int i = 0; i < nproofs; i++) {
        uint8_t next[32]={0};
        rc |= attest_one(proofs[i],strict,have_link?link:NULL,
                         trusted_path?trusted_pub:NULL,i==0&&toolbin?tool_hash:NULL,next);
        memcpy(link, next, 32); have_link = 1;
    }
    printf(rc ? "ATTEST RESULT: FAIL\n" : "ATTEST RESULT: PASS\n");
    return rc;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
            "usage: elftool secs|syms|relocs <obj>\n"
            "       elftool sec <obj> <name>\n"
            "       elftool diff <objA> <objB>   (exit 0 same, 1 differ)\n"
            "       elftool digest <obj>         (structural digest v2)\n"
            "       elftool audit <obj>          (ADR-000 invariants, exit 0/1)\n"
            "       elftool notes <obj>          (toolchain DNA in .note)\n"
            "       elftool attest [--strict] [--trusted-key PUB] [--tool BIN] <proof>...\n"
            "                                    (verify attestation chain)\n");
        return 2;
    }
    if (!strcmp(argv[1], "attest")) return cmd_attest(argc - 2, argv + 2);
    if (!strcmp(argv[1], "diff")) {
        if (argc < 4) die("diff requires two objects");
        return cmd_diff(argv[2], argv[3]);
    }
    if (!strcmp(argv[1], "digest")) return cmd_digest(argv[2]);
    if (!strcmp(argv[1], "audit")) { load(argv[2]); return cmd_audit(); }
    if (!strcmp(argv[1], "notes")) { load(argv[2]); return cmd_notes(); }
    load(argv[2]);
    if (!strcmp(argv[1], "secs"))   { cmd_secs();  return 0; }
    if (!strcmp(argv[1], "syms"))   { cmd_syms();  return 0; }
    if (!strcmp(argv[1], "relocs")) { cmd_relocs(); return 0; }
    if (!strcmp(argv[1], "sec")) {
        if (argc < 4) die("sec requires a section name");
        cmd_sec(argv[3]);
        return 0;
    }
    die("unknown command");
    return 2;
}
