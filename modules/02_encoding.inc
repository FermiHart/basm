/*
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ------------------------------------------------------------------ */
/* Memory operands                                                    */
/* ------------------------------------------------------------------ */
typedef struct {
    int  rip;        /* 1 = RIP-relative symbol reference */
    char sym[NAME_MAX];
    int  base, has_index, index, scale, has_disp;
    long disp;
    int  seg;        /* segment-override prefix byte (0 = none): gs=0x65 fs=0x64 */
    int  addr32;     /* 1 = 32-bit address size ([eax+ecx*4]) → 0x67 prefix */
    int  no_base;    /* 1 = pure displacement, no base reg (e.g. [gs:0x10]) */
    int  abs32s;     /* 1 = explicit 64-bit absolute memory reloc is signed */
    int  disp_has_sym;   /* 1 = disp32 needs an absolute reloc against a label */
    int  disp_sym_sec;   /* section of that label */
    int  disp_sym_glob;  /* label is global → named reloc */
    long disp_sym_off;   /* label's section-relative offset (for named addend) */
    char disp_sym_name[NAME_MAX];
} Mem;


static int g_bounded_sse;
static const uint8_t g_segment_prefix[] = {0x26,0x2e,0x36,0x3e,0x64,0x65};
static long sse_literal(const char *p, long limit) {
    char *end;
    while (char_in(*p," \t")) p++;
    if (!isdigit((unsigned char)*p)) die("SSE requires a literal unsigned integer");
    errno=0;
    long n=strtol(p,&end,p[0]=='0' && char_in(p[1],"xX") ? 16 : 10);
    while (char_in(*end," \t")) end++;
    if (errno || *end || n<0 || n>limit) die("SSE integer out of range or malformed");
    return n;
}
static void sse_disp32(long value) {
    if ((unsigned long)value+2147483648UL > 4294967295UL) die("SSE displacement out of signed 32-bit range");
}

static void parse_mem(const char *tok, Mem *out) {
    int prefetch=g_bounded_sse || (g_ntok && (!strcmp(g_tok[0],"prefetcht0") || !strcmp(g_tok[0],"movnti")));
    if (!validate_operand_len(tok)) die2("parse_mem: operand exceeds max length", tok);
    if (!validate_address_contents(tok)) die2("parse_mem: invalid operand chars", tok);

    Mem m; memset(&m,0,sizeof(m)); m.base=-1; m.scale=1;
    char buf[NAME_MAX];
    size_t operand_length=strlen(tok);
    if (operand_length>=sizeof(buf)) die("memory operand too long");
    memcpy(buf,tok,operand_length+1);
    if (buf[0] != '[') die2("expected memory operand", tok);
    char *p = buf+1; char *end = strchr(p, ']');
    if (!end) die2("unterminated memory operand", tok);
    if (prefetch && end[1]) die("prefetcht0: trailing memory operand text");
    *end = 0;
    while (*p==' ') p++;
    int force_abs = 0;
    if (!strncmp(p, "abs ", 4)) {
        force_abs = 1; m.abs32s = (g_bits == 64); p += 4; while (*p==' ') p++;
    }
    /* Segment override: [gs:disp], [fs:disp], etc. The "seg:" prefix
     * selects an override prefix byte and (for the common per-CPU form
     * [gs:0x10]) leaves a pure-displacement operand with no base reg.
     * Author: F E R M I ∞ H A R T. */
    {
        char *colon = strchr(p, ':');
        if (colon && (colon - p) <= 2) {
            char segname[3] = {0,0,0};
            int n = (int)(colon - p);
            for (int i=0;i<n && i<2;i++) segname[i] = p[i];
            int sg=seg_reg(segname); /* INV-740: same exact six names as segment MOV. */
            if (sg >= 0) { m.seg = g_segment_prefix[sg]; p = colon + 1; while(*p==' ')p++; }
        }
    }
    /* RIP-relative form: explicit [rel SYM], or a symbolic operand under
     * `default rel`. Registers and EQU constants retain absolute/base forms. */
    if (!force_abs && (!strncmp(p, "rel ", 4) || g_default_rel)) {
        int explicit_rel = !strncmp(p, "rel ", 4);
        if (explicit_rel) { p += 4; while(*p==' ')p++; }
        char sym[NAME_MAX]; int i=0;
        while ((isalnum((unsigned char)*p)||char_in(*p, "_.")) && i<NAME_MAX-1) sym[i++]=*p++;
        sym[i]=0;
        long ignored;
        if (i > 0 && !reg_find(sym) && !const_lookup(sym, &ignored)) {
            m.rip = 1;
            qualify(sym, m.sym);
            while(*p==' ')p++;
            if (prefetch && *p && !char_in(*p, "+-")) die("prefetcht0: malformed relative address");
            if (char_in(*p, "+-")) {
                int neg=(*p=='-'); p++;
                int hs=0,section=SEC_NONE,global=0; long offset=0; char name[NAME_MAX];
                long d=g_bounded_sse ? sse_literal(p,2147483648L) :
                    parse_expr_reloc(p,&hs,&section,&offset,name,&global);
                if (hs && (g_pass==2 || !g_fwd_unresolved))
                    die("relative memory addend must be absolute");
                m.disp=neg ? basm_expr_sub(0,d) : d; m.has_disp=1;
            }
            goto parsed;
        }
        if (explicit_rel) die2("rel requires a symbol", tok);
        p = buf + 1; while (*p==' ') p++;
    }
    /* base+index*scale+disp */
    int sign=1, seen_base=0;
    char displacement[NAME_MAX*3+1]; size_t displacement_len=0;
    displacement[0]=0;
    while (*p) {
        while(*p==' ')p++;
        if (*p==0) break;
        char comp[NAME_MAX]; int ci=0;
        int parentheses=0;
        while (*p && (parentheses || !char_in(*p, "+-")) && ci<NAME_MAX-1) {
            if (*p=='(') parentheses++;
            if (*p==')') parentheses--;
            comp[ci++]=*p++;
        }
        comp[ci]=0; while(ci>0&&comp[ci-1]==' ')comp[--ci]=0;
        if (g_bounded_sse && (!ci || (*p && !p[1]))) die("SSE malformed address component");
        if (ci>0) {
            char *star = strchr(comp,'*'); long scale=1; int scale_pending=0;
            if (star) {
                *star=0;
            }
            int cl=(int)strlen(comp); while(cl>0&&comp[cl-1]==' ')comp[--cl]=0;
            const Reg *r = reg_find(comp);
            if (r) {
                if (star) {
                    if (g_bounded_sse) scale=sse_literal(star+1,8);
                    else {
                        scale=parse_expr(star+1);
                        expr_basis_reduce(0);
                        scale_pending=g_expr_basis_pending && g_pass==1;
                        if (!scale_pending && (g_expr_basis_invalid || g_expr_basis_count))
                            die("address scale requires an absolute expression");
                    }
                }
                if (sign<0) die("address register cannot be subtracted");
                if (scale_pending) scale=1; /* sizing only; g_fwd_unresolved forces resolution */
                if (scale!=1 && scale!=2 && scale!=4 && scale!=8) die("invalid address register scale");
                /* Address-size: 64-bit regs are the default; 32-bit regs
                 * select the 0x67 address-size override (same ModRM/SIB
                 * numbering). Mixing sizes in one operand is illegal.
                 * Author: F E R M I ∞ H A R T. */
                int is32 = (r->size == 4);
                if (r->size != 4 && r->size != 8)
                    die2("address register must be 32- or 64-bit", tok);
                if ((seen_base || m.has_index) && m.addr32 != is32)
                    die2("mixed address register sizes", tok);
                if (is32) m.addr32 = 1;
                if (!seen_base && scale==1){ m.base=r->num; seen_base=1; }
                else {
                    if (m.has_index) die("too many address registers");
                    m.has_index=1; m.index=r->num; m.scale=(int)scale;
                }
            } else {
                /* Non-register disp component. If it had a `*`, it is a pure
                 * constant product (e.g. `511 * 8` = the PML4[511] index byte
                 * offset) — apply the scale to the constant. Author: F E R M I ∞ H A R T. */
                if (g_bounded_sse) {
                    if (star) die("SSE displacement cannot be scaled");
                    long dv=sse_literal(comp,2147483648L);
                    m.disp=sign<0 ? basm_expr_sub(m.disp,dv) : basm_expr_add(m.disp,dv);
                    sse_disp32(m.disp);
                } else {
                    /* INV-BASM-MEM-AFFINE-001: relocation bases belong to the
                     * complete displacement, not individual +/- components.
                     * Same-section label differences must cancel before the
                     * one-ELF-basis check; registers remain separately bounded. */
                    if (star) *star='*';
                    size_t len=strlen(comp);
                    if (len+4>sizeof(displacement)-displacement_len)
                        die("memory displacement expression exceeds max length");
                    displacement[displacement_len++]=sign<0?'-':'+';
                    displacement[displacement_len++]='(';
                    memcpy(displacement+displacement_len,comp,len); displacement_len+=len;
                    displacement[displacement_len++]=')'; displacement[displacement_len]=0;
                }
                m.has_disp=1;
            }
        }
        if (*p=='+'){sign=1;p++;} else if(*p=='-'){sign=-1;p++;}
    }
    if (!g_bounded_sse && displacement_len) {
        int hs=0, sc=SEC_NONE, gl=0; long of=0; char nm[NAME_MAX];
        m.disp=parse_expr_reloc(displacement,&hs,&sc,&of,nm,&gl);
        if (hs) {
            m.disp_has_sym=1; m.disp_sym_sec=sc; m.disp_sym_glob=gl; m.disp_sym_off=of;
            memcpy(m.disp_sym_name,nm,strlen(nm)+1);
        }
    }
    if (m.base<0) {
        /* No base register. Legal for:
         *  - a segment-override pure-displacement operand ([gs:0x10]), or
         *  - a pure absolute-address constant ([TRAMP_BASE+0x20]) used by
         *    fixed-address trampoline code.
         * Both encode as disp32 with no base. Author: F E R M I ∞ H A R T. */
        if (m.seg || m.has_index || m.has_disp) { m.no_base = 1; m.has_disp = 1; goto parsed; }
        die2("memory operand needs base register", tok);
    }
    /* INV-586: share the large result copy across all successful parse paths. */
parsed:
    /* SIB index=4 without REX.X means no index. An unscaled stack pointer
     * may be the base, but a scaled one must never disappear from the EA.
     * Retain the bounded SSE subset's existing explicit-index restriction. */
    if (m.has_index && m.index==4) {
        if (g_bounded_sse || m.scale!=1 || m.base<0 || m.base==4)
            die("stack pointer cannot be an address index");
        m.index=m.base; m.base=4;
    }
    /* disp32 is sign-extended for a 64-bit effective address. Address-size
     * override chooses the unsigned 32-bit form, regardless of `abs`. */
    m.abs32s=(g_bits==64 && !m.addr32);
    if (g_bounded_sse) {
        sse_disp32(m.disp);
        if (m.has_index && (m.index==4 || (m.scale!=1 && m.scale!=2 && m.scale!=4 && m.scale!=8))) die("SSE invalid index/scale");
    }
    memcpy(out,&m,sizeof(m)); return;
}

static void mem_rex_bits(Mem *m, int *rex_x, int *rex_b) {
    if (m->rip) { *rex_x=0; *rex_b=0; return; }
    *rex_x = (m->has_index && m->index>=8)?1:0;
    *rex_b = (m->base>=8)?1:0;
}
/* Single choke-point for memory operands: emits the legacy prefixes owned by
 * the effective address (segment override, then 0x67 address-size when the EA
 * uses 32-bit registers) and computes the REX.X/REX.B bits. Every memory
 * encoder MUST call this instead of mem_rex_bits, so the prefix invariant is
 * structural and cannot be forgotten by a new encoder. Prefix order matches
 * nasm byte-for-byte (seg, 0x67, then any 0x66 the caller emits, then REX).
 * Author: F E R M I ∞ H A R T. */
static void mem_begin(Mem *m, int *rex_x, int *rex_b) {
    if (m->seg)    emit(m->seg);
    if (m->addr32) emit(0x67);
    mem_rex_bits(m, rex_x, rex_b);
}
static int scale_bits(int s){ switch(s){case 1:return 0;case 2:return 1;case 4:return 2;case 8:return 3;} die("bad scale"); return 0; }

/* N02: one emission path owns the field width, absolute relocation type,
 * signed addend and flat-binary resolution for every displacement shape. */
static void emit_mem_disp(Mem *m, int width) {
    if (m->disp_has_sym==1 && strcmp(g_fmt,"bin")) {
        int at=cur_off();
        long addend=basm_expr_sub(m->disp,m->disp_sym_off);
        if (m->disp_sym_sec!=SEC_NONE) {
            if (width==2) add_reloc(at,g_cur,12,m->disp_sym_sec,NULL,m->disp);
            else if (m->abs32s) add_reloc_abs32s_section(at,g_cur,m->disp_sym_sec,m->disp);
            else add_reloc_abs32_section(at,g_cur,m->disp_sym_sec,m->disp);
        } else if (m->disp_sym_glob) {
            if (width==2) add_reloc(at,g_cur,12,SEC_NONE,m->disp_sym_name,addend);
            else if (m->abs32s) add_reloc_abs32s_named(at,g_cur,m->disp_sym_name,addend);
            else add_reloc_abs32_named(at,g_cur,m->disp_sym_name,addend);
        }
        else if (g_pass==2 || !g_fwd_unresolved) die("unresolved memory relocation basis");
        if (width==2) emit16(0); else emit32(0);
    } else {
        if (m->disp_has_sym && m->disp_sym_sec==SEC_NONE &&
            (g_pass==2 || m->disp_sym_glob))
            die("external symbol requires ELF64 output");
        if (width==2) emit16((uint32_t)m->disp); else emit32((uint32_t)m->disp);
    }
}

/* Emit ModRM(+SIB+disp) for a memory operand. trailing_imm = #imm bytes that
 * follow the displacement (needed for RIP reloc addend). */
static void encode_mem(int regfield, Mem *m, int trailing_imm) {
    if (m->rip) {
        emit_modrm(0, regfield, 5);              /* RIP-relative */
        int disp_off = cur_off();
        Sym *s = sym_find(m->sym);
        long extra = m->has_disp ? m->disp : 0;
        if (s && s->defined && s->section == g_cur) {
            long rel = (long)s->offset + extra - (long)(disp_off + 4 + trailing_imm);
            if (g_bounded_sse) sse_disp32(rel);
            emit32((uint32_t)rel);
            return;
        } else if (s && s->defined && s->section!=SEC_NONE) {
            /* reloc against section symbol; addend folds the symbol's offset */
            add_reloc_section(disp_off, s->section,
                              (long)s->offset + extra - 4 - trailing_imm);
        } else {
            /* extern / undefined: reloc against named symbol */
            if (g_pass==1 && (!s || !s->defined)) g_fwd_unresolved=1; /* INV-545 */
            add_reloc_named(disp_off, m->sym, extra - 4 - trailing_imm);
        }
        emit32(0);
        return;
    }
    if (m->no_base) {
        /* No base register, pure absolute displacement. In 16-bit mode this is
         * encoded as mod=00, rm=110 + disp16 (no SIB) — used by ap_trampoline.S
         * `mov byte [TRAMP_BASE+...]`. In 32/64-bit it's mod=00, rm=100 (SIB),
         * base=101 + optional index + scale → disp32. A label disp emits an
         * R_X86_64_32 reloc. Author: F E R M I ∞ H A R T. */
        if (g_bits==16 && !m->has_index) {
            emit_modrm(0, regfield, 6);   /* rm=110 → disp16 direct */
            emit_mem_disp(m,2);
            return;
        }
        /* No base register, absolute disp32. In 32-bit mode (no index) the
         * shortest form is mod=00, rm=101 + disp32 (NO SIB) — matches nasm and
         * avoids a 1-byte-per-instruction bloat in the BITS 32 trampoline.
         * In 64-bit mode rm=101 means RIP-relative, so an absolute there (or
         * any indexed form) must use the SIB form mod=00 rm=100, base=101.
         * Author: F E R M I ∞ H A R T. */
        if (g_bits==32 && !m->has_index) {
            emit_modrm(0, regfield, 5);   /* rm=101 → disp32 absolute (32-bit) */
            emit_mem_disp(m,4);
            return;
        }
        /* No base register. Absolute disp32, optionally with an index register
         * (e.g. [P(pd_table) + ecx*8] — the 2MB page-map loop). Encoded as
         * mod=00, rm=100 (SIB); SIB base=101 (disp32) + index (or none=100) +
         * scale. If the disp references a label, emit an R_X86_64_32 reloc
         * (addend = baked disp). Author: F E R M I ∞ H A R T. */
        emit_modrm(0, regfield, 4);
        int nidx = m->has_index ? (m->index & 7) : 4;   /* 100 = no index */
        emit((scale_bits(m->scale)<<6)|(nidx<<3)|5);    /* base=101 → disp32 */
        emit_mem_disp(m,4);
        return;
    }
    int base_low = m->base & 7;
    int need_sib = m->has_index || (base_low==4);
    int mod;
    int disp_zero = (!m->has_disp || m->disp==0);
    if (m->disp_has_sym && strcmp(g_fmt,"bin")) mod=2;
    else if (disp_zero) mod = (base_low==5)?1:0;
    else if (fits_imm8(m->disp)) mod=1; else mod=2;
    if (need_sib) {
        emit_modrm(mod, regfield, 4);
        int idx = m->has_index?(m->index&7):4;
        emit((scale_bits(m->scale)<<6)|(idx<<3)|base_low);
    } else emit_modrm(mod, regfield, base_low);
    if (mod==1) emit((uint8_t)(m->disp&0xff));
    else if (mod==2) emit_mem_disp(m,4);
}

/* ------------------------------------------------------------------ */
/* Operand classification                                             */
/* ------------------------------------------------------------------ */
static int is_mem(const char *t){ return t[0]=='['; }

static int imm_text_is_negative_simm32_hex(const char *s) {
    while (char_in(*s, " \t")) s++;
    if (*s == '-') return 1;
    if (s[0] != '0' || !char_in(s[1], "xX")) return 0;
    s += 2;
    const char *start = s;
    while (isxdigit((unsigned char)*s)) s++;
    size_t n = (size_t)(s - start);
    if (n <= 8 || n > 16) return 0;
    for (size_t i = 0; i + 8 < n; i++) {
        if (!char_in(start[i], "fF")) return 0;
    }
    char top = start[n - 8];
    return top >= '8' || (top >= 'a' && top <= 'f') || (top >= 'A' && top <= 'F');
}

/* ------------------------------------------------------------------ */
/* Instruction encoders                                               */
/* ------------------------------------------------------------------ */

/* MOV in all forms used by stage0. */
#define FAST_COMMIT_BYTES(bytes,count) do { \
    int fast_count=(count); \
    if(g_cur==SEC_TEXT && fast_count<=g_textcap-g_textlen){ \
        memcpy(g_text+g_textlen,(bytes),(size_t)fast_count); g_textlen+=fast_count; \
    } else emit_span((bytes),(size_t)fast_count); \
} while(0)
#define FAST_PACK_BYTE(value) do { buf[n++]=(uint8_t)(value); } while(0)

/* INV-595: the same descriptor chooses bytes, width and trace metadata in
 * both sizing and emission, including the packed fast path. */
/* N07: compact index into the existing descriptor authority. It replaces
 * a full schema scan for every typed scalar RR instruction. Index zero means
 * unsupported; no effect model or validation is inferred from an opcode. */
static uint8_t g_rr_form_index[36];
static int g_rr_form_ready;
static int rr_form_slot(int opcode,int width) {
    int group;
    if(opcode==0x88 || opcode==0x89)group=8;
    else if(opcode>=0 && opcode<0x3a && !(opcode&6))group=opcode>>3;
    else return -1;
    int size=width==8 ? 0 : width==16 ? 1 : width==32 ? 2 : width==64 ? 3 : -1;
    return size<0 ? -1 : group*4+size;
}
static void rr_forms_init(void) {
    if(g_rr_form_ready)return;
    if(INTENT_FORM_COUNT>255)die("too many intent forms for RR index");
    for(int i=0;i<INTENT_FORM_COUNT;i++){
        const IntentForm *form=&g_intent_forms[i];
        if(form->encoding!=INTENT_GPR_RR)continue;
        int slot=rr_form_slot(form->opcode[0],form->width);
        if(slot<0 || form->opcode_len!=1 || g_rr_form_index[slot])
            die("invalid or duplicate RR descriptor");
        g_rr_form_index[slot]=(uint8_t)(i+1);
    }
    g_rr_form_ready=1;
}

static int intent_emit_rr(int opcode, const Reg *rd, const Reg *rs) {
    if(!g_target_profile || g_bits!=64)return 0;
    if(rd->size!=rs->size)die("intent: register widths differ");
    rr_forms_init();
    int slot=rr_form_slot(opcode,rd->size*8);
    int index=slot<0 ? 0 : g_rr_form_index[slot];
    if(!index)die("intent: unregistered register form");
    const IntentForm *form=&g_intent_forms[index-1];
    if(form->opcode[0]!=opcode)die("intent: unregistered register form");
    uint8_t buf[4]; int n=0;
    if(form->width==16)buf[n++]=0x66;
    int rex=0x40|((form->width==64)<<3)|((rs->num>=8)<<2)|(rd->num>=8);
    int needs_rex=rex!=0x40 || rd->rex_req || rs->rex_req;
    int high_dst=rd->size==1 && rd->num>=4 && rd->num<8 && !rd->rex_req;
    int high_src=rs->size==1 && rs->num>=4 && rs->num<8 && !rs->rex_req;
    if(needs_rex && (high_dst || high_src))die("intent: high byte register conflicts with REX");
    if(needs_rex)buf[n++]=(uint8_t)rex;
    buf[n++]=form->opcode[0];
    buf[n++]=(uint8_t)(0xc0|((rs->num&7)<<3)|(rd->num&7));
    FAST_COMMIT_BYTES(buf,n);
    if(!g_intent_prefix)g_intent_form_current=form;
    return 1;
}

/* INV-595: compatibility/bootstrap reuse these mode-64 descriptors only as
 * byte templates, preserving ignored operands and historical BITS 16/32 bytes.
 * SYSRETQ retains the descriptor's 48 prefix; prefixed forms stay unmodeled. */
static void fixed_emit(const IntentForm *form, const char *op) {
    if(g_target_profile && g_bits==64){
        if(g_ntok!=1 || g_tok_precomma[0] || g_token_trailing_comma)
            die2("intent: fixed form takes no operands or commas",op);
        if(!g_intent_prefix)g_intent_form_current=form;
    }
    emit_span(form->opcode,(size_t)form->opcode_len);
}

static void enc_mov_rr(const Reg *rd,const Reg *rs) {
    if(intent_emit_rr(rd->size==1?0x88:0x89,rd,rs))return;
    /* INV-572: byte stores, not 64-bit variable shifts. The packed-u64
     * idiom cost Bear a variable 64-bit shift per byte; stores are one
     * mov each under both Bear and GCC. */
    uint8_t buf[8]; int n=0;
    if(rd->size==2 && opsize_default()!=16) FAST_PACK_BYTE(0x66);
    int rex=0x40|((rd->size==8)<<3)|((rs->num>=8)<<2)|(rd->num>=8);
    if(rex!=0x40 || rd->rex_req || rs->rex_req) FAST_PACK_BYTE(rex);
    FAST_PACK_BYTE(rd->size==1?0x88:0x89);
    FAST_PACK_BYTE(0xc0|((rs->num&7)<<3)|(rd->num&7));
    FAST_COMMIT_BYTES(buf,n); /* INV-556 */
}

/* N26: retain the complete normalized basis until the immediate field is
 * emitted. A small addend is not a small address, and an unknown sizing value
 * must not choose an imm8 or an implicit-one opcode. */
typedef struct {
    long value;
    int has_sym, section, global;
    char name[NAME_MAX];
} ImmediateExpr;

static void parse_immediate(const char *text,ImmediateExpr *out) {
    long offset;
    out->value=parse_expr_reloc(text,&out->has_sym,&out->section,&offset,out->name,&out->global);
}

static int immediate_is_absolute(const ImmediateExpr *imm) {
    /* NASM retains full fields for section-relative expressions in bin too. */
    return !imm->has_sym;
}

static int immediate_value_known(const ImmediateExpr *imm) {
    return !imm->has_sym || (imm->section!=SEC_NONE && !strcmp(g_fmt,"bin"));
}

/* Arithmetic qword operands encode a sign-extended dword immediate. */
static void emit_arithmetic_immediate(int size,const ImmediateExpr *imm) {
    int width=size==8 ? 4 : size;
    int type=size==8 ? 11 : size==4 ? 10 : size==2 ? 12 : 14;
    emit_expr_field(width,type,imm->value,imm->has_sym,imm->section,imm->global,imm->name);
}

static void enc_mov(const char *dst, const char *src) {
    const Reg *rd = reg_find(dst);
    const Reg *rs = (isalpha((unsigned char)src[0]) ? reg_find(src) : NULL);
    /* reg, [mem] */
    if (rd && is_mem(src)) {
        Mem m; parse_mem(src, &m); int rr=(rd->num>=8),rx,rb; mem_begin(&m,&rx,&rb);
               /* BUG-06: Use short form A1 for mov eax, [disp32] in 32-bit mode */
        if (rd->size==4 && rd->num==0 && m.no_base && !m.has_index && g_bits==32) {
            emit(0xa1);
            emit32((uint32_t)m.disp);
            return;
        }
        if (rd->size==1)      { emit_rex(0,rr,rx,rb,rd->rex_req); emit(0x8a); }
        else if (rd->size==2) { emit(0x66); emit_rex(0,rr,rx,rb,0); emit(0x8b); }
        else                  { emit_rex(rd->size==8,rr,rx,rb,0); emit(0x8b); }
        encode_mem(rd->num, &m, 0); return;
    }
    /* [mem], reg */
    if (is_mem(dst) && rs) {
        Mem m; parse_mem(dst, &m); int rr=(rs->num>=8),rx,rb; mem_begin(&m,&rx,&rb);
               /* BUG-04: Use short form A2 for mov [disp32], al in 32-bit mode */
        if (rs->size==1 && rs->num==0 && m.no_base && !m.has_index && g_bits==32) {
            emit(0xa2);
            emit32((uint32_t)m.disp);
            return;
        }
        if (rs->size==1)      { emit_rex(0,rr,rx,rb,rs->rex_req); emit(0x88); }
        else if (rs->size==2) { emit(0x66); emit_rex(0,rr,rx,rb,0); emit(0x89); }
        else                  { emit_rex(rs->size==8,rr,rx,rb,0); emit(0x89); }
        encode_mem(rs->num, &m, 0); return;
    }
    /* reg, reg */
    if (rd && rs) {
        enc_mov_rr(rd,rs); return;
    }
    /* reg, imm */
    if (rd && !rs && !is_mem(src)) {
        /* Capture a label ref in the immediate so a 32-bit register load
         * (e.g. `mov eax, P(pml4_table)` for the cr3 value) emits an
         * R_X86_64_32 reloc. Author: F E R M I ∞ H A R T. */
        int ihs=0,isec=SEC_NONE,igl=0; long ioff=0; char inm[NAME_MAX];
        long imm = parse_expr_reloc(src, &ihs, &isec, &ioff, inm, &igl);
        if (rd->size==8) {
            /* r64 immediate referencing a label (e.g. `mov rsp, P(stack_top)`):
             * emit movabs (REX.W B8+rd io) with a 64-bit absolute reloc so the
             * linker resolves the address. Author: F E R M I ∞ H A R T. */
            if (ihs && (isec!=SEC_NONE || igl)) {
                emit_rex(1,0,0,(rd->num>=8),0); emit(0xb8+(rd->num&7));
                int io=cur_off();
                /* N01: SEC_NONE is an unresolved named basis, not a literal.
                 * Defined symbols fold into their section, including globals;
                 * externs keep the signed constant addend in ELF RELA. */
                if (!strcmp(g_fmt,"bin")) {
                    if (isec==SEC_NONE) die("external symbol requires ELF64 output");
                    emit64((uint64_t)imm); return;
                }
                if (isec!=SEC_NONE) add_reloc_abs64_section(io,g_cur,isec,imm);
                else add_reloc(io,g_cur,1,SEC_NONE,inm,basm_expr_sub(imm,ioff));
                emit64(0); return;
            }
            /* FORWARD symbol ref (a label seen, but not yet defined in this
             * SIZING pass — isec is still SEC_NONE). It WILL become a movabs
             * (10 bytes) in the final pass once the label resolves. The sizing
             * pass MUST reserve those same 10 bytes here, or every label after
             * this instruction shifts by 5 between pass 1 and pass 2 — which
             * desynced forward Jcc displacements (`jz .no_avx` assembled as
             * `74 fe`, an infinite self-loop) and hung the kernel at the TSS
             * setup. Detect "a symbol was referenced" via g_expr_symcount and
             * emit the full movabs width. Author: F E R M I ∞ H A R T. */
            if (g_expr_symcount >= 1) {
                emit_rex(1,0,0,(rd->num>=8),0); emit(0xb8+(rd->num&7));
                emit64(0); return;
            }
            if (imm>=0 && imm<=0xffffffffL) { /* fold to 32-bit (zero-extends) */
                if (rd->num>=8) emit(0x41);
                emit(0xb8+(rd->num&7)); emit32((uint32_t)imm); return;
            }
            uint64_t imm_bits = (uint64_t)imm;
            if ((imm>=-2147483648L && imm<0) || imm_bits >= UINT64_C(0xffffffff80000000) ||
                imm_text_is_negative_simm32_hex(src)) { /* mov r/m64,imm32 sign-extended: C7 /0 */
                emit_rex(1,0,0,(rd->num>=8),0); emit(0xc7); emit_modrm(3,0,rd->num); emit32((uint32_t)imm); return;
            }
            /* movabs: REX.W B8+rd io */
            emit_rex(1,0,0,(rd->num>=8),0);
            emit(0xb8+(rd->num&7)); emit64((uint64_t)imm); return;
        }
        if (rd->size==4) { if(rd->num>=8)emit(0x41); emit(0xb8+(rd->num&7));
            if (ihs && isec!=SEC_NONE) {
                /* BUG-02: In bin format, resolve label directly (no reloc) */
                if (!strcmp(g_fmt, "bin")) {
                    emit32((uint32_t)imm);
                } else {
                    int io=cur_off();
                    add_reloc_abs32_section(io, g_cur, isec, imm);
                    emit32(0);
                }
            } else if (ihs && igl) {
                /* EXTERN symbol as a 32-bit immediate (e.g. mov edi,__bss_start):
                 * named R_X86_64_32 reloc, the linker supplies the address.
                 * Author: F E R M I ∞ H A R T. */
                int io=cur_off();
                if (!strcmp(g_fmt,"bin")) die("external symbol requires ELF64 output");
                add_reloc_abs32_named(io, g_cur, inm, basm_expr_sub(imm,ioff));
                emit32(0);
            } else emit32((uint32_t)imm);
            return; }
        if (rd->size==2) {
            emit_opsize(16); emit_rex(0,0,0,rd->num>=8,0); emit(0xb8+(rd->num&7));
            emit_expr_field(2,12,imm,ihs,isec,igl,inm); return;
        }
        /* 8-bit: B0+rd ib (with forced REX for spl/bpl/sil/dil) */
        emit_rex(0,0,0,rd->num>=8,rd->rex_req); emit(0xb0+(rd->num&7));
        emit_expr_field(1,14,imm,ihs,isec,igl,inm); return;
    }
    die("unsupported mov form");
}

/* mov <size> [mem], imm  (size keyword present) */
static void enc_mov_mem_imm(const char *szkw, const char *memtok, const char *immtok) {
    Mem m; parse_mem(memtok, &m);
    /* Capture a label ref in the immediate (e.g. `mov dword [..], P(pdpt)+3`)
     * so the stored 32-bit value gets an R_X86_64_32 reloc. Author: F E R M I ∞ H A R T. */
    int ihs=0, isec=SEC_NONE, iglob=0; long ioff=0; char inm[NAME_MAX];
    long imm = parse_expr_reloc(immtok, &ihs, &isec, &ioff, inm, &iglob);
    int rx, rb; mem_begin(&m,&rx,&rb);
    int width,type;
    if (strcmp(szkw,"byte")==0) {
        width=1; type=14;
        emit_rex(0,0,rx,rb,0); emit(0xc6); encode_mem(0,&m,1);
    } else if (strcmp(szkw,"word")==0) {
        width=2; type=12;
        emit(0x66); emit_rex(0,0,rx,rb,0); emit(0xc7); encode_mem(0,&m,2);
    } else if (strcmp(szkw,"dword")==0) {
        width=4; type=10;
        emit_rex(0,0,rx,rb,0); emit(0xc7); encode_mem(0,&m,4);
    } else if (strcmp(szkw,"qword")==0) {
        /* The encoded immediate is sign-extended imm32, hence R_X86_64_32S. */
        width=4; type=11;
        emit_rex(1,0,rx,rb,0); emit(0xc7); encode_mem(0,&m,4);
    } else { die2("unknown size keyword",szkw); return; }
    emit_expr_field(width,type,imm,ihs,isec,iglob,inm);
}

static void enc_lea(const char *dst, const char *src) {
    const Reg *rd = reg_find(dst);
    if (!rd || !is_mem(src)) die("unsupported lea form");
    Mem m; parse_mem(src, &m); int rr=(rd->num>=8),rx,rb; mem_begin(&m,&rx,&rb);
    emit_rex(rd->size==8,rr,rx,rb,0); emit(0x8d); encode_mem(rd->num, &m,0);
}

/* movsxd r64, r/m32  (4c 63 /r) */
static void enc_movsxd(const char *dst, const char *src) {
    const Reg *rd=reg_find(dst), *rs=reg_find(src);
    if (!rd) die("movsxd dst not reg");
    if (rs) { emit_rex(1,(rd->num>=8),0,(rs->num>=8),0); emit(0x63); emit_modrm(3,rd->num,rs->num); return; }
    if (is_mem(src)) { Mem m; parse_mem(src, &m); int rx,rb; mem_begin(&m,&rx,&rb);
        emit_rex(1,(rd->num>=8),rx,rb,0); emit(0x63); encode_mem(rd->num, &m,0); return; }
    die("movsxd src");
}

/* N05: NASM 3.02's legacy MOVSX/MOVZX forms include same-width forms
 * and dword zero-extension through a 32-bit MOV. Byte destinations and
 * qword sources remain invalid. 63 /r requires long mode. */
static void enc_movx(int sign_ext, int srcsize, const char *dst, const char *src) {
    const Reg *rd=reg_find(dst); if(!rd) die("movzx/movsx dst");
    if(rd->size==1) die("movzx/movsx needs a 16/32/64-bit destination");
    if(srcsize==0||srcsize==8) die("movzx/movsx has no 64-bit source form");
    const Reg *rsreg=is_mem(src) ? NULL : reg_find(src);
    if(!is_mem(src) && (!rsreg || rsreg->size!=srcsize))die("movzx/movsx source width");
    if(g_bits!=64 && (rd->size==8 || rd->num>=8 ||
       (rsreg && (rsreg->num>=8 || rsreg->rex_req))))
        die("movzx/movsx register requires BITS 64");
    /* NASM's default optimization also uses CBW/CWDE/CDQE for the exact
     * accumulator widening forms. These have the same signed result. */
    if(sign_ext && rsreg && rd->num==0 && rsreg->num==0 && rd->size==srcsize*2){
        if(rd->size==2)emit_opsize(16);
        else if(rd->size==4)emit_opsize(32);
        emit_rex(rd->size==8,0,0,0,0); emit(0x98); return;
    }
    if(srcsize==4) {
        if(sign_ext && g_bits!=64)die("movsx dword source requires BITS 64");
        int w=sign_ext && rd->size==8, opcode=sign_ext ? 0x63 : 0x8b;
        if(rd->size==2)emit_opsize(16); else if(!w)emit_opsize(32);
        if (is_mem(src)) { Mem m; parse_mem(src, &m); int rx,rb; mem_begin(&m,&rx,&rb);
            emit_rex(w,(rd->num>=8),rx,rb,0); emit(opcode); encode_mem(rd->num, &m,0); return; }
        emit_rex(w,(rd->num>=8),0,(rsreg->num>=8),0); emit(opcode); emit_modrm(3,rd->num,rsreg->num); return;
    }
    int op = sign_ext ? (srcsize==1?0xbe:0xbf) : (srcsize==1?0xb6:0xb7);
    if(rd->size==2) emit_opsize(16); else if(rd->size==4) emit_opsize(32);
    if (is_mem(src)) { Mem m; parse_mem(src, &m); int rx,rb; mem_begin(&m,&rx,&rb);
        emit_rex(rd->size==8,(rd->num>=8),rx,rb,0); emit(0x0f); emit(op); encode_mem(rd->num, &m,0); return; }
    const Reg *rs=reg_find(src); if(!rs) die("movzx/movsx src");
    if(rs->size==8) die("movzx/movsx needs an 8/16/32-bit source");
    /* INV-580: ah/ch/dh/bh are unencodable under any REX prefix. */
    if(((rd->size==8)||(rd->num>=8)||(rs->num>=8)||rs->rex_req) &&
       rs->size==1 && rs->num>=4 && rs->num<8 && !rs->rex_req)
        die("high byte register cannot be used with extended registers");
    emit_rex(rd->size==8,(rd->num>=8),0,(rs->num>=8),rs->rex_req); emit(0x0f); emit(op); emit_modrm(3,rd->num,rs->num);
}

/* ALU reg,imm using /digit group1 (add=0 or=1 and=4 sub=5 xor=6 cmp=7). */
static void enc_alu_ri(int ext, const Reg *rd, long imm) {
    int rb=(rd->num>=8);
    if (rd->size==1) { /* 8-bit: 80 /digit ib (AL short form 04+8*ext) */
        if (rd->num==0) { static const int acc8[8]={0x04,0x0c,0x14,0x1c,0x24,0x2c,0x34,0x3c};
            emit(acc8[ext]); emit((uint8_t)imm); return; }
        emit_rex(0,0,0,rb,rd->rex_req); emit(0x80); emit_modrm(3,ext,rd->num); emit((uint8_t)imm); return;
    }
    /* operand-size prefix: 0x66 when reg width != mode default (e.g.
     * `or eax,1` in BITS 16 needs 66). Author: F E R M I ∞ H A R T. */
    if (rd->size==2) emit_opsize(16); else if (rd->size==4) emit_opsize(32);
    if (fits_imm8(imm)) { emit_rex(rd->size==8,0,0,rb,0); emit(0x83); emit_modrm(3,ext,rd->num); emit((uint8_t)imm); return; }
    /* Accumulator form also has a word field in the 16-bit operand size. */
    if (rd->num==0) {
        static const int acc[8]={0x05,0x0d,0x15,0x1d,0x25,0x2d,0x35,0x3d};
        emit_rex(rd->size==8,0,0,0,0); emit(acc[ext]);
        if(rd->size==2)emit16((uint32_t)imm); else emit32((uint32_t)imm);
        return;
    }
    emit_rex(rd->size==8,0,0,rb,0); emit(0x81); emit_modrm(3,ext,rd->num);
    if (rd->size==2) emit16((uint32_t)imm); else emit32((uint32_t)imm);
}

static void enc_alu_ri_expr(int ext,const Reg *rd,const char *text) {
    ImmediateExpr imm; parse_immediate(text,&imm);
    if(immediate_is_absolute(&imm)){ enc_alu_ri(ext,rd,imm.value); return; }
    if(rd->size==2)emit_opsize(16); else if(rd->size==4)emit_opsize(32);
    emit_rex(rd->size==8,0,0,rd->num>=8,rd->rex_req);
    if(rd->num==0)emit((rd->size==1 ? 0x04 : 0x05)+ext*8);
    else { emit(rd->size==1 ? 0x80 : 0x81); emit_modrm(3,ext,rd->num); }
    emit_arithmetic_immediate(rd->size,&imm);
}
/* ALU reg,reg using the "01+8*ext" opcode family (op /r, r/m,reg). */
static void enc_alu_rr(int opbase, const Reg *rd, const Reg *rs) {
    if(intent_emit_rr(rd->size==1?opbase-1:opbase,rd,rs))return;
    if (rd->size==1) { /* 8-bit form: opbase-1 (e.g. xor 30 vs 31) */
        emit_rex(0,(rs->num>=8),0,(rd->num>=8),(rd->rex_req||rs->rex_req));
        emit(opbase-1); emit_modrm(3, rs->num, rd->num); return;
    }
    if (rd->size==2) emit_opsize(16); /* 16-bit operand: 0x66 only if not the mode default */
    else if (rd->size==4) emit_opsize(32); /* 32-bit operand: 0x66 in BITS 16 */
    emit_rex(rd->size==8,(rs->num>=8),0,(rd->num>=8),0);
    emit(opbase); emit_modrm(3, rs->num, rd->num);
}

/* generic 2-operand ALU dispatch */
static void enc_alu(int ext, const char *dst, const char *src) {
    /* opcode bases: add 01, or 09, and 21, sub 29, xor 31, cmp 39 ; ext digits */
    int rrbase=ext*8+1, rmbase=rrbase+2;
    const Reg *rd=reg_find(dst);
    const Reg *rs=isalpha((unsigned char)src[0])?reg_find(src):NULL;
    /* reg, [mem]  -> rmbase /r */
    if (rd && is_mem(src)) {
        Mem m; parse_mem(src, &m); int rr=(rd->num>=8),rx,rb; mem_begin(&m,&rx,&rb);
        if (rd->size==2) emit_opsize(16); else if (rd->size==4) emit_opsize(32);
        emit_rex(rd->size==8,rr,rx,rb,rd->rex_req); emit(rd->size==1?rmbase-1:rmbase); encode_mem(rd->num, &m,0); return;
    }
    /* [mem], reg -> rrbase /r */
    if (is_mem(dst) && rs) {
        Mem m; parse_mem(dst, &m); int rr=(rs->num>=8),rx,rb; mem_begin(&m,&rx,&rb);
        if (rs->size==2) emit_opsize(16); else if (rs->size==4) emit_opsize(32);
        emit_rex(rs->size==8,rr,rx,rb,rs->rex_req); emit(rs->size==1?rrbase-1:rrbase); encode_mem(rs->num, &m,0); return;
    }
    if (rd && rs) { enc_alu_rr(rrbase, rd, rs); return; }
    if (rd && !rs && !is_mem(src)) { enc_alu_ri_expr(ext,rd,src); return; }
    die("unsupported alu form");
}

static void fast_emit_alu(int ext,const Reg *rd,const Reg *rs,int has_imm,long imm) {
    if(!has_imm && intent_emit_rr(ext*8+(rd->size==1?0:1),rd,rs))return;
    /* INV-572: see enc_mov_rr — straight-line byte stores plus unrolled
     * immediates (constant shifts only, no i*8 variable shift loop). */
    uint8_t buf[8]; int n=0;
    uint32_t u;
    int rb=rd->num>=8;
    if(!has_imm){
        if(rd->size==1){
            int rex=0x40|((rs->num>=8)<<2)|rb;
            if(rex!=0x40 || rd->rex_req || rs->rex_req) FAST_PACK_BYTE(rex);
            FAST_PACK_BYTE(ext*8); FAST_PACK_BYTE(0xc0|((rs->num&7)<<3)|(rd->num&7));
        } else {
            /* INV-560: r8w..r15w stay word-class and emit 0x66 before REX/opcode. */
            if((rd->size==2 && opsize_default()!=16) || (rd->size==4 && opsize_default()!=32)) FAST_PACK_BYTE(0x66);
            int rex=0x40|((rd->size==8)<<3)|((rs->num>=8)<<2)|rb;
            if(rex!=0x40) FAST_PACK_BYTE(rex);
            FAST_PACK_BYTE(ext*8+1); FAST_PACK_BYTE(0xc0|((rs->num&7)<<3)|(rd->num&7));
        }
    } else if(rd->size==1){
        if(rd->num==0){ FAST_PACK_BYTE(0x04+ext*8); FAST_PACK_BYTE(imm); }
        else {
            int rex=0x40|rb; if(rex!=0x40 || rd->rex_req) FAST_PACK_BYTE(rex);
            FAST_PACK_BYTE(0x80); FAST_PACK_BYTE(0xc0|(ext<<3)|(rd->num&7)); FAST_PACK_BYTE(imm);
        }
    } else {
        /* INV-560: immediate ALU uses the same word-width prefix rule. */
        if((rd->size==2 && opsize_default()!=16) || (rd->size==4 && opsize_default()!=32)) FAST_PACK_BYTE(0x66);
        int rex=0x40|((rd->size==8)<<3)|rb; if(rex!=0x40) FAST_PACK_BYTE(rex);
        if(fits_imm8(imm)){
            FAST_PACK_BYTE(0x83); FAST_PACK_BYTE(0xc0|(ext<<3)|(rd->num&7)); FAST_PACK_BYTE(imm);
        } else if(rd->num==0) {
            FAST_PACK_BYTE(0x05+ext*8);
            u=(uint32_t)imm;
            FAST_PACK_BYTE(u); FAST_PACK_BYTE(u>>8);
            if(rd->size!=2){ FAST_PACK_BYTE(u>>16); FAST_PACK_BYTE(u>>24); }
        } else {
            FAST_PACK_BYTE(0x81); FAST_PACK_BYTE(0xc0|(ext<<3)|(rd->num&7));
            u=(uint32_t)imm;
            FAST_PACK_BYTE(u); FAST_PACK_BYTE(u>>8);
            if(rd->size!=2){ FAST_PACK_BYTE(u>>16); FAST_PACK_BYTE(u>>24); }
        }
    }
    FAST_COMMIT_BYTES(buf,n); /* INV-557 */
}

/* N06: bounded source slices and NUL-terminated tokens share the exact
 * immutable vocabulary and full-byte candidate validation. */
static const Reg *fast_reg_find(const char *s,size_t len) {
    return reg_find_n(s,len);
}

static int fast_fixed_span(const char *op,size_t len);

static int try_fast_instruction(const char *line) {
    /* N08: this is an admitted original-source line, ending at LF/CR/NUL.
     * Legacy token macros may replace opcode or operands; leave those to the
     * full tokenizer. No state is mutated before a complete form is proven. */
    if(g_nmacros)return 0;
    /* INV-572: single-expression char classes (bitwise |, never ||/&&)
     * so Bear emits straight-line setcc/OR instead of a memory temporary
     * plus branch per operator. Hot loops stay at ~1 test per char. */
    const char *p=line;
    while((*p==' ')|(*p=='\t')) p++;
    const char *op=p;
    while((unsigned)(*p-(unsigned)'a')<26u) p++;
    size_t oplen=(size_t)(p-op);
    /* The common operand-free forms can bypass token arrays too. Descriptor
     * selection and tracing remain shared with the ordinary fixed encoder. */
    if(oplen==3 && ((op[0]=='n' && op[1]=='o' && op[2]=='p') ||
                   (op[0]=='r' && op[1]=='e' && op[2]=='t'))){
        while((*p==' ')|(*p=='\t'))p++;
        if(*p && *p!=';' && *p!='\n' && *p!='\r')return 0;
        return fast_fixed_span(op,oplen);
    }
    int is_mov=0, ext=-1;
    if(oplen==3 && op[0]=='m' && op[1]=='o' && op[2]=='v') is_mov=1;
    else if(oplen==3 && op[0]=='a' && op[1]=='d' && op[2]=='d') ext=0;
    else if(oplen==2 && op[0]=='o' && op[1]=='r') ext=1;
    else if(oplen==3 && op[0]=='a' && op[1]=='n' && op[2]=='d') ext=4;
    else if(oplen==3 && op[0]=='s' && op[1]=='u' && op[2]=='b') ext=5;
    else if(oplen==3 && op[0]=='x' && op[1]=='o' && op[2]=='r') ext=6;
    else if(oplen==3 && op[0]=='c' && op[1]=='m' && op[2]=='p') ext=7;
    else return 0;
    if((*p!=' ')&(*p!='\t')) return 0;
    while((*p==' ')|(*p=='\t')) p++;
    const char *dst=p;
    while(((unsigned)(*p-(unsigned)'a')<26u)|((unsigned)(*p-(unsigned)'0')<10u)) p++;
    size_t dstlen=(size_t)(p-dst);
    while((*p==' ')|(*p=='\t')) p++;
    if(*p!=',') return 0;
    p++;
    if(dstlen==0||dstlen>=16) return 0;
    while((*p==' ')|(*p=='\t')) p++;
    const char *src=p;
    while(!((*p==0)|(*p==' ')|(*p=='\t')|(*p==';')|(*p=='\n')|(*p=='\r'))) p++;
    size_t srclen=(size_t)(p-src);
    while((*p==' ')|(*p=='\t')) p++;
    if(srclen==0||srclen>=32) return 0;
    if((*p!=0)&(*p!=';')&(*p!='\n')&(*p!='\r')) return 0;
    /* INV-572: fast_reg_find is length-aware, so registers decode
     * straight from the line with zero copies. Only the imm fallback
     * copies, to feed the shared NUL-based strtol conversion (INV-554). */
    const Reg *rd=fast_reg_find(dst,dstlen);
    if(!rd) return 0;
    const Reg *rs=((src[0]>='a')&(src[0]<='z'))?fast_reg_find(src,srclen):NULL;
    if(is_mov){ if(!rs) return 0; enc_mov_rr(rd,rs); return 1; }
    if(rs){ fast_emit_alu(ext,rd,rs,0,0); return 1; }
    long imm;
    char srcbuf[32];
    memcpy(srcbuf,src,srclen); srcbuf[srclen]=0;
    if(!parse_decimal_literal(srcbuf,&imm)) return 0;
    fast_emit_alu(ext,rd,NULL,1,imm);
    return 1; /* INV-557 */
}

/* alu <size> [mem], imm  (e.g. cmp byte [r14],'-') */
static void enc_alu_mem_imm(int ext, const char *szkw, const char *memtok, const char *immtok) {
    Mem m; parse_mem(memtok,&m);
    ImmediateExpr imm; parse_immediate(immtok,&imm);
    int size=!strcmp(szkw,"byte") ? 1 : !strcmp(szkw,"word") ? 2 :
             !strcmp(szkw,"dword") ? 4 : !strcmp(szkw,"qword") ? 8 : 0;
    if(!size)die2("alu mem size",szkw);
    int short_field=size!=1 && immediate_is_absolute(&imm) && fits_imm8(imm.value);
    int width=short_field ? 1 : size==8 ? 4 : size;
    int rx,rb; mem_begin(&m,&rx,&rb);
    if(size==2)emit_opsize(16); else if(size==4)emit_opsize(32);
    emit_rex(size==8,0,rx,rb,0); emit(size==1 ? 0x80 : short_field ? 0x83 : 0x81);
    encode_mem(ext,&m,width);
    if(short_field)emit((uint8_t)imm.value); else emit_arithmetic_immediate(size,&imm);
}

/* shift reg, imm8 (C1 /4 shl, /5 shr, /7 sar) or reg,1 (D1) */
static void enc_shift(int ext, const char *dst, const char *src) {
    if(g_ntok!=3 || g_token_trailing_comma || g_tok_precomma[0] ||
       g_tok_precomma[1] || !g_tok_precomma[2])die("shift needs two comma-separated operands");
    const Reg *rd=reg_find(dst); if(!rd) die("shift dst");
    /* Variable-count shift: shl rax, cl → D3 /4 (uses CL register) */
    const Reg *rc=reg_find(src);
    if (rc && rc->num == 1 && rc->size == 1) { /* cl register */
        if (rd->size==1) { emit_rex(0,0,0,(rd->num>=8),rd->rex_req); emit(0xd2); emit_modrm(3,ext,rd->num); return; }
        if (rd->size==2)emit_opsize(16); else if(rd->size==4)emit_opsize(32);
        emit_rex(rd->size==8,0,0,(rd->num>=8),0); emit(0xd3); emit_modrm(3,ext,rd->num); return;
    }
    if(rc)die("shift count register must be cl");
    ImmediateExpr imm; parse_immediate(src,&imm);
    int one=immediate_is_absolute(&imm) && imm.value==1, rb=(rd->num>=8);
    if (rd->size==1) {
        /* 8-bit: D0 /ext (by 1), C0 /ext ib (by imm) */
        emit_rex(0,0,0,rb,rd->rex_req); emit(one ? 0xd0 : 0xc0); emit_modrm(3,ext,rd->num);
    } else {
        if (rd->size==2)emit_opsize(16); else if(rd->size==4)emit_opsize(32);
        emit_rex(rd->size==8,0,0,rb,0); emit(one ? 0xd1 : 0xc1); emit_modrm(3,ext,rd->num);
    }
    if(!one)emit_arithmetic_immediate(1,&imm);
}

/* inc/dec : reg (FF /0, /1) or  <size> [mem] */
static void enc_incdec(int ext, int ntok) {
    if (ntok==2) { /* inc reg */
        const Reg *rd=reg_find(g_tok[1]); if(!rd) die("inc/dec reg");
        /* BUG-01: In BITS 16/32, use short form (0x40+rd for inc, 0x48+rd for dec) */
        if (g_bits != 64 && rd->size != 1 && rd->num < 8) {
            emit((ext == 0 ? 0x40 : 0x48) + rd->num);
            return;
        }
        emit_rex(rd->size==8,0,0,(rd->num>=8),0); emit(rd->size==1?0xfe:0xff); emit_modrm(3,ext,rd->num); return;
    }
    /* inc <size> [mem] : 3 tokens (mnemonic, size, [mem]) */
    const char *szkw=g_tok[1]; Mem m; parse_mem(g_tok[2], &m); int rx,rb; mem_begin(&m,&rx,&rb);
    if (!strcmp(szkw,"byte")) { emit_rex(0,0,rx,rb,0); emit(0xfe); }
    else if (!strcmp(szkw,"word")) { emit(0x66); emit_rex(0,0,rx,rb,0); emit(0xff); }
    else if (!strcmp(szkw,"dword")) { emit_rex(0,0,rx,rb,0); emit(0xff); }
    else if (!strcmp(szkw,"qword")) { emit_rex(1,0,rx,rb,0); emit(0xff); }
    else die2("inc/dec size", szkw);
    encode_mem(ext, &m, 0);
}

/* neg/mul/imul1/div : F7 /3 neg, /4 mul, /5 imul, /6 div, /7 idiv */
static void enc_unary_grp3(int ext, const char *r) {
    const Reg *rd=reg_find(r); if(!rd) die("grp3 needs reg");
    emit_rex(rd->size==8,0,0,(rd->num>=8),0); emit(0xf7); emit_modrm(3,ext,rd->num);
}
/* imul r, r/m  (two-operand 0F AF /r) — also handles imul r, [mem] */
static void enc_imul2(const char *dst, const char *src) {
    const Reg *rd=reg_find(dst); if(!rd) die("imul2 dst");
    const Reg *rs=reg_find(src);
    if (rs) {
        /* reg, reg */
        emit_rex(rd->size==8,(rd->num>=8),0,(rs->num>=8),0); emit(0x0f); emit(0xaf);
        emit_modrm(3,rd->num,rs->num);
        return;
    }
    /* reg, [mem] — 0F AF /r with r/m = mem */
    if (is_mem(src)) {
        Mem m; parse_mem(src, &m); int rx,rb; mem_begin(&m,&rx,&rb);
       emit_rex(rd->size==8,(rd->num>=8),rx,rb,0); emit(0x0f); emit(0xaf);
        encode_mem(rd->num, &m, 0);
        return;
    }
    die("imul2 needs reg or [mem] source");
}

static void enc_stack_reg(const char *r, int pop) {
    const Reg *rg=reg_find(r);
    if (!rg || (rg->size!=8 && rg->size!=4)) die(pop ? "pop r64/r32" : "push r64/r32");
    if (g_target_profile && g_bits==64 && rg->size!=8)
        die(pop ? "target profile: pop requires r64" : "target profile: push requires r64");
    if (rg->num>=8) emit(0x41);
    emit(0x50+pop*8+(rg->num&7));
}
#define enc_push(r) enc_stack_reg(r,0)
#define enc_pop(r) enc_stack_reg(r,1)

/* call: if target is a symbol defined in .text, resolve to rel32 directly
 * (no reloc, like NASM); otherwise emit a PC32 reloc against the named symbol. */
static void enc_call(const char *t) {
    if(!strcmp(t,"$")){ emit(0xe8); emit32((uint32_t)-5); return; } /* INV-595 */
    /* Register-indirect call: `call r12` → FF /2 (REX.B if r8-r15).
     * The operand is a 64-bit GPR, not a branch target. Author: F E R M I ∞ H A R T. */
    const Reg *rg = reg_find(t);
    if (rg && rg->size==8) {
        if (rg->num>=8) emit(0x41);          /* REX.B for r8-r15 */
        emit(0xff); emit_modrm(3, 2, rg->num);  /* /2 = call r/m64 */
        return;
    }
    char q[NAME_MAX]; qualify(t,q); Sym *s=sym_find(q);
    emit(0xe8);
    if (s && s->defined && s->section==g_cur) {
        long rel = (long)s->offset - (long)(cur_off()+4);
        emit32((uint32_t)rel);
    } else if (s && s->defined && s->section!=SEC_NONE && !s->global) {
        add_reloc_section(cur_off(), s->section, (long)s->offset - 4);
        emit32(0);
    } else {
        if (g_pass==1 && (!s || !s->defined)) g_fwd_unresolved=1; /* INV-545 */
        add_reloc_named(cur_off(), q, -4);
        emit32(0);
    }
}

/* INV-538: SETcc r8: REX must precede 0F 9X+cond /0 (ModRM.reg=0, rm=reg). The codegen emits
 * `setX al` etc. so the operand is an 8-bit register. Author: F E R M I ∞ H A R T. */

static void qualify(const char *target, char *out) {
    if (target[0]=='.' && g_last_global[0]) {
        size_t gl=strlen(g_last_global), tl=strlen(target);
        if (gl+tl>=NAME_MAX) die("qualified label too long");
        memcpy(out,g_last_global,gl); memcpy(out+gl,target,tl+1);
    } else { basm_name_copy(out,target); }
}

/* Branch-size relaxation, NASM-style. The decision of rel8 vs rel32 must be
 * made from a SINGLE consistent layout: mixing this-pass branch positions with
 * last-pass target offsets falsely inflates forward displacements and promotes
 * branches that actually fit. So the emit functions during sizing only RECORD
 * each branch's position and target; the driver recomputes the whole size
 * assignment after the pass and iterates to the shortest stable layout. */
/* INV-BASM-BRANCH-GROWTH-001: grow metadata for real translated compiler TUs,
 * retaining bounded ordinals and the unchanged relaxation algorithm. */
#define BRANCH_MAX 65536
static int *g_branch_long; /* 1 if this branch ordinal needs rel32 */
static long *g_branch_pos;
static int *g_branch_sec;
static int *g_branch_force;
static char (*g_branch_tgt)[NAME_MAX];
static size_t g_branch_capacity;
static int g_branch_ord = 0;
static int g_sizing = 0;        /* 1 during sizing iterations */

static void branch_require(void) {
    if (g_branch_ord >= BRANCH_MAX) die("too many branches");
    if ((size_t)g_branch_ord < g_branch_capacity) return;
    size_t capacity = g_branch_capacity ? g_branch_capacity * 2 : 256;
    if (capacity > BRANCH_MAX) capacity = BRANCH_MAX;
    if (capacity <= g_branch_capacity || capacity > SIZE_MAX / NAME_MAX)
        die("branch allocation overflow");
    void *grown = realloc(g_branch_long, capacity * sizeof(*g_branch_long));
    if (!grown) die("cannot grow branch metadata");
    g_branch_long = grown;
    memset(g_branch_long + g_branch_capacity, 0,
           (capacity - g_branch_capacity) * sizeof(*g_branch_long));
    grown = realloc(g_branch_pos, capacity * sizeof(*g_branch_pos));
    if (!grown) die("cannot grow branch metadata");
    g_branch_pos = grown;
    grown = realloc(g_branch_sec, capacity * sizeof(*g_branch_sec));
    if (!grown) die("cannot grow branch metadata");
    g_branch_sec = grown;
    grown = realloc(g_branch_force, capacity * sizeof(*g_branch_force));
    if (!grown) die("cannot grow branch metadata");
    g_branch_force = grown;
    grown = realloc(g_branch_tgt, capacity * NAME_MAX);
    if (!grown) die("cannot grow branch metadata");
    g_branch_tgt = grown;
    g_branch_capacity = capacity;
}

static long branch_target_off(const char *target, int section, int *known) {
    if(!strcmp(target,"$")){ *known=1; return cur_off(); } /* INV-595 */
    char q[NAME_MAX]; qualify(target,q); Sym *s=sym_find(q);
    if (s && s->defined && s->section==section) { *known=1; return s->offset; }
    *known=0; return 0;
}

/* Resolve a branch target to its (interned) Sym* by its already-qualified
 * name, or NULL if not yet defined. */
static void *branch_sym_byname(const char *qname) {
    return (void*)sym_find(qname);
}

/* jmp: rel8 (EB) or rel32 (E9). Fixpoint sizing: each sizing pass recomputes
 * every branch's size from the current layout; the driver repeats passes until
 * the layout stops changing (NASM-style shrinking to the minimal encoding). */
static void enc_jmp(const char *target, int force) {
    /* INV-589: immediate far jumps are a pinned bootstrap operation, not a
     * legal long-mode instruction. Segment-prefixed memory is still legal. */
    if(g_target_profile && !g_bootstrap && target[0]!='[' && strchr(target,':'))
        die("target profile: immediate far jump requires bootstrap");
#ifndef BASM_PUBLIC_ONLY
    /* Far direct jump `jmp [dword] sel:offset` — EA <off> <sel16>.
     * boot.S uses `jmp 0x08:long_mode_entry` (32-bit offset) to reload CS;
     * ap_trampoline.S (BITS 16) uses `jmp dword 0x08:(...)` where `dword`
     * forces a 32-bit offset, which in 16-bit mode needs a 0x66 prefix.
     * The offset may be a label expression needing an R_X86_64_32 reloc.
     * Author: F E R M I ∞ H A R T. */
    {
        /* strip an optional leading size keyword (word/dword) */
        int far_opsize = opsize_default();   /* far-jump offset width: 16 or 32 */
        const char *t = target;
        while (*t==' ') t++;
        if (!strncmp(t,"dword",5) && char_in(t[5], ": 0")) { far_opsize=32; t+=5; while(*t==' ')t++; }
        else if (!strncmp(t,"word",4) && char_in(t[4], ": 0")) { far_opsize=16; t+=4; while(*t==' ')t++; }
        const char *colon = strchr(t, ':');
        /* Both fields may carry an ELF relocation in the bootstrap modes. */
        if (colon) {
            if(g_bits==64)die("immediate far jump requires BITS 16 or 32");
            char selstr[NAME_MAX]; int sl=(int)(colon-t);
            if (sl>0 && sl<NAME_MAX) {
                memcpy(selstr,t,sl); selstr[sl]=0;
                ImmediateExpr selector,offset;
                parse_immediate(selstr,&selector); parse_immediate(colon+1,&offset);
                emit_opsize(far_opsize);   /* 0x66 if offset width != mode default */
                emit(0xea);
                emit_arithmetic_immediate(far_opsize/8,&offset);
                emit_arithmetic_immediate(2,&selector);
                return;
            }
        }
    }
#endif
    /* Register-indirect jump: `jmp r12` → FF /4 (REX.B if r8-r15).
     * Fixed-size (no branch relaxation), so handle before the ordinal
     * machinery. Author: F E R M I ∞ H A R T. */
    const Reg *rg = reg_find(target);
    if (rg && rg->size==8) {
        if (rg->num>=8) emit(0x41);          /* REX.B for r8-r15 */
        emit(0xff); emit_modrm(3, 4, rg->num);  /* /4 = jmp r/m64 */
        return;
    }
    /* Memory-indirect jump: `jmp [rdx+192]` (AT&T `jmp *PC(%rdx)`) → FF /4.
     * Without this it falls through to the relative path and collapses to
     * `eb 00`. ucontext's `jmp *PC(%rdx)` needs it. Author: F E R M I HART. */
    if (is_mem(target)) {
        Mem m; parse_mem(target, &m); int rx,rb; mem_begin(&m,&rx,&rb);
       emit_rex(0,0,rx,rb,0);              /* jmp m64: default 64-bit, no REX.W */
        emit(0xff); encode_mem(4, &m, 0);   /* /4 = jmp r/m64 */
        return;
    }
    branch_require();
    int ord = g_branch_ord++;
    int known; long toff = branch_target_off(target,g_cur,&known);
    if (g_sizing) {  /* record only; the driver decides sizes after the pass */
        g_branch_pos[ord]=cur_off(); g_branch_sec[ord]=g_cur;
        g_branch_force[ord]=force; qualify(target,g_branch_tgt[ord]);
    }
    /* A jmp whose target is an EXTERN symbol (declared `extern`, defined in
     * another object — e.g. `jmp switch_to_user`) is resolved at LINK time and
     * MUST use the 5-byte near form E9 + R_X86_64_PC32 reloc.  rel8 (EB) has no
     * room for a relocation, so without this the branch collapsed to `eb 00`
     * (jump to the very next instruction) — a silent fall-through into whatever
     * code follows.  Mirror enc_call's extern path: force the long encoding and
     * emit a PC32 reloc against the named symbol.  Author fix: F E R M I HART. */
    char xq[NAME_MAX]; qualify(target,xq); Sym *xs=sym_find(xq);
    int is_extern = (xs && xs->global && !xs->defined);
    int cross = xs && xs->defined && xs->section!=SEC_NONE && xs->section!=g_cur;
    int is_long = force == 1 || g_branch_long[ord] || is_extern || cross;
    if (cross && (force==0 || g_bits!=64 || strcmp(g_fmt,"elf64")))
        die("cross-section jump requires near ELF64 BITS 64"); /* INV-703 */
    if (force == 0 && is_extern) die("short jump cannot target extern");
    if (!is_long) { long disp=known?toff-(long)(cur_off()+2):0;
        if(!g_sizing && (!known || !fits_imm8(disp))) die2("short jump out of range",target);
        emit(0xeb); emit((uint8_t)disp); }
    else if (is_extern) { emit(0xe9); add_reloc_named(cur_off(), xq, -4); emit32(0); }
    else if (cross) { emit(0xe9); add_reloc_section(cur_off(),xs->section,(long)xs->offset-4); emit32(0); }
    else { emit(0xe9); if(!g_sizing&&!known)die2("jmp target undefined",target);
           emit32((uint32_t)(known?toff-(long)(cur_off()+4):0)); }
}

/* conditional jump: rel8 (70+cc) or rel32 (0F 80+cc). */
static void enc_jcc(int cc, const char *target, int force) {
    branch_require();
    int ord = g_branch_ord++;
    int known; long toff = branch_target_off(target,g_cur,&known);
    if (g_sizing) {  /* record only; the driver decides sizes after the pass */
        g_branch_pos[ord]=cur_off(); g_branch_sec[ord]=g_cur;
        g_branch_force[ord]=force; qualify(target,g_branch_tgt[ord]);
    }
    char q[NAME_MAX]; qualify(target,q); Sym *s=sym_find(q);
    int is_extern = s && s->global && !s->defined;
    int cross = s && s->defined && s->section!=SEC_NONE && s->section!=g_cur;
    int is_long = force == 1 || g_branch_long[ord] || is_extern || cross;
    if (cross && (force==0 || g_bits!=64 || strcmp(g_fmt,"elf64")))
        die("cross-section conditional jump requires near ELF64 BITS 64"); /* INV-703 */
    if (force == 0 && is_extern) die("short conditional jump cannot target extern");
    if (!is_long) { long disp=known?toff-(long)(cur_off()+2):0;
        if(!g_sizing && (!known || !fits_imm8(disp))) die2("short conditional jump out of range",target);
        emit(0x70+cc); emit((uint8_t)disp); }
    else if (is_extern) { emit(0x0f); emit(0x80+cc); add_reloc_named(cur_off(),q,-4); emit32(0); }
    else if (cross) { emit(0x0f); emit(0x80+cc); add_reloc_section(cur_off(),s->section,(long)s->offset-4); emit32(0); }
    else { emit(0x0f); emit(0x80+cc); if(!g_sizing&&!known)die2("jcc target undefined",target);
           emit32((uint32_t)(known?toff-(long)(cur_off()+4):0)); }
}

static void enc_loop(const char *target) {
    int known; long toff=branch_target_off(target,g_cur,&known);
    if (g_pass==1 && !known) g_fwd_unresolved=1; /* INV-545 */
    long disp=known?toff-(long)(cur_off()+2):0;
    if(!g_sizing && (!known || !fits_imm8(disp))) die2("loop target out of range",target);
    emit(0xe2); emit((uint8_t)disp);
}

/* After a sizing pass, decide branch sizes from the just-recorded consistent
 * layout. Target offset is re-read from the Sym NOW (every label holds this
 * pass's offset), so forward and backward branches use the SAME layout. A
 * branch needs rel32 iff, as rel8, its displacement (target - end-of-2-byte-
 * insn) doesn't fit a signed byte. Returns 1 if any branch's size changed. */
static int branch_decide(int nbr) {
    int changed=0;
    for (int ord=0; ord<nbr; ord++) {
        int next_long = g_branch_long[ord];
        if (g_branch_force[ord] == 0) next_long = 0;
        if (g_branch_force[ord] == 1) {
            next_long = 1;
        } else if (g_branch_force[ord] != 0) {
            Sym *s = (Sym*)branch_sym_byname(g_branch_tgt[ord]);
            if (s && s->global && !s->defined) {
                next_long = 1; /* INV-545: late extern declarations need rel32. */
            } else if (s && s->defined && s->section==g_branch_sec[ord]) {
                long disp = s->offset - (g_branch_pos[ord] + 2);
                next_long = !fits_imm8(disp);
            } else if (s && s->defined && s->section!=SEC_NONE) {
                next_long = 1; /* INV-703: cross-section displacements need a link-time field. */
            }
        }
        if (g_branch_long[ord] != next_long) { g_branch_long[ord]=next_long; changed=1; }
    }
    return changed;
}

/* ------------------------------------------------------------------ */
/* Instruction dispatch                                               */
/* ------------------------------------------------------------------ */
static int is_size_kw(const char *t){ return !strcmp(t,"byte")||!strcmp(t,"word")||!strcmp(t,"dword")||!strcmp(t,"qword"); }

/* INV-740/741: tokenization drops commas; retain the same raw-line boundary. */
static int source_commas(void) {
    int n=0;
    for (const char *p=g_data_source;p && *p && !char_in(*p,"\n;\r");p++) if (*p==',') n++;
    return n;
}

/* Join tokens [from..g_ntok) into one expression string (operands like
 * "'a' - 10" get split by the tokenizer on spaces; rejoin them here). */
static void join_from(int from, char *out, int outsz) {
    out[0]=0; int len=0;
    for (int i=from;i<g_ntok;i++){ int tl=(int)strlen(g_tok[i]);
        if (len+tl+1>=outsz) die("operand expression too long");
        memcpy(out+len,g_tok[i],tl); len+=tl; out[len]=0; }
}

static void enc_alu_dispatch(int ext) {
    int immediate_index=g_ntok==4 && is_size_kw(g_tok[1]) ? 3 : 2;
    if(g_ntok!=immediate_index+1 || g_token_trailing_comma || g_tok_precomma[0] ||
       g_tok_precomma[1] || !g_tok_precomma[immediate_index] ||
       (immediate_index==3 && g_tok_precomma[2]))die("alu needs two comma-separated operands");
    if (g_ntok==4 && is_size_kw(g_tok[1]) && reg_find(g_tok[3])) enc_alu(ext,g_tok[2],g_tok[3]);
    else if (g_ntok==4 && is_size_kw(g_tok[1])) enc_alu_mem_imm(ext,g_tok[1],g_tok[2],g_tok[3]);
    else enc_alu(ext,g_tok[1],g_tok[2]);
}

static int branch_force_arg(int *target_index) {
    if (g_ntok > 2 && !strcmp(g_tok[1],"short")) { *target_index=2; return 0; }
    if (g_ntok > 2 && !strcmp(g_tok[1],"near"))  { *target_index=2; return 1; }
    *target_index=1; return -1;
}

/* INV-586: share operand dispatch rather than spilling it for every Jcc. */
static void enc_jcc_dispatch(int cc) {
    int ti; int force=branch_force_arg(&ti); enc_jcc(cc,g_tok[ti],force);
}

static int vec_reg(const char *s, int *is_ymm) {
    const char *p;
    if (!strncmp(s,"xmm",3)) { *is_ymm=0; p=s+3; }
    else if (!strncmp(s,"ymm",3)) { *is_ymm=1; p=s+3; }
    else return -1;
    if (!isdigit((unsigned char)*p)) return -1;
    int n=0; while(isdigit((unsigned char)*p)) { if(n>15)return -1; n=n*10+(*p++-'0'); }
    return (*p==0 && n<16)?n:-1;
}

static void emit_vex(int map, int pp, int l, int reg, int vvvv, int x, int b) {
    int r=reg>=8;
    if (map==1 && !x && !b) {
        emit(0xc5); emit(((!r)&1)<<7 | ((~vvvv)&15)<<3 | (l<<2) | pp);
    } else {
        emit(0xc4); emit(((!r)&1)<<7 | ((!x)&1)<<6 | ((!b)&1)<<5 | map);
        emit(((~vvvv)&15)<<3 | (l<<2) | pp);
    }
}

/* INV-740: one closed descriptor drives bytes and declared effects. No AVX
 * replacement, arithmetic memory operands, implicit narrowing or flag claims. */
static void enc_sse(void) {
    if (g_bits!=64 || g_intent_prefix || g_ntok<3 || g_ntok>4)
        die("SSE requires unprefixed bounded operands in BITS 64");
    const char *p=g_data_source;
    while (*p && !char_in(*p,",;\r\n")) p++;
    if (*p!=',') die("SSE requires operand commas");
    const char *end=p;
    while (end>g_data_source && char_in(end[-1]," \t")) end--;
    size_t len=strlen(g_tok[1]);
    if ((size_t)(end-g_data_source)<=len) die("SSE malformed destination");
    p=end-len;
    if (!char_in(p[-1]," \t")) die("SSE malformed destination");
    for (int i=1;i<g_ntok;i++) {
        len=strlen(g_tok[i]);
        if (strncmp(p,g_tok[i],len)) die("SSE malformed operand");
        p+=len;
        while (char_in(*p," \t")) p++;
        if (i+1<g_ntok) {
            if (*p++!=',') die("SSE requires exactly separated operands");
            while (char_in(*p," \t")) p++;
        }
    }
    if (*p && !char_in(*p,";\r\n")) die("SSE trailing operand text");
    int yd=0,ys=0,rd=vec_reg(g_tok[1],&yd),rs=vec_reg(g_tok[2],&ys);
    if (yd || ys) die("SSE accepts only XMM registers");
    int encoding=INTENT_SSE_RR, reg=rd, rm=rs, imm=-1;
    const char *mem=NULL;
    if (!strcmp(g_tok[0],"pslld") || !strcmp(g_tok[0],"psrld")) {
        encoding=INTENT_SSE_SHIFT; rm=rd; reg=g_tok[0][2]=='l' ? 6 : 2;
        imm=(int)sse_literal(g_tok[2],255);
    } else if (g_ntok==4) {
        encoding=INTENT_SSE_SHUF; imm=(int)sse_literal(g_tok[3],255);
    } else if (is_mem(g_tok[2])) { encoding=INTENT_SSE_RM; mem=g_tok[2]; }
    else if (is_mem(g_tok[1])) { encoding=INTENT_SSE_MR; mem=g_tok[1]; reg=rs; }
    else if (rs<0 && rd>=0) {
        const Reg *r=reg_find(g_tok[2]);
        if (r && r->size==8) { encoding=INTENT_SSE_XG; rm=r->num; }
    } else if (rd<0 && rs>=0) {
        const Reg *r=reg_find(g_tok[1]);
        if (r && r->size==8) { encoding=INTENT_SSE_GX; reg=rs; rm=r->num; }
    }
    if (reg<0 || (!mem && rm<0) || (encoding==INTENT_SSE_SHIFT && g_ntok!=3))
        die("SSE unsupported operands");
    const IntentForm *form=NULL;
    for (int i=0;i<INTENT_FORM_COUNT;i++) {
        const IntentForm *f=&g_intent_forms[i];
        if (f->encoding==encoding && !strcmp(f->mnemonic,g_tok[0])) { form=f; break; }
    }
    if (!form) die("SSE unsupported form");
    int x=0,b=rm>=8; Mem m;
    if (mem) { g_bounded_sse=1; parse_mem(mem,&m); mem_begin(&m,&x,&b); }
    int first=0;
    if (form->opcode[0]!=0x0f) emit(form->opcode[first++]);
    emit_rex(encoding==INTENT_SSE_XG || encoding==INTENT_SSE_GX,reg>=8,x,b,0);
    emit_span(form->opcode+first,(size_t)(form->opcode_len-first));
    if (mem) encode_mem(reg,&m,0); else emit_modrm(3,reg,rm);
    g_bounded_sse=0;
    if (imm>=0) emit((uint8_t)imm);
    if (g_target_profile) g_intent_form_current=form;
}

static void enc_vmov(int pp, const char *dst, const char *src) {
    int yd=0,ys=0; int rd=vec_reg(dst,&yd),rs=vec_reg(src,&ys);
    if (rd>=0 && yd && is_mem(src)) { Mem m; parse_mem(src,&m); int x,b; mem_begin(&m,&x,&b);
        emit_vex(1,pp,1,rd,0,x,b); emit(0x6f); encode_mem(rd,&m,0); return; }
    if (is_mem(dst) && rs>=0 && ys) { Mem m; parse_mem(dst,&m); int x,b; mem_begin(&m,&x,&b);
        emit_vex(1,pp,1,rs,0,x,b); emit(0x7f); encode_mem(rs,&m,0); return; }
    die("vmovdqa/vmovdqu needs ymm, m256 or m256, ymm");
}

/* INV-740: share VEX mechanics, preserving both existing validation contracts. */
static void enc_vex_nds_common(int pp, int opcode, const char *dst, const char *src1, const char *src2) {
    int yd=0,y1=0,y2=0; int rd=vec_reg(dst,&yd),r1=vec_reg(src1,&y1),r2=vec_reg(src2,&y2);
    if (rd<0 || r1<0 || (pp ? !yd || !y1 : yd!=y1))
        die(pp ? "AVX instruction needs YMM destination/source" : "AVX ps instruction needs matching vector destination/source");
    if (r2>=0) {
        if (pp ? !y2 : y2!=yd) die(pp ? "AVX instruction needs YMM source" : "AVX ps instruction needs matching vector source");
        emit_vex(1,pp,yd,rd,r1,0,r2>=8); emit(opcode); emit_modrm(3,rd,r2); return;
    }
    if (is_mem(src2)) { Mem m; parse_mem(src2,&m); int x,b; mem_begin(&m,&x,&b);
        emit_vex(1,pp,yd,rd,r1,x,b); emit(opcode); encode_mem(rd,&m,0); return; }
    die(pp ? "AVX instruction needs YMM or memory source" : "AVX ps instruction needs vector or memory source");
}
#define enc_vex_nds(op,d,s,t) enc_vex_nds_common(1,op,d,s,t)
#define enc_vex_ps_nds(op,d,s,t) enc_vex_nds_common(0,op,d,s,t)

static void enc_vbroadcastss(const char *dst, const char *src) {
    int yd=0,ys=0; int rd=vec_reg(dst,&yd),rs=vec_reg(src,&ys);
    if (rd<0) die("vbroadcastss needs vector destination");
    if (rs>=0) { if(ys)die("vbroadcastss register source must be XMM"); emit_vex(2,1,yd,rd,0,0,rs>=8); emit(0x18); emit_modrm(3,rd,rs); return; }
    if (is_mem(src)) { Mem m; parse_mem(src,&m); int x,b; mem_begin(&m,&x,&b);
        emit_vex(2,1,yd,rd,0,x,b); emit(0x18); encode_mem(rd,&m,0); return; }
    die("vbroadcastss needs XMM or memory source");
}

static void enc_vptest(const char *a, const char *bop) {
    int ya=0,yb=0; int ra=vec_reg(a,&ya),rbv=vec_reg(bop,&yb);
    if(ra<0||!ya)die("vptest needs ymm operands");
    if(rbv>=0){if(!yb)die("vptest needs ymm operands");emit_vex(2,1,1,ra,0,0,rbv>=8);emit(0x17);emit_modrm(3,ra,rbv);return;}
    if(is_mem(bop)){Mem m;parse_mem(bop,&m);int x,b;mem_begin(&m,&x,&b);emit_vex(2,1,1,ra,0,x,b);emit(0x17);encode_mem(ra,&m,0);return;}
    die("vptest needs ymm or memory source");
}

/* O(1) instruction dispatch: mnemonics are hashed once into an enum, then
 * a single integer switch routes to the encoder. Author: F E R M I ∞ H A R T. */
typedef enum {
    INSN_adc, INSN_add, INSN_and, INSN_btr, INSN_call, INSN_cdq, INSN_cdqe, INSN_clac,
    INSN_clc, INSN_cld, INSN_cli, INSN_clts, INSN_cmp, INSN_cpuid, INSN_cqo,
    INSN_cwde, INSN_dec, INSN_div, INSN_fninit, INSN_fnsave, INSN_fnstcw,
    INSN_fnstsw, INSN_frstor, INSN_fwait, INSN_fxrstor, INSN_fxrstor64,
    INSN_fxsave, INSN_fxsave64, INSN_hlt,
    INSN_idiv, INSN_imul, INSN_in, INSN_inc, INSN_insb, INSN_insd, INSN_insw,
    INSN_int, INSN_int3, INSN_invlpg, INSN_invpcid, INSN_iret, INSN_iretd, INSN_iretq, INSN_ja,
    INSN_jae, INSN_jb, INSN_jbe, INSN_jc, INSN_je, INSN_jg, INSN_jge, INSN_jl,
    INSN_jle, INSN_jmp, INSN_jnc, INSN_jne, INSN_jns, INSN_jnz, INSN_js,
    INSN_jz, INSN_lea, INSN_leave, INSN_lfence, INSN_lgdt, INSN_lidt, INSN_lldt, INSN_lock, INSN_loop,
    INSN_lodsb, INSN_lodsd, INSN_ltr, INSN_mfence, INSN_monitor, INSN_mov,
    INSN_sse, INSN_movnti, INSN_movsb, INSN_movsd, INSN_movsq, INSN_movsx, INSN_movsxd, INSN_movzx,
    INSN_mul, INSN_mwait, INSN_neg, INSN_nop, INSN_o64, INSN_or, INSN_out,
    INSN_outsb, INSN_outsd, INSN_outsw, INSN_pause, INSN_prefetcht0, INSN_pop, INSN_popa,
    INSN_popad, INSN_popf, INSN_popfq, INSN_push, INSN_pusha, INSN_pushad,
    INSN_pushf, INSN_pushfq, INSN_rdfsbase, INSN_rdmsr, INSN_rdpkru,
    INSN_rdrand, INSN_rdseed, INSN_rdtsc, INSN_rdtscp, INSN_rep, INSN_repe,
    INSN_repne, INSN_repnz, INSN_repz, INSN_ret, INSN_retf, INSN_retfq,
    INSN_rol, INSN_ror, INSN_sar, INSN_sbb, INSN_scasb, INSN_sfence, INSN_sgdt, INSN_shl, INSN_shr, INSN_sidt, INSN_stac,
    INSN_stc, INSN_std, INSN_sti, INSN_stosb, INSN_stosd, INSN_stosq,
    INSN_stosw, INSN_sub, INSN_swapgs, INSN_syscall, INSN_sysret, INSN_sysretq,
    INSN_sete, INSN_setne, INSN_setl, INSN_setg, INSN_setle, INSN_setge,
    INSN_setb, INSN_setae, INSN_setbe, INSN_seta, INSN_seto, INSN_setno,
    INSN_sets, INSN_setns, INSN_setp, INSN_setnp,
    INSN_test, INSN_ud2, INSN_wbinvd, INSN_wrfsbase, INSN_wrmsr, INSN_wrpkru,
    INSN_fldcw, INSN_ldmxcsr, INSN_stmxcsr, INSN_vaddps, INSN_vbroadcastss,
    INSN_vmovdqa, INSN_vmovdqu, INSN_vmulps, INSN_vpcmpeqd, INSN_vpor, INSN_vptest, INSN_vpxor, INSN_vxorps,
    INSN_xchg, INSN_xgetbv, INSN_xor, INSN_xrstor, INSN_xsave, INSN_xsetbv, INSN_endbr64,
    INSN_COUNT, INSN_UNKNOWN = INSN_COUNT
} InsnKind;

static InsnKind insn_kind(const char *op);
static const IntentForm *g_fixed_forms[INSN_COUNT];

#define INSN_HT_CAP 256
typedef struct { uint32_t hash; uint8_t len; InsnKind kind; const char *name; } InsnHTEntry;
static InsnHTEntry g_insn_ht[INSN_HT_CAP];
static int g_insn_ht_ready = 0;
static size_t g_insn_max_len;

static void insn_ht_insert(const char *name, InsnKind kind) {
    size_t nl = strlen(name);
    if(nl>255)die("instruction name too long for dispatch table");
    if(nl>g_insn_max_len)g_insn_max_len=nl;
    uint32_t h = str_hash(name, nl);
    int mask = INSN_HT_CAP - 1;
    int i = (int)(h & (uint32_t)mask), probes=0;
    while(g_insn_ht[i].hash && probes<INSN_HT_CAP){i=(i+1)&mask;probes++;}
    if(probes==INSN_HT_CAP)die("instruction dispatch table full");
    g_insn_ht[i].hash = h;
    g_insn_ht[i].len = (uint8_t)nl;
    g_insn_ht[i].kind = kind;
    g_insn_ht[i].name = name;
}

/* INV-572: one registration loop, not a spill-heavy call site per name.
 * File-scope data avoids Bear's per-entry local initializer code. Explicit
 * enum pairs retain the vocabulary and insertion order. */
static const struct { const char *name; InsnKind kind; } g_insn_names[] = {
#define I(name) {#name, INSN_##name}
    I(adc), I(add), I(and), I(btr), I(call), I(cdq), I(cdqe), I(clac), I(clc), I(cld),
    I(cli), I(clts), I(cmp), I(cpuid), I(cqo), I(cwde), I(dec), I(div),
    I(fninit), I(fnsave), I(fnstcw), I(fnstsw), I(frstor), I(fwait),
    I(fxrstor), I(fxrstor64), I(fxsave), I(fxsave64), I(hlt), I(idiv), I(imul),
    I(in), I(inc), I(insb),
    I(insd), I(insw), I(int), I(int3), I(invlpg), I(invpcid), I(iret), I(iretd), I(iretq), I(ja),
    I(jae), I(jb), I(jbe), I(jc), I(je), I(jg), I(jge), I(jl), I(jle), I(jmp),
    I(jnc), I(jne), I(jns), I(jnz), I(js), I(jz), I(lea), I(leave), I(lgdt),
    I(lidt), I(lldt), I(lock), I(lodsb), I(lodsd), I(loop), I(ltr), I(lfence), I(mfence),
    I(monitor), I(mov), I(movnti), I(movsb), I(movsd), I(movsq), I(movsx), I(movsxd),
    I(movzx), I(mul), I(mwait), I(neg), I(nop), I(o64), I(or), I(out), I(outsb),
    I(outsd), I(outsw), I(pause), I(pop), I(popf), I(popfq),
    I(prefetcht0),
    I(push), I(pushf), I(pushfq), I(rdfsbase), I(rdmsr),
#ifndef BASM_PUBLIC_ONLY
    I(popa), I(popad), I(pusha), I(pushad),
#endif
    I(rdpkru), I(rdrand), I(rdseed), I(rdtsc), I(rdtscp), I(rep), I(repe),
    I(repne), I(repnz), I(repz), I(ret), I(retf), I(retfq), I(rol), I(ror), I(sar), I(sbb), I(scasb), I(sfence),
    I(sgdt), I(shl), I(shr), I(sidt), I(stac), I(stc), I(std), I(sti),
    I(stosb), I(stosd), I(stosq), I(stosw), I(sub), I(swapgs), I(syscall),
    I(sysret), I(sysretq), I(sete), I(setne), I(setl), I(setg), I(setle), I(setge),
    I(setb), I(setae), I(setbe), I(seta), I(seto), I(setno), I(sets), I(setns),
    I(setp), I(setnp), I(test), I(ud2), I(wbinvd), I(wrfsbase), I(wrmsr),
    I(fldcw), I(ldmxcsr), I(stmxcsr), I(vaddps), I(vbroadcastss), I(vmovdqa), I(vmovdqu), I(vmulps), I(vpcmpeqd),
    I(vpor), I(vptest), I(vpxor), I(vxorps), I(wrpkru), I(xchg), I(xgetbv), I(xor), I(xrstor), I(xsave), I(xsetbv),
    INTENT_SSE_NAMES(INSN_sse), I(endbr64)
#undef I
};

static void insn_ht_init(void) {
    if (g_insn_ht_ready) return;
    for (size_t i=0;i<sizeof(g_insn_names)/sizeof(g_insn_names[0]);i++)
        insn_ht_insert(g_insn_names[i].name,g_insn_names[i].kind);
    g_insn_ht_ready = 1;
    /* Resolve descriptors once through the registered vocabulary. Mark the
     * hash ready first so insn_kind does not recurse into initialization. */
    for(int i=0;i<INTENT_FORM_COUNT;i++){
        const IntentForm *form=&g_intent_forms[i];
        if(form->encoding!=INTENT_FIXED)continue;
        InsnKind kind=insn_kind(form->mnemonic);
        if(kind==INSN_UNKNOWN)die2("intent: unregistered fixed form",form->mnemonic);
        g_fixed_forms[kind]=form;
    }
}

/* SETcc r8: 0F 9X+cond /0 (ModRM.reg=0, rm=reg). The codegen emits
 * `setX al` etc. so the operand is an 8-bit register. Author: F E R M I ∞ H A R T. */
static const uint8_t g_setcc_codes[] = {4,5,12,15,14,13,2,3,6,7,0,1,8,9,10,11};
static const uint8_t g_jcc_codes[] = {7,3,2,6,2,4,15,13,12,14,0,3,5,9,5,8,4};
static void enc_setcc(InsnKind insn, const char *reg) {
    const Reg *rd = reg_find(reg);
    if (!rd || rd->size != 1) die("setcc needs an 8-bit register");
    /* Map INSN to the condition nibble (the 0F 9X opcode byte).
     * SETcc encoding: 0F 90+cc /0, where cc is the condition code.
     * seto=0, setno=1, setb=2(setc=2), setae=3(setnc=3),
     * sete=4(setz=4), setne=5(setnz=5), setbe=6(setna=6), seta=7(setnbe=7),
     * setl=0xC, setge=0xD, setle=0xE, setg=0xF,
     * sets=8, setns=9, setp=0xA(setpo=0xA), setnp=0xB. */
    uint8_t cc=0;
    if (insn>=INSN_sete && insn<=INSN_setnp) cc=g_setcc_codes[insn-INSN_sete];
    /* REX: W=0, R=0 (the /0 extension), X=0, B=(rd>=8), force for spl/bpl/sil/dil */
    emit_rex(0, 0, 0, rd->num >= 8, rd->rex_req);
    emit(0x0f); emit(0x90 + (cc & 0xF));
    emit_modrm(3, 0, rd->num & 7);          /* /0, register-direct */
}
static InsnKind insn_kind(const char *op) {
    if (!g_insn_ht_ready) insn_ht_init();
    /* N07: determine length and hash together. A name beyond the longest
     * registered spelling cannot match; hash/length/bytes still all verify. */
    size_t nl=0;
    uint32_t h=2166136261u;
    while(op[nl]){
        if(nl>=g_insn_max_len)return INSN_UNKNOWN;
        h^=(unsigned char)op[nl++]; h*=16777619u;
    }
    if(!h)h=1;
    int mask = INSN_HT_CAP - 1;
    int i = (int)(h & (uint32_t)mask);
    for(int probes=0;probes<INSN_HT_CAP && g_insn_ht[i].hash;probes++) {
        if (g_insn_ht[i].hash == h && g_insn_ht[i].len == nl &&
            memcmp(op, g_insn_ht[i].name, nl) == 0)
            return g_insn_ht[i].kind;
        i = (i + 1) & mask;
    }
    return INSN_UNKNOWN;
}

/* N08: this helper is reached only after complete raw-line validation.
 * Select the same immutable descriptor used by fixed_emit; no copied token
 * array or synthetic g_ntok is needed for these two operand-free forms. */
static int fast_fixed_span(const char *op,size_t len) {
    if(len!=3)return 0;
    InsnKind kind;
    if(op[0]=='n' && op[1]=='o' && op[2]=='p')kind=INSN_nop;
    else if(op[0]=='r' && op[1]=='e' && op[2]=='t')kind=INSN_ret;
    else return 0;
    insn_ht_init();
    const IntentForm *form=g_fixed_forms[kind];
    if(!form)return 0;
    g_intent_instruction=1;
    if(g_target_profile && g_bits==64 && !g_intent_prefix)g_intent_form_current=form;
    emit_span(form->opcode,(size_t)form->opcode_len);
    return 1;
}

static InsnKind g_prefetched_insn_kind=INSN_UNKNOWN;

/* INV-572: memory-only /digit forms differ only in opcode and REX.W.
 * Keep parse_mem/mem_begin before REX, including legacy address prefixes. */
static void enc_mem_group(const char *src, int opcode, int ext, int w) {
    Mem m; parse_mem(src,&m);
    int x,b; mem_begin(&m,&x,&b);
    emit_rex(w,0,x,b,0);
    if (opcode>255) emit(opcode>>8);
    emit((uint8_t)opcode);
    encode_mem(ext,&m,0);
}

/* Keep complex instruction families out of the central dispatcher so Bear
 * does not spill all of their independent locals into one oversized frame. */
static void enc_adc_rotate(InsnKind kind, const char *op) {
    if (g_bits!=64 || g_ntok!=3 || g_intent_prefix)
        die("adc/rotate requires two unprefixed operands in BITS 64");
    const Reg *rd=reg_find(g_tok[1]), *rs=reg_find(g_tok[2]);
    if (!rd || (rd->size!=4 && rd->size!=8))
        die("adc/rotate requires a supported r32/r64 destination");
    int commas=source_commas();
    if (commas>1) die("adc/rotate requires exactly one operand comma");
    if (!commas) die("adc/rotate requires an operand comma");
    const char *comma=strchr(g_data_source,',');
    const char *end=comma;
    while (end>g_data_source && char_in(end[-1]," \t")) end--;
    const char *start=end;
    while (start>g_data_source && !char_in(start[-1]," \t:")) start--;
    size_t len=(size_t)(end-start);
    if (len!=strlen(g_tok[1]) || memcmp(start,g_tok[1],len))
        die("adc/rotate comma must follow destination");
    start=comma+1;
    while (char_in(*start," \t")) start++;
    len=strlen(g_tok[2]);
    if (strncmp(start,g_tok[2],len)) die("adc/rotate invalid source operand");
    start+=len;
    while (char_in(*start," \t")) start++;
    if (*start && !char_in(*start,"\n;\r")) die("adc/rotate trailing operand text");
    if (kind==INSN_adc) {
        if (!rs || rd->size!=rs->size) die("adc supports only same-width r32/r32 or r64/r64");
        enc_alu_rr(0x11,rd,rs);
    } else {
        const IntentForm *form=NULL;
        for (int i=0;i<INTENT_FORM_COUNT;i++) {
            const IntentForm *f=&g_intent_forms[i];
            if (f->encoding==INTENT_GPR_ROTATE && f->width==rd->size*8 &&
                !strcmp(f->mnemonic,op) && !strcmp(f->operands+4,g_tok[2])) { form=f; break; }
        }
        if (!form) die("rotate supports only ror r64,1 or rol r32,8 (literal counts)");
        emit_rex(form->width==64,0,0,rd->num>=8,0);
        emit(form->opcode[0]); emit_modrm(3,kind==INSN_ror,rd->num);
        if (kind==INSN_rol) emit(8);
        if (g_target_profile) g_intent_form_current=form;
    }
}

static void enc_mov_dispatch(void) {
    const Reg *plain_dst=reg_find(g_tok[1]);
    const Reg *plain_src=(g_ntok==3 && isalpha((unsigned char)g_tok[2][0]))?reg_find(g_tok[2]):NULL;
    if(plain_dst && plain_src){ enc_mov_rr(plain_dst,plain_src); return; }
    if (g_ntok==4 && plain_dst && is_size_kw(g_tok[2])) {
        int width=!strcmp(g_tok[2],"dword") ? 4 : !strcmp(g_tok[2],"qword") ? 8 : 0;
        if (!width || width!=plain_dst->size || !is_mem(g_tok[3]))
            die("mov explicit load requires matching r32/dword or r64/qword memory");
        enc_mov(g_tok[1],g_tok[3]); return;
    }
    int cd = cr_reg(g_tok[1]);
    int cs2 = g_ntok>2 ? cr_reg(g_tok[2]) : -1;
    if (cd>=0 || cs2>=0) {
        if (g_ntok!=3 || g_intent_prefix || source_commas()!=1) die("mov CR requires two unprefixed comma-separated operands");
        const char *p=strchr(g_data_source,',')+1;
        while (char_in(*p," \t")) p++;
        size_t n=strlen(g_tok[2]);
        if (strncmp(p,g_tok[2],n)) die("mov CR malformed source");
        p+=n;
        while (char_in(*p," \t")) p++;
        if (*p && !char_in(*p,";\r\n")) die("mov CR trailing operands");
        const Reg *r=reg_find(g_tok[cd>=0 ? 2 : 1]);
        if (!r || r->size!=(g_bits==64 ? 8 : 4) || (g_bits!=64 && r->num>=8))
            die("mov CR register width does not match BITS mode");
        if (r->num>=8) emit(0x41);
        emit(0x0f); emit(cd>=0 ? 0x22 : 0x20); emit_modrm(3,cd>=0 ? cd : cs2,r->num);
        return;
    }
    int sd = seg_reg(g_tok[1]);
    int ss2 = seg_reg(g_tok[2]);
    if (sd >= 0) { const Reg*rs=reg_find(g_tok[2]); if(!rs)die("mov sreg needs r16/r32");
        if(rs->num>=8)emit(0x41); emit(0x8e); emit_modrm(3,sd,rs->num&7); }
    else if (ss2 >= 0) { const Reg*rd=reg_find(g_tok[1]); if(!rd)die("mov from sreg needs r16/r32");
        if(rd->size==2)emit(0x66); if(rd->num>=8)emit(0x41); emit(0x8c); emit_modrm(3,ss2,rd->num&7); }
    else if (g_ntok==4 && is_size_kw(g_tok[1])) {
        if (reg_find(g_tok[3])) enc_mov(g_tok[2], g_tok[3]);
        else enc_mov_mem_imm(g_tok[1],g_tok[2],g_tok[3]);
    }
    else enc_mov(g_tok[1],g_tok[2]);
}

static void enc_push_dispatch(void) {
    if(g_target_profile && g_bits==64 && is_size_kw(g_tok[1]) &&
       strcmp(g_tok[1],"qword") &&
       (strcmp(g_tok[1],"byte") || (g_ntok>2 && is_mem(g_tok[2]))))
        die("target profile: unsupported push width");
    if (reg_find(g_tok[1])) enc_push(g_tok[1]);
    else if (is_mem(g_tok[1]) || (is_size_kw(g_tok[1]) && g_ntok>2 && is_mem(g_tok[2]))) {
        const char *mt = is_mem(g_tok[1]) ? g_tok[1] : g_tok[2];
        Mem m; parse_mem(mt, &m); int rx,rb; mem_begin(&m,&rx,&rb);
        emit_rex(0,0,rx,rb,0);
        emit(0xff); encode_mem(6, &m, 0);
    } else {
        const char *imt = is_size_kw(g_tok[1]) ? g_tok[2] : g_tok[1];
        int has_sym=0,section=SEC_NONE,global=0; long offset=0; char name[NAME_MAX];
        long imm;
        if(g_target_profile && !strcmp(g_tok[1],"byte")){
            char expression[256]; size_t used=0;
            for(int i=2;i<g_ntok;i++){
                size_t n=strlen(g_tok[i]);
                if(used+n+2>sizeof(expression))die("push expression too long");
                if(used)expression[used++]=' ';
                memcpy(expression+used,g_tok[i],n); used+=n;
            }
            expression[used]=0;
            imm=parse_expr_reloc(expression,&has_sym,&section,&offset,name,&global);
        } else imm=parse_expr_reloc(imt,&has_sym,&section,&offset,name,&global);
        if(g_target_profile && !strcmp(g_tok[1],"byte") &&
           (has_sym || !fits_imm8(imm)))
            die("target profile: push byte requires signed imm8 constant");
        if (has_sym) {
            emit(0x68);
            emit_expr_field(4,g_bits==64 ? 11 : 10,imm,has_sym,section,global,name);
        } else if (fits_imm8(imm)) {
            emit(0x6a); emit((uint8_t)imm);
        } else {
            emit(0x68); emit32((uint32_t)imm);
        }
    }
}

static void enc_test_dispatch(void) {
    if(g_ntok!=3 || g_token_trailing_comma || g_tok_precomma[0] ||
       g_tok_precomma[1] || !g_tok_precomma[2])die("test needs two comma-separated operands");
    const Reg*rd=reg_find(g_tok[1]),*rs=reg_find(g_tok[2]);
    if(rd && rs){
        if(rd->size!=rs->size)die("test requires same-width registers");
        if(rd->size==1 && (rd->rex_req || rs->rex_req || rd->num>=8 || rs->num>=8) &&
           ((rd->num>=4 && rd->num<8 && !rd->rex_req) ||
            (rs->num>=4 && rs->num<8 && !rs->rex_req)))die("test high byte register conflicts with REX");
        if(rd->size==1){ emit_rex(0,(rs->num>=8),0,(rd->num>=8),(rd->rex_req||rs->rex_req)); emit(0x84); emit_modrm(3,rs->num,rd->num); }
        else { emit_opsize(rd->size==2 ? 16 : 32); emit_rex(rd->size==8,(rs->num>=8),0,(rd->num>=8),0); emit(0x85); emit_modrm(3,rs->num,rd->num); }
    } else if(rd && !rs && !is_mem(g_tok[2])){
        ImmediateExpr imm; parse_immediate(g_tok[2],&imm);
        int rb=(rd->num>=8);
        if(rd->size==1){
            if(rd->num==0 && !rd->rex_req)emit(0xa8);
            else { emit_rex(0,0,0,rb,rd->rex_req); emit(0xf6); emit_modrm(3,0,rd->num); }
        } else {
            if(rd->size==2)emit_opsize(16); else if(rd->size==4)emit_opsize(32);
            emit_rex(rd->size==8,0,0,rb,0);
            if(rd->num==0)emit(0xa9); else { emit(0xf7); emit_modrm(3,0,rd->num); }
        }
        emit_arithmetic_immediate(rd->size,&imm);
    } else die("test reg,reg");
}

/* Keep more complex families out of the central dispatcher so Bear does not
 * spill all of their independent locals into one oversized frame. Each helper
 * preserves the original validation, diagnostics and encoding exactly. */
static void enc_sbb_dispatch(void) {
    if (g_bits!=64 || g_ntok!=3) die("sbb requires two same-width registers in BITS 64");
    const Reg *rd=reg_find(g_tok[1]), *rs=reg_find(g_tok[2]);
    if (!rd || !rs || rd->size!=rs->size) die("sbb requires same-width registers");
    if (source_commas()!=1) die("sbb requires exactly two operands");
    int rex=rd->num>=8 || rs->num>=8 || rd->rex_req || rs->rex_req;
    if (rd->size==1 && rex && ((rd->num>=4 && rd->num<8 && !rd->rex_req) ||
                               (rs->num>=4 && rs->num<8 && !rs->rex_req)))
        die("sbb high byte register conflicts with REX");
    enc_alu_rr(0x19,rd,rs);
}

static void enc_movnti_dispatch(void) {
    int explicit_size=0, at=1;
    if (g_ntok==4 && is_size_kw(g_tok[1])) {
        explicit_size=!strcmp(g_tok[1],"dword") ? 4 : !strcmp(g_tok[1],"qword") ? 8 : -1;
        at=2;
    }
    if (g_bits!=64 || g_ntok!=at+2 || g_tok[at][0]!='[')
        die("movnti requires memory, r32/r64 in BITS 64");
    const Reg *r=reg_find(g_tok[at+1]);
    if (!r || (r->size!=4 && r->size!=8) || (explicit_size && explicit_size!=r->size))
        die("movnti operand width mismatch");
    if (source_commas()!=1) die("movnti requires exactly two operands");
    Mem m; parse_mem(g_tok[at],&m);
    if ((!m.rip && m.disp_has_sym) || (m.has_index && m.index==4) ||
        m.disp < -2147483647L-1 || m.disp > 2147483647L)
        die("movnti unsupported displacement/index; symbolic addresses require rel");
    int x,b; mem_begin(&m,&x,&b);
    emit_rex(r->size==8,r->num>=8,x,b,0); emit(0x0f); emit(0xc3); encode_mem(r->num,&m,0);
}

static void enc_prefetcht0_dispatch(void) {
    if (g_bits!=64 || g_ntok!=2 || g_tok[1][0]!='[')
        die("prefetcht0 requires one unsized memory operand in BITS 64");
    if (source_commas()) die("prefetcht0 does not accept commas");
    Mem m; parse_mem(g_tok[1],&m);
    if (!m.rip && m.base>=0 && m.disp_has_sym)
        die("prefetcht0: symbolic base displacement is unsupported; use rel");
    if (m.has_index && m.index==4) die("prefetcht0: stack pointer cannot be an index");
    if (m.disp < -2147483647L-1 || m.disp > 2147483647L)
        die("prefetcht0 displacement out of range");
    int x,b; mem_begin(&m,&x,&b);
    emit_rex(0,0,x,b,0); emit(0x0f); emit(0x18); encode_mem(1,&m,0);
}

static void enc_jmp_dispatch(void) {
    int has_colon=0; for(int k=1;k<g_ntok;k++) if(strchr(g_tok[k],':')){has_colon=1;break;}
    if (g_ntok>2 && (has_colon || is_size_kw(g_tok[1]))) {
        char j[256]; size_t jl=0; j[0]=0;
        for (int k=1;k<g_ntok;k++){ size_t tl=strlen(g_tok[k]);
            if (jl+tl<sizeof(j)-1){ memcpy(j+jl,g_tok[k],tl); jl+=tl; j[jl]=0; }
            if (k==1 && is_size_kw(g_tok[k]) && jl<sizeof(j)-1){ j[jl++]=' '; j[jl]=0; } }
        enc_jmp(j,-1);
    } else { int ti; int force=branch_force_arg(&ti); enc_jmp(g_tok[ti],force); }
}

static void enc_imul_dispatch(void) {
    if (g_ntok==3) {
        if(g_token_trailing_comma || g_tok_precomma[0] || g_tok_precomma[1] ||
           !g_tok_precomma[2])die("imul needs comma-separated operands");
        if (reg_find(g_tok[2])) enc_imul2(g_tok[1],g_tok[2]);
        else if (is_mem(g_tok[2])) enc_imul2(g_tok[1],g_tok[2]);
        else {
            const Reg*rd=reg_find(g_tok[1]); if(!rd || rd->size==1)die("imul immediate needs r16/r32/r64");
            ImmediateExpr imm; parse_immediate(g_tok[2],&imm);
            if(rd->size==2)emit_opsize(16); else if(rd->size==4)emit_opsize(32);
            emit_rex(rd->size==8,(rd->num>=8),0,(rd->num>=8),0);
            int short_field=immediate_is_absolute(&imm) && fits_imm8(imm.value);
            emit(short_field ? 0x6b : 0x69); emit_modrm(3,rd->num,rd->num);
            if(short_field)emit((uint8_t)imm.value); else emit_arithmetic_immediate(rd->size,&imm);
        }
    } else if (g_ntok==2 && !g_token_trailing_comma && !g_tok_precomma[0] && !g_tok_precomma[1])
        enc_unary_grp3(5,g_tok[1]);
    else die("imul supports one operand or an abbreviated two-operand form");
}

static void enc_out_dispatch(void) {
    if(g_ntok!=3 || g_token_trailing_comma || g_tok_precomma[0] ||
       g_tok_precomma[1] || !g_tok_precomma[2])die("out needs two comma-separated operands");
    const Reg*rp=reg_find(g_tok[1]); const Reg*rs=reg_find(g_tok[2]);
    if(!rp) {
        ImmediateExpr port; parse_immediate(g_tok[1],&port);
        if((immediate_value_known(&port) && !fits_u8(port.value)) || !rs || rs->num!=0)
            die("out imm8: use 'out imm8, al|ax|eax'");
        if(rs->size==1)emit(0xe6);
        else if(rs->size==2){ emit_opsize(16); emit(0xe7); }
        else if(rs->size==4){ emit_opsize(32); emit(0xe7); }
        else die("out imm8: bad src size");
        emit_arithmetic_immediate(1,&port); return;
    }
    if(rp->size!=2 || rp->num!=2 || !rs || rs->num!=0)die("out: use 'out dx, al|ax|eax'");
    if(rs->size==1) emit(0xee);
    else if(rs->size==2){ emit_opsize(16); emit(0xef); }
    else if(rs->size==4){ emit_opsize(32); emit(0xef); }
    else die("out: bad src size");
}

static void enc_pop_dispatch(void) {
    if(g_target_profile && g_bits==64 && is_size_kw(g_tok[1]) && strcmp(g_tok[1],"qword"))
        die("target profile: explicit pop form requires qword");
    if (!reg_find(g_tok[1]) &&
        (is_mem(g_tok[1]) || (is_size_kw(g_tok[1]) && g_ntok>2 && is_mem(g_tok[2])))) {
        const char *mt = is_mem(g_tok[1]) ? g_tok[1] : g_tok[2];
        Mem m; parse_mem(mt, &m); int rx,rb; mem_begin(&m,&rx,&rb);
        emit_rex(0,0,rx,rb,0);
        emit(0x8f); encode_mem(0, &m, 0);
    } else enc_pop(g_tok[1]);
}

static void enc_in_dispatch(void) {
    const Reg*rd=reg_find(g_tok[1]); const Reg*rp=reg_find(g_tok[2]);
    if(!rd||!rp||rp->num!=2) die("in: use 'in al|ax|eax, dx'");
    if(rd->size==1) emit(0xec);
    else if(rd->size==2){ emit_opsize(16); emit(0xed); }
    else if(rd->size==4){ emit_opsize(32); emit(0xed); }
    else die("in: bad dest size");
}

static void emit_0f01(uint8_t ext) {
    emit(0x0f); emit(0x01); emit(ext);
}

static void enc_btr_dispatch(void) {
    if(g_ntok!=3 || g_token_trailing_comma || g_tok_precomma[0] ||
       g_tok_precomma[1] || !g_tok_precomma[2])die("btr needs two comma-separated operands");
    const Reg*r=reg_find(g_tok[1]); if(!r||(r->size!=4&&r->size!=8))die("btr needs r32/r64, imm8");
    ImmediateExpr imm; parse_immediate(g_tok[2],&imm);
    if(immediate_value_known(&imm) && !fits_u8(imm.value))die("btr imm out of range");
    if(r->size==4)emit_opsize(32);
    emit_rex(r->size==8,0,0,(r->num>=8),0); emit(0x0f); emit(0xba); emit_modrm(3,6,r->num);
    emit_arithmetic_immediate(1,&imm);
}

static void enc_invpcid_dispatch(void) {
    if(g_ntok!=3 || source_commas()!=1)die("invpcid needs two comma-separated operands");
    const Reg*r=reg_find(g_tok[1]); if(!r||r->size!=8 || g_bits!=64)die("invpcid needs r64, m128 in BITS 64");
    Mem m; parse_mem(g_tok[2],&m); int rx,rb; mem_begin(&m,&rx,&rb);
    /* N05: the r64 operand is implicit in long mode; W is not an operand-size
     * selector for this opcode. Preserve R/X/B for extended registers. */
    emit(0x66); emit_rex(0,(r->num>=8),rx,rb,0); emit(0x0f); emit(0x38); emit(0x82); encode_mem(r->num,&m,0);
}

static void enc_mxcsr_dispatch(InsnKind kind) {
    Mem m; parse_mem(g_tok[1],&m); int x,b; mem_begin(&m,&x,&b);
    emit_rex(0,0,x,b,0); emit(0x0f); emit(0xae); encode_mem(kind==INSN_ldmxcsr?2:3,&m,0);
}

static void enc_movx_dispatch(int sx) {
    if(is_size_kw(g_tok[2]))enc_movx(sx,!strcmp(g_tok[2],"byte")?1:(!strcmp(g_tok[2],"word")?2:(!strcmp(g_tok[2],"dword")?4:0)),g_tok[1],g_tok[3]);
    else { const Reg*rs=reg_find(g_tok[2]); enc_movx(sx, !rs?2:(rs->size==1?1:(rs->size==2?2:(rs->size==4?4:0))), g_tok[1],g_tok[2]); }
}

static void enc_int_dispatch(void) {
    if (g_ntok!=2 || g_token_trailing_comma || g_tok_precomma[0] || g_tok_precomma[1])die("int needs imm8 vector");
    ImmediateExpr imm; parse_immediate(g_tok[1],&imm);
    if (immediate_value_known(&imm) && !fits_u8(imm.value))die("int vector out of range");
    emit(0xcd); emit_arithmetic_immediate(1,&imm);
}

static void enc_fnstsw_dispatch(void) {
    const Reg*r=reg_find(g_tok[1]); if(!r||r->size!=2||r->num!=0)die("fnstsw supports ax"); emit(0xdf); emit(0xe0);
}

static void enc_ltr_dispatch(void) {
    const Reg*r=reg_find(g_tok[1]); if(!r)die("ltr needs r/m16");
    if(r->num>=8)emit_rex(0,0,0,1,0); emit(0x0f); emit(0x00); emit_modrm(3,3,r->num);
}

static void enc_lldt_dispatch(void) {
    const Reg*r=reg_find(g_tok[1]); if(!r||r->size!=2)die("lldt needs r/m16"); if(r->num>=8)emit_rex(0,0,0,1,0); emit(0x0f); emit(0x00); emit_modrm(3,2,r->num);
}

static void enc_rdrand_dispatch(InsnKind kind) {
    const Reg*r=reg_find(g_tok[1]);
    if(!r||(r->size!=2&&r->size!=4&&r->size!=8))die(kind==INSN_rdrand ? "rdrand needs r16/r32/r64" : "rdseed needs r16/r32/r64");
    if(r->size==2)emit_opsize(16); emit_rex(r->size==8,0,0,(r->num>=8),0); emit(0x0f); emit(0xc7); emit_modrm(3,kind==INSN_rdrand ? 6 : 7,r->num);
}

static void enc_fsbase_dispatch(InsnKind kind) {
    const Reg*r=reg_find(g_tok[1]);
    if(!r||(r->size!=4&&r->size!=8))die(kind==INSN_rdfsbase ? "rdfsbase needs r32/r64" : "wrfsbase needs r32/r64");
    emit(0xf3); emit_rex(r->size==8,0,0,(r->num>=8),0); emit(0x0f); emit(0xae); emit_modrm(3,kind==INSN_rdfsbase ? 0 : 2,r->num);
}

static void enc_vmov_dispatch(InsnKind kind) {
    enc_vmov(kind==INSN_vmovdqa?1:2,g_tok[1],g_tok[2]);
}

static void enc_xchg_dispatch(void) {
    const Reg*rd=reg_find(g_tok[1]); const Reg*rs=reg_find(g_tok[2]);
    if(!rd||!rs||rd->size!=rs->size||(rd->size!=4&&rd->size!=8))die("xchg supports r32/r64, r32/r64");
    emit_rex(rd->size==8,(rd->num>=8),0,(rs->num>=8),0); emit(0x87); emit_modrm(3,rd->num,rs->num);
}

/* N05: implicit string widths own 66/REX.W. Emit the operand-size prefix
 * before REP, then REX, so repeated forms have the canonical byte order.
 * The same encoder also handles the unprefixed compatibility modes. */
static int enc_string_dispatch(InsnKind kind,int repeat) {
    int opcode,width=8;
    switch(kind){
    case INSN_insb: opcode=0x6c; break;
    case INSN_insw: opcode=0x6d; width=16; break;
    case INSN_insd: opcode=0x6d; width=32; break;
    case INSN_outsb: opcode=0x6e; break;
    case INSN_outsw: opcode=0x6f; width=16; break;
    case INSN_outsd: opcode=0x6f; width=32; break;
    case INSN_movsb: opcode=0xa4; break;
    case INSN_movsd: opcode=0xa5; width=32; break;
    case INSN_movsq: opcode=0xa5; width=64; break;
    case INSN_stosb: opcode=0xaa; break;
    case INSN_stosw: opcode=0xab; width=16; break;
    case INSN_stosd: opcode=0xab; width=32; break;
    case INSN_stosq: opcode=0xab; width=64; break;
    case INSN_lodsb: opcode=0xac; break;
    case INSN_lodsd: opcode=0xad; width=32; break;
    case INSN_scasb: opcode=0xae; break;
    default: return 0;
    }
    if(g_ntok!=1 || source_commas())die("string instruction takes no explicit operands");
    if(width==64 && g_bits!=64)die("qword string instruction requires BITS 64");
    if(width==16 || width==32)emit_opsize(width);
    if(repeat)emit(repeat);
    if(width==64)emit_rex(1,0,0,0,0);
    emit(opcode);
    return 1;
}

static int repeat_prefix(InsnKind kind) {
    if(kind==INSN_rep || kind==INSN_repe || kind==INSN_repz)return 0xf3;
    if(kind==INSN_repne || kind==INSN_repnz)return 0xf2;
    return 0;
}
static void do_instruction_body(void);
static void do_instruction(void) {
    /* N26: `$` denotes the start of the entire instruction, including any
     * explicit prefix. Recursive prefix dispatch inherits this anchor. */
    int prior_location=g_expr_location_override;
    if(prior_location<0)g_expr_location_override=cur_off();
    do_instruction_body();
    g_expr_location_override=prior_location;
}
static void enc_prefix_dispatch(InsnKind kind) {
    g_intent_prefix=1;
    int prefix=kind==INSN_lock ? 0xf0 : repeat_prefix(kind), count=1;
    if(prefix!=0xf0){
        /* Identical repeated tokens collapse. Distinct spellings conflict,
         * even when their encoded byte agrees, as in NASM's prefix grammar. */
        while(count<g_ntok){
            InsnKind next=insn_kind(g_tok[count]);
            if(!repeat_prefix(next))break;
            if(next!=kind)die("conflicting repeat prefixes");
            count++;
        }
    }
    if(count>=g_ntok)die("prefix requires an instruction");
    for(int i=0;i<=count;i++)if(g_tok_precomma[i])die("comma before prefixed instruction");
    memmove(g_tok,g_tok+count,(size_t)(g_ntok-count)*sizeof(g_tok[0]));
    memmove(g_tok_precomma,g_tok_precomma+count,(size_t)(g_ntok-count)*sizeof(g_tok_precomma[0]));
    g_ntok-=count; g_tok[g_ntok]=NULL;
    g_prefetched_insn_kind=INSN_UNKNOWN;
    InsnKind child=insn_kind(g_tok[0]);
    if(prefix!=0xf0 && enc_string_dispatch(child,prefix))return;
    g_prefetched_insn_kind=child;
    emit(prefix); do_instruction();
}

static void do_instruction_body(void) {
    if(g_ntok<=0 || !g_tok[0])die("missing instruction");
    const char *op = g_tok[0];
    g_intent_instruction=1;
    /* N07: consume the prefetched classification exactly once, including
     * all early-return paths. Prefix removal explicitly reclassifies below. */
    InsnKind kind=g_prefetched_insn_kind;
    g_prefetched_insn_kind=INSN_UNKNOWN;
    if(kind==INSN_UNKNOWN)kind=insn_kind(op);
    /* Consume three-operand shuffles before generic immediate rejoining. */
    if (kind==INSN_sse || (kind==INSN_movsd && g_ntok>1)) {
        /* MOVSD without operands is the string instruction; explicit
         * operands select the scalar SSE descriptor and its strict parser. */
        g_prefetched_insn_kind=INSN_UNKNOWN; enc_sse(); return;
    }
    if(g_target_profile && g_ntok>3 && reg_find(g_tok[1]) && reg_find(g_tok[2]))
        die("intent: trailing register operands");
    /* o64/o32/a32 operand/address-size override prefixes. `o64 sysret`
     * forces REX.W → sysretq (48 0F 07). Emit the prefix, drop the
     * prefix token, and fall through to encode the real instruction.
     * For o64 specifically we special-case the known REX.W forms.
     * Author: F E R M I ∞ H A R T. */
    /* INV-434: keep prefix dispatch independent of compiler folding of
     * sizeof(string-literal) inside a function-like macro. */
    if (op[0]=='o' && op[1]=='6' && op[2]=='4' && op[3]==0) {
        g_prefetched_insn_kind=INSN_UNKNOWN; /* INV-595: early returns consume the prefetch too. */
        g_intent_prefix=1;
        if(g_ntok<2)die("o64 needs an instruction");
        if(g_tok_precomma[0] || g_tok_precomma[1])die("comma before prefixed instruction");
        if(g_target_profile && g_ntok!=2 &&
           (!strcmp(g_tok[1],"sysret") || !strcmp(g_tok[1],"iret")))
            die("target profile: unexpected return operands");
        if (g_ntok>=2 && !strcmp(g_tok[1],"sysret")) { emit(0x48); emit(0x0f); emit(0x07); return; }
        if (g_ntok>=2 && !strcmp(g_tok[1],"iret"))   { emit(0x48); emit(0xcf); return; }
        /* Typed encoders derive operand width from their operands. Prefixing
         * them here would duplicate REX.W (or add one to push/pop). */
        memmove(g_tok,g_tok+1,(size_t)(g_ntok-1)*sizeof(g_tok[0]));
        memmove(g_tok_precomma,g_tok_precomma+1,(size_t)(g_ntok-1)*sizeof(g_tok_precomma[0]));
        g_ntok--; g_tok[g_ntok]=NULL; op = g_tok[0];
        kind=insn_kind(op); /* Prefix removal changes the opcode token. */
    }
    /* Rejoin a multi-token second operand that is an arithmetic expression
     * (e.g. "'a' - 10"): only when the 3rd token onward are operator/number
     * pieces, NOT a "byte [mem]" memory form. */
    if (g_ntok>3 && g_tok[1][0]!='[' && !is_size_kw(g_tok[2])) {
        int arith=0,extra_comma=0;
        for (int i=3;i<g_ntok;i++){ char c=g_tok[i][0];
            if(g_tok_precomma[i])extra_comma=1;
            if (char_in(c, "+-*/|&^<>")||isdigit((unsigned char)c)||c=='\'') arith=1; }
        if (arith && !extra_comma && !is_size_kw(g_tok[1])) {
            char ex[256]; join_from(2,ex,sizeof(ex));
            size_t exlen=strlen(ex);
            /* g_tok[2] is char[NAME_MAX]; a joined operand longer than that would
             * be silently truncated by strncpy -> a silent miscompile. Fail loud
             * instead. (No current stage0 *.basm input triggers this.) */
            if (exlen >= (size_t)NAME_MAX) die("operand expression too long for token buffer");
            memcpy(g_tok[2],ex,exlen+1); g_ntok=3;
        }
    }
    /* Rejoin a multi-token immediate in "mov <size> [mem], expr" form */
    if (g_ntok>4 && is_size_kw(g_tok[1]) && g_tok[2][0]=='[') {
        int arith=0,extra_comma=0;
        for (int i=4;i<g_ntok;i++){ char c=g_tok[i][0];
            if(g_tok_precomma[i])extra_comma=1;
            if (char_in(c, "+-*/|&^<>")||isdigit((unsigned char)c)||c=='\'') arith=1; }
        if (arith && !extra_comma) {
            char ex[256]; join_from(3,ex,sizeof(ex));
            size_t exlen=strlen(ex);
            if (exlen >= (size_t)NAME_MAX) die("operand expression too long for token buffer");
            memcpy(g_tok[3],ex,exlen+1); g_ntok=4;
        }
    }
    if(kind!=INSN_UNKNOWN){
        const IntentForm *form=g_fixed_forms[kind];
        if(form){fixed_emit(form,op);return;}
    }
    if(g_target_profile && (kind==INSN_popa || kind==INSN_popad ||
       kind==INSN_pusha || kind==INSN_pushad))
        die2("instruction excluded by target profile",op); /* INV-589 */
    switch (kind) {
    case INSN_endbr64:
        /* INV-740: literal CET landing instruction, intentionally unmodeled. */
        if (g_bits!=64 || g_ntok!=1 || g_intent_prefix || source_commas())
            die("endbr64 requires no operands or prefixes in BITS 64");
        emit32(0xfa1e0ff3U);
        break;
    case INSN_adc:
    case INSN_rol:
    case INSN_ror:
    {
        /* INV-730: only the csum-copy RR32/64 and two literal rotate forms.
         * Validate raw separators too: tokenize deliberately discards commas. */
        enc_adc_rotate(kind,op);
    }
    break;
    case INSN_sbb:
    {
        /* INV-703: add only the qualified RR family, not unchecked ALU forms. */
        enc_sbb_dispatch();
    }
    break;
    case INSN_movnti:
    {
        /* INV-703: 0F C3 /r is memory-destination r32/r64 only. */
        enc_movnti_dispatch();
    }
    break;
    case INSN_prefetcht0:
        /* INV-632: qualify memory forms before emitting the prefetch opcode. */
    {
        enc_prefetcht0_dispatch();
    }
    break;
    case INSN_add:
    {
        enc_alu_dispatch(0);
    }
    break;
    case INSN_and:
    {
        enc_alu_dispatch(4);
    }
    break;
    case INSN_btr:
    {
        enc_btr_dispatch();
    }
    break;
    case INSN_cmp:
    {
        enc_alu_dispatch(7);
    }
    break;
    case INSN_call:
    {
        enc_call(g_tok[1]);
    }
    break;
    case INSN_dec:
    {
        enc_incdec(1,g_ntok);
    }
    break;
    case INSN_div:
    {
        enc_unary_grp3(6,g_tok[1]);
    }
    break;
    case INSN_fldcw:
    {
        enc_mem_group(g_tok[1],0xd9,5,0); /* INV-538 */
    }
    break;
    case INSN_fwait:
    {
        emit(0x9b);
    }
    break;
    case INSN_fnstsw:
    {
        enc_fnstsw_dispatch();
    }
    break;
    case INSN_fnstcw:
    {
        enc_mem_group(g_tok[1],0xd9,7,0);
    }
    break;
    case INSN_frstor:
    {
        enc_mem_group(g_tok[1],0xdd,4,0);
    }
    break;
    case INSN_fnsave:
    {
        enc_mem_group(g_tok[1],0xdd,6,0);
    }
    break;
    case INSN_fxsave:
    {
        enc_mem_group(g_tok[1],0x0fae,0,0);
    }
    break;
    case INSN_fxrstor:
    {
        enc_mem_group(g_tok[1],0x0fae,1,0);
    }
    break;
    case INSN_fxsave64:
    {
        enc_mem_group(g_tok[1],0x0fae,0,1);
    }
    break;
    case INSN_fxrstor64:
    {
        enc_mem_group(g_tok[1],0x0fae,1,1);
    }
    break;
    case INSN_int3:
    {
        emit(0xcc);
    }
    break;
    case INSN_inc:
    {
        enc_incdec(0,g_ntok);
    }
    break;
    case INSN_idiv:
    {
        enc_unary_grp3(7,g_tok[1]);
    }
    break;
    case INSN_imul:
    {
        enc_imul_dispatch();
    }
    break;
    case INSN_int:
    {
        enc_int_dispatch();
    }
    break;
    case INSN_iret:
    case INSN_iretd:
    {
        emit(0xcf);
    }
    break;
    case INSN_iretq:
    {
        emit(0x48); emit(0xcf);
    }
    break;
    case INSN_in:
    {
        enc_in_dispatch();
    }
    break;
    case INSN_invlpg:
    {
        enc_mem_group(g_tok[1],0x0f01,7,0);
    }
    break;
    case INSN_invpcid:
    {
        /* INV-538: INVPCID is 66 REX.W 0F 38 82 /r; NASM emits W=1 for the r64 operand. */
        enc_invpcid_dispatch();
    }
    break;
    case INSN_jz: case INSN_js: case INSN_jnz: case INSN_jns:
    case INSN_jne: case INSN_jnc: case INSN_jle: case INSN_jl:
    case INSN_jge: case INSN_jg: case INSN_je: case INSN_jc:
    case INSN_jbe: case INSN_jb: case INSN_jae: case INSN_ja:
        enc_jcc_dispatch(g_jcc_codes[kind-INSN_ja]); /* INV-740: same CC/force/relocation path. */
        break;
    case INSN_jmp:
    {
        /* Far jump operands like `dword 0x08:(long_mode_entry - VMA + LMA)`
        * get split across tokens (size keyword + selector:offset with spaces
        * inside the parens). Rejoin if any token carries a ':' or the first
        * is a size keyword. A space after a leading size keyword is kept so
        * enc_jmp can strip it. Author: F E R M I ∞ H A R T. */
        enc_jmp_dispatch();
    }
    break;
    case INSN_loop:
    {
        enc_loop(g_tok[1]);
    }
    break;
    case INSN_lea:
    {
        enc_lea(g_tok[1],g_tok[2]);
    }
    break;
    case INSN_lgdt:
    {
        enc_mem_group(g_tok[1],0x0f01,2,0);
    }
    break;
    case INSN_lidt:
    {
        enc_mem_group(g_tok[1],0x0f01,3,0);
    }
    break;
    case INSN_ltr:
    {
        enc_ltr_dispatch();
    }
    break;
    case INSN_insb:
    case INSN_insw:
    case INSN_insd:
    case INSN_outsb:
    case INSN_outsw:
    case INSN_outsd:
    case INSN_movsb:
    case INSN_movsd:
    case INSN_movsq:
    case INSN_stosb:
    case INSN_stosw:
    case INSN_stosd:
    case INSN_stosq:
    case INSN_lodsb:
    case INSN_lodsd:
    case INSN_scasb:
        (void)enc_string_dispatch(kind,0);
        break;
    case INSN_lock:
    case INSN_rep:
    case INSN_repe:
    case INSN_repz:
    case INSN_repnz:
    case INSN_repne:
    {
        enc_prefix_dispatch(kind);
    }
    break;
    case INSN_lldt:
    {
        enc_lldt_dispatch();
    }
    break;
    case INSN_mul:
    {
        enc_unary_grp3(4,g_tok[1]);
    }
    break;
    case INSN_movsxd:
    {
        enc_movsxd(g_tok[1],g_tok[2]);
    }
    break;
    case INSN_sse:
    {
        enc_sse();
    }
    break;
    case INSN_mov:
    {
        /* mov Sreg, r/m16 (8E /r) and mov r/m16, Sreg (8C /r). Segment regs
         * (es=0,cs=1,ss=2,ds=3,fs=4,gs=5) are needed for GDT segment reloads.
         * NASM emits no operand-size prefix for these. Ref: Intel SDM Vol 2. */
        /* INV-740: CR0/2/3/4 only. Long mode requires r64; legacy modes
         * require a low r32. No LOCK aliases, ignored extras or size coercion. */
        enc_mov_dispatch();
    }
    break;
    case INSN_movzx:
    {
        /* INV-580: 3-way source width; dword source is rejected in enc_movx. */
        enc_movx_dispatch(0);
    }
    break;
    case INSN_movsx:
    {
        /* INV-580: 3-way source width; r64->r64 and dword->movzx rejected. */
        enc_movx_dispatch(1);
    }
    break;
    case INSN_monitor:
    {
        emit_0f01(0xc8);
    }
    break;
    case INSN_mwait:
    {
        emit_0f01(0xc9);
    }
    break;
    case INSN_ldmxcsr:
    case INSN_stmxcsr:
    {
        enc_mxcsr_dispatch(kind); /* INV-538 */
    }
    break;
    case INSN_neg:
    {
        enc_unary_grp3(3,g_tok[1]);
    }
    break;
    case INSN_or:
    {
        enc_alu_dispatch(1);
    }
    break;
    case INSN_out:
    {
        enc_out_dispatch();
    }
    break;
#ifndef BASM_PUBLIC_ONLY
    case INSN_popad:
    {
        emit(0x61);
    }
    break;
    case INSN_popa:
    {
        emit(0x61);
    }
    break;
#endif
    case INSN_push:
    {
        /* push r64 | push imm (optionally with a size keyword, e.g.
        * `push qword 0x08`). NASM: imm8 sign-extended -> 6A ib, else
        * imm32 sign-extended -> 68 id. Default operand size is 64 in
        * long mode, so no operand-size prefix is emitted. */
        enc_push_dispatch();
    }
    break;
    case INSN_pop:
    {
        /* pop m64: 8F /0. Mirrors push m64 (FF /6). ucontext's `pop PC(%rdx)`
        * pops the return address straight into the saved context. F E R M I HART. */
        enc_pop_dispatch();
    }
    break;
    case INSN_pushf:
    {
        /* BUG-05: In 32/64-bit mode, pushf is 1 byte (0x9c).
         * In 16-bit mode, pushfd needs prefix (0x66 0x9c). */
        if (g_bits == 16) emit(0x66);
        emit(0x9c);
    }
    break;
    case INSN_pushfq:
    {
        emit(0x9c);
    }
    break;
    case INSN_popf:
    {
        /* BUG-05: In 32/64-bit mode, popf is 1 byte (0x9d).
         * In 16-bit mode, popfd needs prefix (0x66 0x9d). */
        if (g_bits == 16) emit(0x66);
        emit(0x9d);
    }
    break;
    case INSN_popfq:
    {
        emit(0x9d);
    }
    break;
#ifndef BASM_PUBLIC_ONLY
    case INSN_pushad:
    {
        emit(0x60);
    }
    break;
#endif
    case INSN_retfq:
    {
        emit(0x48); emit(0xcb);
    }
    break;
    case INSN_rdrand:
    case INSN_rdseed:
    {
        enc_rdrand_dispatch(kind); /* INV-538 */
    }
    break;
    case INSN_rdpkru:
    {
        /* INV-580: 0F 01 EE. E7 is SMSW r/m16 — a silent wrong-result
         * miscompile of PKRU reads (no fault, wrong value). */
        emit_0f01(0xee);
    }
    break;
    case INSN_rdfsbase:
    case INSN_wrfsbase:
    {
        enc_fsbase_dispatch(kind);
    }
    break;
    case INSN_retf:
    {
        emit(0xcb);
    }
    break;
    case INSN_sub:
    {
        enc_alu_dispatch(5);
    }
    break;
    case INSN_shr:
    {
        enc_shift(5,g_tok[1],g_tok[2]);
    }
    break;
    case INSN_shl:
    {
        enc_shift(4,g_tok[1],g_tok[2]);
    }
    break;
    case INSN_sar:
    {
        enc_shift(7,g_tok[1],g_tok[2]);
    }
    break;
    case INSN_sete: case INSN_setne: case INSN_setl: case INSN_setg:
    case INSN_setle: case INSN_setge: case INSN_setb: case INSN_setae:
    case INSN_setbe: case INSN_seta: case INSN_seto: case INSN_setno:
    case INSN_sets: case INSN_setns: case INSN_setp: case INSN_setnp:
    {
        /* SETcc r8 — all share the same encoding via enc_setcc */
        enc_setcc(kind, g_tok[1]);
    }
    break;
    case INSN_sysret:
    {
        emit(0x0f); emit(0x07);
    }
    break;
    case INSN_sgdt:
    {
        enc_mem_group(g_tok[1],0x0f01,0,0);
    }
    break;
    case INSN_sidt:
    {
        enc_mem_group(g_tok[1],0x0f01,1,0);
    }
    break;
    case INSN_test:
    {
        /* test reg,imm — F6 /0 ib (8-bit) or F7 /0 id; accumulator
         * short form A8 ib / A9 id (matches NASM byte-for-byte).
         * test has NO imm8-sign-extended (0x83) form. ∞HART */
        enc_test_dispatch();
    }
    break;
    case INSN_wrpkru:
    {
        emit_0f01(0xef);
    }
    break;
    case INSN_wbinvd:
    {
        emit(0x0f); emit(0x09);
    }
    break;
    case INSN_xor:
    {
        enc_alu_dispatch(6);
    }
    break;
    case INSN_vmovdqa:
    case INSN_vmovdqu:
    {
        enc_vmov_dispatch(kind);
    }
    break;
    case INSN_vaddps:
    {
        enc_vex_ps_nds(0x58,g_tok[1],g_tok[2],g_tok[3]);
    }
    break;
    case INSN_vmulps:
    {
        enc_vex_ps_nds(0x59,g_tok[1],g_tok[2],g_tok[3]);
    }
    break;
    case INSN_vxorps:
    {
        enc_vex_ps_nds(0x57,g_tok[1],g_tok[2],g_tok[3]);
    }
    break;
    case INSN_vbroadcastss:
    {
        enc_vbroadcastss(g_tok[1],g_tok[2]);
    }
    break;
    case INSN_vpcmpeqd:
    {
        enc_vex_nds(0x76,g_tok[1],g_tok[2],g_tok[3]);
    }
    break;
    case INSN_vpxor:
    {
        enc_vex_nds(0xef,g_tok[1],g_tok[2],g_tok[3]);
    }
    break;
    case INSN_vpor:
    {
        enc_vex_nds(0xeb,g_tok[1],g_tok[2],g_tok[3]);
    }
    break;
    case INSN_vptest:
    {
        enc_vptest(g_tok[1],g_tok[2]);
    }
    break;
    case INSN_xchg:
    {
        /* NASM canonical direction for the ambiguous 87 /r encoding:
         * first operand in the reg field, second in r/m (parity gate). */
        enc_xchg_dispatch();
    }
    break;
    case INSN_xsave:
    {
        enc_mem_group(g_tok[1],0x0fae,4,0);
    }
    break;
    case INSN_xrstor:
    {
        enc_mem_group(g_tok[1],0x0fae,5,0);
    }
    break;
    default: die2("unknown instruction", op);
    }
#undef OP_IS
}
