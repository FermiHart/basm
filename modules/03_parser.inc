/*
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ------------------------------------------------------------------ */
/* Data directives                                                    */
/* ------------------------------------------------------------------ */
typedef struct {
    int valid;
    int textlen, datalen, rodatalen;
    long bsslen;
    int nsyms, nconsts, ncustom, nsecorder;
    int custom_len[CUSTOM_MAX];
    int secorder[SEC_MAX];
    /* INV-777: heap snapshot of per-symbol layout, grown with g_sym_cap. */
    struct symsnap { int section, offset, defined, global; } *syms;
    int syms_cap;
    long const_values[CONST_MAX];
} LayoutSnapshot;
static LayoutSnapshot g_layout_snapshot;
static int g_deferred_content;
/* g_wrt_line/g_pc32_line/g_extern_sym are declared in 01_foundation.inc next
 * to the symbol pool; inv-777 grows them in lockstep with it. */

static int data_string_token(const char *text) {
    if (!char_in(*text,"\"'`")) return 0;
    char quote=*text++;
    while (*text) {
        if (quote=='`' && *text=='\\') {
            if (!text[1]) die("unterminated string escape");
            text+=2; continue;
        }
        if (*text==quote) return text[1]==0;
        text++;
    }
    die("unterminated quoted value");
    return 0;
}

/* emit a data item list for db/dw/dd/dq. */
static void data_define(int unit, int ntok) {
    if (ntok<2) die("data directive requires a value");
    if (g_tok_precomma[1] || g_token_trailing_comma) die("empty data operand");
    int list_offset=g_expr_location_override>=0 ? g_expr_location_override : cur_off();
    for (int i=1;i<ntok;i++) if (!strcmp(g_tok[i],"wrt")) {
        if (unit!=8 || ntok!=4 || i!=2 || strcmp(g_tok[3],"..sym"))
            die("dq wrt requires exactly NAME wrt ..sym");
        if (strcmp(g_fmt,"elf64")) die("dq wrt ..sym requires ELF64 output");
        const char *name=g_tok[1];
        if (strlen(name)>=NAME_MAX) die("dq wrt ..sym symbol name too long");
        if (!(isalpha((unsigned char)*name) || char_in(*name, "_.?@")))
            die("dq wrt ..sym requires a bare symbol");
        for (const char *p=name;*p;p++)
            if (!(isalnum((unsigned char)*p) || char_in(*p, "_.?@$#~")))
                die("dq wrt ..sym requires a bare symbol");
        for (const char *p=g_data_source;*p && !char_in(*p, "\n;\r");p++)
            if (*p==',') die("dq wrt ..sym does not accept commas or extra operands");
        char q[NAME_MAX]; qualify(name,q);
        Sym *s=sym_intern(q);
        g_wrt_line[(int)(s-g_syms)]=g_line;
        g_deferred_content=1; /* Validate forward globals/externs after the final pass. */
        add_reloc_abs64(cur_off(),g_cur,q);
        emit64(0);
        return;
    }
    for (int i=1;i<ntok;i++) {
        if (i>1 && !g_tok_precomma[i]) die("missing comma between data operands");
        char *t=g_tok[i];
        if (data_string_token(t) && !(i+1<ntok && !g_tok_precomma[i+1] &&
                                      char_in(g_tok[i+1][0],"+-*/<>|&^"))) {
            /* INV-BASM-STANDALONE-002: NASM packs a string's bytes, then pads
             * that operand to the data width. Widening every character changes
             * subsequent labels; emitting escapes as a lone byte misaligns dq. */
            char q=t[0]; const char *p=t+1;
            int bytes=0;
            while (*p && *p!=q) {
                uint8_t byte;
                if (q=='`' && *p=='\\') { p++; byte=basm_escape_byte(&p); }
                else byte=(uint8_t)*p++;
                emit(byte); bytes++;
            }
            while (bytes%unit) { emit(0); bytes++; }
        } else {
            /* An arithmetic expression may have been split across tokens by
             * the tokenizer (it drops spaces AND commas), e.g.
             * `dd -(MBOOT2_MAGIC + 0 + 24)`. Rejoin following tokens while
             * parentheses are unbalanced or the expression ends on a binary
             * operator. Author: F E R M I ∞ H A R T. */
            char ex[256]; size_t el=0; ex[0]=0;
            int first=i;
            int depth=0;
            int j=i;
            for (;;) {
                const char *tk=g_tok[j];
                size_t tl=strlen(tk);
                if (el+tl+2>sizeof(ex)) die("data expression too long");
                if (j>first) ex[el++]=' ';
                memcpy(ex+el,tk,tl); el+=tl; ex[el]=0;
                for (const char *c=tk;*c;c++){ if(*c=='(')depth++; else if(*c==')')depth--; }
                char last = el? ex[el-1] : 0;
                int trailing_op = char_in(last, "+-*/<>|&^");
                int next_is_op = (j+1<ntok) && !g_tok_precomma[j+1] && char_in(g_tok[j+1][0], "+-*/<>|&^");
                if ((depth>0 || trailing_op) && j+1<ntok && g_tok_precomma[j+1])
                    die("incomplete expression before comma");
                if ((depth>0 || trailing_op || next_is_op) && j+1<ntok) { j++; continue; }
                break;
            }
            i=j;
            /* INV-632: a field-relative address is S-P, not an absolute S plus the
             * section-local value of -$. Keep this grammar deliberately narrow. */
            if (isalpha((unsigned char)ex[0]) || char_in(ex[0], "_.?@")) {
                const char *p=ex;
                while (isalnum((unsigned char)*p) || char_in(*p, "_.?@$#~")) p++;
                if (strchr(p,'$') && !strstr(p,"$$")) {
                    const char *name_end=p;
                    long adjustment=0;
                    while (char_in(*p," \t")) p++;
                    const char *after_sign=p;
                    if (char_in(*after_sign,"+-")) {
                        after_sign++;
                        while (char_in(*after_sign," \t")) after_sign++;
                    }
                    /* INV-703/W05: preserve whitespace boundaries while
                     * validating the same narrow field-relative grammar. */
                    if (char_in(*p,"+-") && *after_sign!='$') {
                        int negative=*p=='-'; p=after_sign;
                        if(!isdigit((unsigned char)*p))die("relative field offset requires an integer");
                        uint64_t magnitude=basm_parse_u64(&p);
                        if(magnitude>2147483647UL)die("relative field offset out of range");
                        adjustment=(long)magnitude;
                        if(negative)adjustment=-adjustment;
                    }
                    while (char_in(*p," \t")) p++;
                    int relative=*p=='-';
                    if(relative)p++;
                    while (char_in(*p," \t")) p++;
                    relative=relative && *p=='$';
                    if(*p=='$')p++;
                    while (char_in(*p," \t")) p++;
                    if (unit!=4 || !relative || *p || first!=1 || i!=ntok-1)
                        die("relative data field requires dd NAME[+/-integer] - $");
                    for (const char *c=g_data_source;*c && !char_in(*c, "\n;\r");c++)
                        if (*c==',') die("relative data field does not accept commas");
                    if (strcmp(g_fmt,"elf64")) die("relative data field requires ELF64 output");
                    char name[NAME_MAX], q[NAME_MAX]; size_t n=(size_t)(name_end-ex);
                    if (n>=sizeof(name)) die("relative data field symbol name too long");
                    memcpy(name,ex,n); name[n]=0; qualify(name,q);
                    long cv;
                    if (const_lookup(q,&cv)) die("relative data field requires a label or extern");
                    Sym *s=sym_intern(q);
                    g_pc32_line[(int)(s-g_syms)]=g_line; g_deferred_content=1;
                    long field_adjustment=basm_expr_add(adjustment,basm_expr_sub(cur_off(),list_offset));
                    if (s->defined && s->section==g_cur) {
                        long value=basm_expr_sub(basm_expr_add(s->offset,field_adjustment),cur_off());
                        if(value < -2147483647L-1 || value>2147483647L)die("relative field displacement out of range");
                        emit32((uint32_t)value);
                    }
                    else {
                        if (s->defined && s->section!=SEC_NONE) add_reloc_section(cur_off(),s->section,basm_expr_add(s->offset,field_adjustment));
                        else add_reloc_named(cur_off(),q,field_adjustment);
                        emit32(0);
                    }
                    continue;
                }
            }
            /* Evaluate with symbol capture: if the expression references one
             * cross-section label (e.g. `gdt_start - VMA + LMA` or
             * `isr0 + 8`), emit an absolute reloc (R_X86_64_32 for dd,
             * R_X86_64_64 for dq) against that section/symbol with the baked
             * value as addend, so the linker resolves the final address.
             * Author: F E R M I ∞ H A R T. */
            int has_sym=0, ssec=SEC_NONE, sglob=0; long soff=0; char sname[NAME_MAX];
            int prior_location=g_expr_location_override;
            g_expr_location_override=list_offset;
            long v = parse_expr_reloc(ex, &has_sym, &ssec, &soff, sname, &sglob);
            g_expr_location_override=prior_location;
            int type=unit==8 ? 1 : (unit==4 ? 10 : (unit==2 ? 12 : 14));
            emit_expr_field(unit,type,v,has_sym,ssec,sglob,sname);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Directive / label handling                                         */
/* ------------------------------------------------------------------ */
static int handle_global_line(const char *line) {
    const char *p=line;
    while (char_in(*p, " \t")) p++;
    int local=!strncmp(p,"static",6);
    if ((!local && strncmp(p,"global",6)) || (p[6] && !isspace((unsigned char)p[6]) && !char_in(p[6], ",;"))) return 0;
    p+=6;
    if (*p && !isspace((unsigned char)*p)) die("global requires a name");
    while (isspace((unsigned char)*p)) p++;
    char name[NAME_MAX], qualified[NAME_MAX]; size_t n=0;
    if (!(isalpha((unsigned char)*p) || char_in(*p, "_.?@$")))
        die("global requires a symbol name");
    while (isalnum((unsigned char)*p) || char_in(*p, "_.?@$#~")) {
        if (n>=sizeof(name)-1) die("global symbol name too long");
        name[n++]=*p++;
    }
    name[n]=0;
    int isf=0, isn=0, iso=0, hidden=0;
    if (*p==':') {
        p++;
        if (!strncmp(p,"function",8)) { p+=8; isf=1; }
        /* INV-703: NASM's explicit local NOTYPE size is not a function. */
        else if (!strncmp(p,"notype",6)) { p+=6; isn=1; }
        else if (!strncmp(p,"data",4)) { p+=4; iso=1; }
        else if (!local && !strncmp(p,"hidden",6)) { p+=6; hidden=1; }
        else die("global: unsupported symbol attribute");
    }
    if (*p && !isspace((unsigned char)*p) && *p!=';') die("global: malformed extra operand");
    while (isspace((unsigned char)*p)) p++;
    const char *end=p;
    while (*end && !char_in(*end, ";\r\n")) end++;
    while (end>p && isspace((unsigned char)end[-1])) end--;
    size_t len=(size_t)(end-p);
    if (local && ((!isf && !isn && !iso) || !len)) die("static requires :function, :notype or :data and an explicit size");
    if ((iso || isn) && !len) die("global :data/:notype requires an explicit size");
    if (len && !isf && !isn && !iso) die("global: size requires :function or :data");
    qualify(name,qualified);
    Sym *s=sym_intern(qualified);
    if (len>=256) die("function size expression too long");
    if (s->size_expr && !len) die2("conflicting function size",name);
    int binding=local ? 2 : 1;
    if ((s->binding_decl && s->binding_decl!=binding) || (local && (s->weak || g_extern_sym[(int)(s-g_syms)])))
        die2("conflicting static/global symbol binding",name);
    if (s->binding_decl && (s->is_func!=isf || s->is_object!=iso || s->hidden!=hidden))
        die2(local ? "conflicting static symbol type" : "conflicting symbol type or visibility",name); /* INV-741 */
    if (hidden && s->weak) die("hidden global cannot be weak");
    s->binding_decl=binding;
    s->global=!local; s->is_func=isf; s->is_object=iso; s->hidden=hidden;
    if (hidden) g_deferred_content=1;
    if (len) {
        if (s->size_expr && (strlen(s->size_expr)!=len || memcmp(s->size_expr,p,len) || strcmp(s->size_scope,g_last_global)))
            die2("conflicting function size",name);
        if (!s->size_expr) {
            s->size_expr=malloc(len+strlen(g_last_global)+2);
            if (!s->size_expr) die("oom function size expression");
            s->size_scope=s->size_expr+len+1;
        }
        memcpy(s->size_expr,p,len); s->size_expr[len]=0;
        memcpy(s->size_scope,g_last_global,strlen(g_last_global)+1);
        s->size_line=g_line;
        /* INV-545: even branch-free sources need final-pass size validation. */
        g_deferred_content=1;
    }
    return 1;
}

static void validate_symbol_sizes(void) {
    for (int i=0;i<g_nsyms;i++) {
        Sym *s=&g_syms[i];
        if (s->hidden && (!s->defined || s->defgen!=g_sym_gen || s->section==SEC_NONE))
            die2("hidden global requires a defined label",s->name);
        if (!s->size_expr) continue;
        g_line=s->size_line;
        if (!s->defined || s->defgen!=g_sym_gen || s->section==SEC_NONE)
            die2(s->is_func ? "function size requires a defined function" : "symbol size requires a defined label",s->name);
        int sec=s->section;
        if (s->is_func && sec!=SEC_TEXT && !(sec>=SEC_CUSTOM0 && sec<SEC_CUSTOM0+g_ncustom &&
            g_custom_type[custom_idx(sec)]==1 && (g_custom_flags[custom_idx(sec)]&4)))
            die2("function size requires a code section",s->name);
        /* INV-703: NOTYPE may describe data too; bound it by its own section,
         * without inferring FUNC/OBJECT from flags or a nonzero extent. */
        long limit=sec==SEC_TEXT ? g_textlen : sec==SEC_DATA ? g_datalen :
                   sec==SEC_RODATA ? g_rodatalen : sec==SEC_BSS ? g_bsslen :
                   sec>=SEC_CUSTOM0 ? g_custom_len[custom_idx(sec)] : 0;
        /* A separate bounded linear evaluator preserves section provenance and
         * rejects overflow/trailing operands instead of using relocation math. */
        long acc[17]={0}; int balance[17]={0}, factor[17]={0};
        int depth=0, sign=1, need_term=1;
        const char *p=s->size_expr;
        for (;;) {
            while (isspace((unsigned char)*p)) p++;
            long value=0; int coeff=0;
            if (need_term) {
                if (char_in(*p, "+-")) { if (*p=='-') sign=-sign; p++; continue; }
                if (*p=='(') {
                    if (depth==16) die("function size expression too deep");
                    depth++; factor[depth]=sign; acc[depth]=0; balance[depth]=0;
                    sign=1; p++; continue;
                }
                if (isdigit((unsigned char)*p)) {
                    int base=10, digits=0;
                    if (p[0]=='0' && char_in(p[1], "xX")) { base=16; p+=2; }
                    for (;;) {
                        int digit=-1;
                        if (*p>='0' && *p<='9') digit=*p-'0';
                        else if (base==16 && *p>='a' && *p<='f') digit=*p-'a'+10;
                        else if (base==16 && *p>='A' && *p<='F') digit=*p-'A'+10;
                        if (digit<0) break;
                        if (value>(BASM_LONG_MAX-digit)/base) die("function size integer out of range");
                        value=value*base+digit; digits++; p++;
                    }
                    if (!digits) die("function size requires an integer");
                } else {
                    char name[NAME_MAX], qualified[NAME_MAX]; size_t n=0;
                    if (!(isalpha((unsigned char)*p) || char_in(*p, "_.?@")))
                        die("function size: missing or malformed term");
                    while (isalnum((unsigned char)*p) || char_in(*p, "_.?@$#~")) {
                        if (n>=sizeof(name)-1) die("function size symbol name too long");
                        name[n++]=*p++;
                    }
                    name[n]=0;
                    size_t scope=name[0]=='.' ? strlen(s->size_scope) : 0;
                    if (scope+n>=sizeof(qualified)) die("function size symbol name too long");
                    memcpy(qualified,s->size_scope,scope); memcpy(qualified+scope,name,n+1);
                    Sym *term=sym_find(qualified);
                    if (!term || !term->defined || term->defgen!=g_sym_gen)
                        die2("function size: undefined or external symbol",qualified);
                    if (term->section!=sec) die2("function size: cross-section symbol",qualified);
                    value=term->offset; coeff=1;
                }
            } else {
                if (char_in(*p, "+-")) { sign=*p=='-' ? -1 : 1; p++; need_term=1; continue; }
                if (*p==')' && depth) {
                    value=acc[depth]; coeff=balance[depth]; sign=factor[depth]; depth--; p++;
                } else if (!*p && !depth) break;
                else die("function size: malformed extra operand or parentheses");
            }
            if (sign<0) { value=-value; coeff=-coeff; }
            if ((value>0 && acc[depth]>BASM_LONG_MAX-value) ||
                (value<0 && acc[depth]<-BASM_LONG_MAX-value))
                die("function size arithmetic out of range");
            acc[depth]+=value; balance[depth]+=coeff;
            need_term=0; sign=1;
        }
        if (balance[0]) die("function size must be an absolute expression");
        if (acc[0]<0 || s->offset<0 || s->offset>limit || acc[0]>limit-s->offset)
            die2("function size extent out of range",s->name);
        s->size=(uint64_t)acc[0];
    }
}

/* INV-572: exact data/reserve spellings share one classifier; never consume a
 * prefix of a label or read past its NUL. Negative units denote reservations. */
static int data_directive_unit(const char *op) {
    int sign=1;
    if (*op=='d') op++;
    else if (!strncmp(op,"res",3)) { op+=3; sign=-1; }
    else return 0;
    if (!*op) return 0;
    if (op[1]) return 0;
    switch (*op) {
    case 'b': return sign;
    case 'w': return sign*2;
    case 'd': return sign*4;
    case 'q': return sign*8;
    default: return 0;
    }
}

static int handle_data_directive(void) {
    int unit=data_directive_unit(g_tok[0]);
    if (!unit) return 0;
    if (unit>0) data_define(unit,g_ntok);
    else {
        if (g_ntok<2) die("reserve directive requires a count");
        if (source_commas()) die("reserve directive requires one count");
        unit=-unit;
        char ex[256]; basm_join_tokens(1,g_ntok,ex,sizeof(ex));
        long n=basm_parse_count(ex,BASM_LONG_MAX/unit,"res* count out of range");
        reserve_bytes(n*unit);
    }
    return 1;
}

static int handle_directive_or_label(char *line); /* fwd: times/label tails re-dispatch */
static const struct { const char *name; int bit,value; } g_section_attrs[] = {
    {"alloc",2,2}, {"noalloc",2,0}, {"exec",4,4}, {"noexec",4,0},
    {"write",1,1}, {"nowrite",1,0}, {"progbits",8,1}, {"nobits",8,8}, {"note",8,7}
};

/* Keep directive families out of the central dispatcher so Bear does not
 * spill all of their independent locals into one oversized frame. Each
 * helper preserves the original validation, diagnostics and effects. */
static int handle_section_directive(void) {
        if (g_ntok<2) die("section requires a name");
        size_t section_name_len=strlen(g_tok[1]);
        if (section_name_len>=NAME_MAX) die("section name too long");
        /* INV-741: NOTE is an explicit ELF type, never inferred from its name. */
        if (source_commas()) die("section attributes require whitespace, not commas");
        int flags=2,type=1,align=1,seen=0;
        for (int i=2;i<g_ntok;i++) {
            const char *a=g_tok[i]; int bit=0,value=0;
            for (int j=0;j<9;j++) if (!strcmp(a,g_section_attrs[j].name)) {
                bit=g_section_attrs[j].bit; value=g_section_attrs[j].value; break;
            }
            if (!bit && !strncmp(a,"align=",6)) {
                bit=16; align=(int)sse_literal(a+6,1073741824L);
                if (!align || (align&(align-1))) die("section alignment requires a positive power of two");
            }
            if (!bit) die("unknown section attribute");
            if (seen&bit) die("duplicate or conflicting section attribute");
            if (bit<8) { if (!(seen&7)) flags=0; flags|=value; }
            if (bit==8) type=value;
            seen|=bit;
        }
        if ((flags&5)==5 || (type==7 && (flags&5))) die("section permissions conflict with W^X/NOTE");
        int fixed=-1;
        for (int i=0;i<SEC_CUSTOM0;i++) if (!strcmp(g_tok[1],g_fixed_sec_names[i])) { fixed=i; break; }
        if (fixed>=0) {
            /* INV-BASM-STANDALONE-003: canonical sections have fixed ELF
             * permissions/types in the writer. A declaration may repeat those
             * properties, but must not request noexec and silently receive X.
             * Compare only explicitly supplied permission bits. */
            int fixed_flags=fixed==SEC_TEXT ? 6 :
                            (fixed==SEC_DATA || fixed==SEC_BSS) ? 3 :
                            fixed==SEC_RODATA ? 2 : 0;
            int fixed_type=fixed==SEC_BSS ? 8 : 1;
            if (((seen&7)&(flags^fixed_flags)) || ((seen&8) && type!=fixed_type))
                die("canonical section attributes conflict with fixed type or permissions");
            g_cur=fixed;
        }
        else {
            /* Custom named section (e.g. .multiboot, .ap_trampoline). Intern
             * it, parse NASM attributes (alloc/exec/write/nobits/progbits/
             * align=N), and select it as current. Author: F E R M I ∞ H A R T. */
            int found=-1;
            for (int i=0;i<g_ncustom;i++) if(!strcmp(g_custom_name[i],g_tok[1])){found=i;break;}
            if (found<0) {
                if (g_ncustom>=CUSTOM_MAX) die2("too many custom sections", g_tok[1]);
                found=g_ncustom++;
                /* Copy the admitted spelling including its terminator exactly.
                 * A bounded string-copy API may reserve one of its n bytes
                 * for NUL; that would collapse distinct 255-byte names. */
                memcpy(g_custom_name[found],g_tok[1],section_name_len+1);
                /* NASM treats every non-canonical name as custom: alloc-only
                 * PROGBITS unless attributes say otherwise, even for .text.*
                 * and .bss.* names. Linker scripts may classify by name. */
                g_custom_type[found]=type; g_custom_flags[found]=flags;
                g_custom_declalign[found]=align; g_secalign[SEC_CUSTOM0+found]=align;
            } else if (seen && (g_custom_type[found]!=(uint32_t)type || g_custom_flags[found]!=(uint64_t)flags ||
                       g_custom_declalign[found]!=align)) die("conflicting section redeclaration");
            g_cur=SEC_CUSTOM0+found;
        }
        if (g_cur<SEC_CUSTOM0 && type==7) die("NOTE requires a custom section");
        if (g_cur<SEC_CUSTOM0 && (seen&16)) {
            if (align>g_secrequired[g_cur]) g_secrequired[g_cur]=align;
            g_secalign[g_cur]=g_secrequired[g_cur];
        }
        secorder_touch(g_cur);
        return 1;
}

/* W04: unlike the tokenizer, this narrow CSV reader retains empty operands
 * and spaces inside count expressions. Quoted filenames may contain commas. */
static int incbin_arguments(char args[3][BASM_LINE_CAP]) {
    const char *p=g_data_source;
    while (char_in(*p," \t")) p++;
    while (*p && !char_in(*p," \t,;\r\n")) p++;
    int count=0;
    for (;;) {
        while (char_in(*p," \t")) p++;
        const char *start=p;
        char quote=0;
        int depth=0;
        while (*p && !char_in(*p,"\r\n")) {
            if (quote) {
                if (quote=='`' && *p=='\\' && p[1]) { p+=2; continue; }
                if (*p==quote) quote=0;
                p++; continue;
            }
            if (char_in(*p,"\"'`")) { quote=*p++; continue; }
            if (*p=='(') depth++;
            else if (*p==')') { if(!depth)die("incbin: unmatched parenthesis"); depth--; }
            if (!depth && char_in(*p,",;")) break;
            p++;
        }
        if (quote || depth) die("incbin: unterminated operand");
        const char *end=p;
        while (end>start && char_in(end[-1]," \t")) end--;
        size_t len=(size_t)(end-start);
        if (!len || count==3 || len>=BASM_LINE_CAP) die("incbin requires FILE[,SKIP[,COUNT]]");
        memcpy(args[count],start,len); args[count++][len]=0;
        if (*p!=',') break;
        p++;
    }
    return count;
}

static void filename_token(const char *token,char *out,size_t capacity) {
    size_t len=strlen(token);
    if (char_in(*token,"\"'`")) {
        if (len<2 || token[len-1]!=*token) die("unterminated file name");
        token++; len-=2;
    }
    if (!len || len>=capacity) die("file name too long or empty");
    memcpy(out,token,len); out[len]=0;
}

static int handle_incbin_directive(void) {
    char args[3][BASM_LINE_CAP],fn[BASM_LINE_CAP];
    int argc=incbin_arguments(args);
    filename_token(args[0],fn,sizeof(fn));
    long skip=argc>1 ? basm_parse_count(args[1],BASM_LONG_MAX,"incbin skip out of range") : 0;
    long want=argc>2 ? basm_parse_count(args[2],BASM_LONG_MAX,"incbin count out of range") : -1;
    const BasmDependency *dep=basm_snapshot_open(fn,BASM_DEP_INCBIN);
    if (dep->len>(size_t)BASM_LONG_MAX) die("incbin snapshot too large");
    long end=(long)dep->len;
    long have=end>skip ? end-skip : 0;
    long n=want>=0 && want<have ? want : have;
    if (g_sizing) {
        g_deferred_content=1;
        advance_content_len(n);
        return 1;
    }
    if (sec_is_nobits(g_cur)) die("incbin: cannot emit into nobits section");
    if (n) file_span_add(dep,g_cur,cur_off(),skip,n);
    advance_content_len(n);
    return 1;
}

static int handle_times_directive(char *line) {
        (void)line;
        if (g_ntok<4) die("times requires count, directive and value");
        int di=-1, unit=0, is_res=0;
        for(int i=2;i<g_ntok;i++){
            unit=data_directive_unit(g_tok[i]);
            if(unit){di=i;is_res=unit<0;if(is_res)unit=-unit;break;}
        }
        if(di<0)die("times needs a data or reserve directive");
        char cexpr[256]; cexpr[0]=0;
        basm_join_tokens(1,di,cexpr,sizeof(cexpr));
        int prior_fwd_unresolved = g_fwd_unresolved;
        g_fwd_unresolved = 0;
        long count = basm_parse_count(cexpr,BASM_LONG_MAX,"times count out of range");
        int count_fwd_unresolved = g_fwd_unresolved;
        g_fwd_unresolved |= prior_fwd_unresolved; /* INV-545 */
        if (count_fwd_unresolved) die("times: forward reference in count (NASM compatibility)");
        if(count<0)die("times count must be non-negative");
        /* INV-582: fail early past any emittable size (DATA_MAX is the
         * largest section ceiling) instead of grinding billions of
         * data_define calls toward a certain overflow. */
        if(!is_res && unit>0 && count> (long)(DATA_MAX/(unsigned)unit))die("times count too large");
        if(is_res){
            if(di+1>=g_ntok)die("times reserve needs a count");
            char rexpr[256]; basm_join_tokens(di+1,g_ntok,rexpr,sizeof(rexpr));
            long maximum=count>0 ? BASM_LONG_MAX/count/unit : BASM_LONG_MAX/unit;
            long n=basm_parse_count(rexpr,maximum,"times reserve size too large");
            reserve_bytes(count*n*unit);
        } else {
            if(di+1>=g_ntok)die("times data directive needs a value");
            int vals=g_ntok-di-1;
            for(int i=0;i<=vals;i++) {
                g_tok[i]=g_tok[di+i]; g_tok_precomma[i]=g_tok_precomma[di+i];
            }
            g_tok_precomma[1]=0;
            g_ntok=vals+1;
            int prior_location=g_expr_location_override;
            g_expr_location_override=cur_off();
            for(long k=0;k<count;k++)data_define(unit,g_ntok);
            g_expr_location_override=prior_location;
        }
        return 1;
}

static Sym *label_intern_at_cur(const char *name) {
        char qual[NAME_MAX];
        if (name[0]=='.' && g_last_global[0]) {
            size_t gl=strlen(g_last_global), nl=strlen(name);
            if(gl+nl>=NAME_MAX)die("label too long"); /* INV-542 */
            memcpy(qual,g_last_global,gl); memcpy(qual+gl,name,nl+1);
            memcpy(qual,g_last_global,gl); memcpy(qual+gl,name,nl+1);
        } else { basm_name_copy(qual,name);
                 if(name[0]!='.') basm_name_copy(g_last_global,name); }
        Sym *s=sym_intern(qual);
        if (s->defined && s->defgen==g_sym_gen &&
            (s->section!=g_cur || s->offset!=cur_off()))
            die2("label inconsistently redefined", name);
        s->defined=1; s->defgen=g_sym_gen; s->is_local=(name[0]=='.');
        s->section=g_cur; s->offset=cur_off();
        if (s->defseq<0) s->defseq=g_defseq++;
        return s;
}

static int label_rest_of_line(char *line) {
        for (int i=1;i<g_ntok;i++) {
            g_tok[i-1]=g_tok[i]; g_tok_precomma[i-1]=g_tok_precomma[i];
        }
        g_ntok--;
        const char *n0=g_tok[0];
        if(handle_data_directive())return 1;
        if(!strcmp(n0,"times")) return handle_directive_or_label(line);
        return 0;
}

/* INV-741: direct and deferred macro errors preserve the expanded message. */
static void source_error(const char *message) {
    char text[BASM_LINE_CAP]; int n=0;
    while (*message && !char_in(*message,"\r\n") && n<BASM_LINE_CAP-1) text[n++]=*message++;
    text[n]=0;
    die2("%error",text);
}

static int handle_directive_or_label(char *line) {
    (void)line; /* tokens are already produced by process_source's tokenize(buf) */
    if (g_ntok==0) return 1;
    const char *t0 = g_tok[0];
    if (!strcmp(t0,"%error")) {
        const char *p=g_data_source;
        while (char_in(*p," \t")) p++;
        source_error(p+6);
    }

    /* NASM directives are case-insensitive. The .S files use bare
     * `BITS 16/32/64` (uppercase, no brackets). This MUST update g_bits at
     * assembly time (not just in the preprocessor) so operand/address-size
     * prefixes and REX validity follow the current mode — ap_trampoline.S
     * switches BITS 16 → 32 → 64 mid-file. Author: F E R M I ∞ H A R T. */
#ifndef BASM_PUBLIC_ONLY
    if (!strcmp(t0,"bits") || !strcmp(t0,"BITS") || !strcmp(t0,"Bits")) {
        /* INV-589: valid modern directives were consumed before tokenization.
         * Comma-delimited aliases must not reach the compatibility assignment. */
        if(g_target_profile)die("target profile: malformed BITS directive");
        basm_token_arity(2,2);
        if (source_commas()) die("BITS requires one mode");
        {
            if (!strcmp(g_tok[1],"16")) g_bits=16;
            else if (!strcmp(g_tok[1],"32")) g_bits=32;
            else if (!strcmp(g_tok[1],"64")) g_bits=64;
            else die("BITS requires 16, 32 or 64");
        }
        return 1;
    }
#endif
    if (!strcmp(t0,"org") || !strcmp(t0,"ORG") || !strcmp(t0,"Org")) {
        if (g_ntok<2 || source_commas()) die("org requires one expression");
        char expression[256]; basm_join_tokens(1,g_ntok,expression,sizeof(expression));
        g_org = (uint64_t)parse_expr(expression);
        return 1;
    }
    if (!strcmp(t0,"default") || !strcmp(t0,"DEFAULT")) {
        basm_token_arity(2,2);
        if (source_commas()) die("default requires rel or abs");
        if (!strcmp(g_tok[1],"rel")) g_default_rel=1;
        else if (!strcmp(g_tok[1],"abs")) g_default_rel=0;
        else die2("unknown default mode",g_tok[1]);
        return 1;
    }
    if (!strcmp(t0,"global") || !strcmp(t0,"static")) {
        die("global: malformed directive"); /* Valid globals are parsed before commas are lost. */
    }
    if (!strcmp(t0,"extern")) {
        basm_token_arity(2,2);
        if (source_commas()) die("extern requires one symbol");
        basm_require_symbol(g_tok[1]);
        Sym *s=sym_intern(g_tok[1]);
        if (s->binding_decl==2) die("static symbol cannot be extern");
        s->global=1; s->defined=0;
        g_extern_sym[(int)(s-g_syms)]=1; return 1; }
    /* `weak <sym>` → exported with STB_WEAK binding. Like global, but a weak
     * symbol may stay undefined (resolves to 0) without erroring. Used by the
     * NetBSD csu crtbegin for its optional __cxa_finalize / frame-info hooks.
     * Author: F E R M I HART. */
    if (!strcmp(t0,"weak")) {
        basm_token_arity(2,2);
        if (source_commas()) die("weak requires one symbol");
        basm_require_symbol(g_tok[1]);
        char name[NAME_MAX]; basm_name_copy(name,g_tok[1]);
        char *c=strchr(name,':'); if(c) *c=0;
        Sym *s=sym_intern(name);
        if (s->binding_decl==2) die("static symbol cannot be weak");
        if (s->hidden) die("hidden global cannot be weak");
        s->global=1; s->weak=1; return 1;
    }

    /* Structure directives (struc/istruc/at/endstruc/iend) */
    if (!strcmp(t0,"struc")) { handle_struc_start(); return 1; }
    if (!strcmp(t0,"endstruc")) { handle_endstruc(); return 1; }
    if (!strcmp(t0,"istruc")) { handle_istruc(); return 1; }
    if (!strcmp(t0,"at")) { handle_at(); return 1; }
    if (!strcmp(t0,"iend")) { handle_iend(); return 1; }

    /* If we're inside a struc, treat this line as a field definition */
    if (g_in_struc) {
        handle_struc_field();
        return 1;
    }
    if (!strcmp(t0,"section") || !strcmp(t0,"segment")) {
        return handle_section_directive();
    }

    /* NASM-style preprocessor directives */
    if (!strcmp(t0,"%define")) {
        if (g_ntok<2) die("%define requires a name");
        basm_require_symbol(g_tok[1]);
        char val[512]; basm_join_tokens(2,g_ntok,val,sizeof(val));
        macro_add(g_tok[1], val); return 1;
    }
    if (!strcmp(t0,"%undef")) {
        basm_token_arity(2,2); basm_require_symbol(g_tok[1]);
        if (source_commas()) die("%undef requires one name");
        Macro *m=macro_find(g_tok[1]); if(m)m->active=0; return 1;
    }

    /* %if / %elif / %else / %endif - simple conditional assembly */
    if (!strcmp(t0,"%if")) {
        if (g_ntok<2) die("%if requires an expression");
        if (g_if_depth >= 64) die("%if nesting too deep");
        char condition[512]; basm_join_tokens(1,g_ntok,condition,sizeof(condition));
        long val = g_if_active && g_ntok>=2 ? parse_condition(condition) : 0;
        int new_active = (val != 0) && g_if_active;
        g_if_stack[g_if_depth] = g_if_active ? (val ? 1 : 2) : 3;
        g_if_depth++; g_if_active = new_active;
        return 1;
    }
    if (!strcmp(t0,"%elif")) {
        if (g_ntok<2) die("%elif requires an expression");
        if (g_if_depth==0) die("%%elif without %%if");
        if (g_if_stack[g_if_depth-1]==1) g_if_active=0;
        else if (g_if_stack[g_if_depth-1]==3) { }
        else { char condition[512]; basm_join_tokens(1,g_ntok,condition,sizeof(condition));
               long val = (g_ntok>=2) ? parse_condition(condition) : 0; g_if_stack[g_if_depth-1] = val?1:2; g_if_active = val?1:0; }
        return 1;
    }
    if (!strcmp(t0,"%else")) {
        basm_token_arity(1,1);
        if (source_commas()) die("%else takes no operands");
        if (g_if_depth==0) die("%%else without %%if");
        if (g_if_stack[g_if_depth-1]==1) g_if_active=0;
        else if (g_if_stack[g_if_depth-1]==2) g_if_active=1;
        return 1;
    }
    if (!strcmp(t0,"%endif")) {
        basm_token_arity(1,1);
        if (source_commas()) die("%endif takes no operands");
        if (g_if_depth==0) die("%%endif without %%if");
        g_if_depth--; g_if_active = (g_if_depth==0) ? 1 : (g_if_stack[g_if_depth-1]!=3);
        return 1;
    }
    if (!strcmp(t0,"%include")) {
        basm_token_arity(2,2);
        char fname[BASM_LINE_CAP]; filename_token(g_tok[1],fname,sizeof(fname));
        if(g_inc_depth>=INCLUDE_DEPTH)die("include depth exceeded");
        const BasmDependency *dep=basm_snapshot_open(fname,BASM_DEP_INCLUDE);
        basm_validate_source_bytes((const char *)dep->data,dep->len);
        if(dep->len==(size_t)-1)die("include too large");
        char *buf=malloc(dep->len+1); if(!buf)die("oom include");
        memcpy(buf,dep->data,dep->len); buf[dep->len]=0;
        g_inc_stack[g_inc_depth].buf=buf; g_inc_stack[g_inc_depth].p=buf;
        if(strlen(dep->path)>=sizeof(g_inc_stack[0].fname))die("include path too long");
        memcpy(g_inc_stack[g_inc_depth].fname,dep->path,strlen(dep->path)+1);
        g_inc_depth++;
        return 1;
    }
    if (!strcmp(t0,"align") || !strcmp(t0,"alignb")) {
        if (g_ntok<2 || source_commas()) die("align requires one expression");
        char expression[256]; basm_join_tokens(1,g_ntok,expression,sizeof(expression));
        int a=(int)basm_parse_count(expression,1073741824L,"align out of range");
        if (a <= 0 || (a & (a - 1)) != 0) die2("align needs positive power of two", g_tok[1]);
        if (a > g_secalign[g_cur]) g_secalign[g_cur] = a;
        if (g_cur<SEC_CUSTOM0 && a>g_secrequired[g_cur]) g_secrequired[g_cur]=a;
        /* `align` (vs `alignb`) fills with NOP (0x90) in progbits sections —
         * NASM does this for .text AND .rodata/.data; `alignb` fills with 0x00.
         * .bss has no contents. Match NASM byte-for-byte. */
        int fill = !strcmp(t0,"alignb") ? 0x00 : 0x90;
        long pad = (long)((a - (cur_off() % a)) % a);
        if (sec_is_nobits(g_cur)) reserve_bytes(pad);
        else emit_fill((uint8_t)fill, pad); /* INV-392 */
        return 1;
    }
    /* NAME equ expr */
    if (g_ntok>=3 && !strcmp(g_tok[1],"equ")) {
        /* reconstruct expr from remaining tokens (may contain spaces) */
        char ex[256]; ex[0]=0;
        basm_join_tokens(2,g_ntok,ex,sizeof(ex));
        long value;
        if (equ_constant_value(ex,&value)) const_set(t0,value);
        return 1;
    }
    /* data def directives: db/dw/dd/dq/resb */
    if (handle_data_directive()) return 1;
    /* incbin "file" [,skip[,count]] — embed a binary file verbatim into the
     * current section (used by initramfs_blob.S to ride the cpio archive in
     * .rodata). The filename token retains its quotes from the tokenizer.
     * Resolved relative to the including .asm's directory, then CWD, then -I
     * paths. Author: F E R M I ∞ H A R T. */
    if (!strcmp(t0,"incbin")) return handle_incbin_directive();
    /* times <n> <data-or-reserve-directive> ... */
    if (!strcmp(t0,"times")) return handle_times_directive(line);

    /* label "name:" possibly followed by a directive/instruction */
    size_t l=strlen(t0);
    if (l>1 && t0[l-1]==':') {
        if (l > NAME_MAX) die("label too long"); /* INV-542 */
        char name[NAME_MAX]; memcpy(name,t0,l-1); name[l-1]=0;
        /* INV-578: NASM rejects redefinition at a different address
         * ("inconsistently redefined") but accepts the same address
         * (fallthrough labels). Same-generation keying keeps multi-pass
         * redefinition working: the final pass needs the converged table. */
        label_intern_at_cur(name);
        if (g_ntok>1) {
            /* rest of line is a directive or instruction: shift tokens left */
            return label_rest_of_line(line);
        }
        return 1;
    }
    /* Implicit labels in data sections: "my_var dq 100" without colon */
    if ((g_cur==SEC_DATA || g_cur==SEC_RODATA || g_cur==SEC_BSS) &&
        (isalpha((unsigned char)t0[0]) || t0[0]=='_')) {
        /* Create implicit label */
        if (strlen(t0) >= NAME_MAX) die("label too long"); /* INV-542 */
        char name[NAME_MAX]; basm_name_copy(name,t0);
        label_intern_at_cur(name); /* INV-578 */
        /* Now process the rest of the line as directive */
        if (g_ntok>1) {
            return label_rest_of_line(line);
        }
        return 1;
    }

    return 0;
}

/* Process a single source buffer (used for main file and includes) */
static void process_source(char *src) {
    char *p = src;
    /* Per-source buffer for tokenization.  Allocated once per source to avoid
     * the StackAddressEscape warning that a fixed stack buffer would trigger
     * when g_tok points into it; lifetime is exactly this function call. */
    char *buf = (char*)malloc(BASM_LINE_CAP);
    if (!buf) die("oom source buffer");
    while (*p) {
        g_line++;
        if(g_explain)intent_location_expanded(g_line);
        g_intent_form_current=NULL; g_intent_instruction=0; g_intent_prefix=0;
        int trace_section=g_cur, trace_start=cur_off();
        char *eol = strchr(p, '\n');
        int len = checked_source_line_len(p, eol);
        g_data_source=p;
        /* N08: prove the line limit first, then parse supported complete
         * instruction spans directly from the immutable source. Failed fast
         * attempts emit nothing and retain the ordinary directive/token path. */
        if(g_if_active && !g_in_struc && g_cur!=SEC_DATA && g_cur!=SEC_RODATA &&
           g_cur!=SEC_BSS && try_fast_instruction(p)){
            if(g_explain)intent_trace_record(trace_section,trace_start,cur_off(),g_line,g_intent_form_current);
            g_ntok=0;
            if(!eol) break;
            p=eol+1;
            continue;
        }
        memcpy(buf, p, len); buf[len] = 0;
        if (g_target_profile && g_if_active && target_bits_line(buf)) {
            g_ntok = 0;
            if (!eol) break;
            p = eol + 1;
            continue;
        }
        if (g_if_active && handle_global_line(buf)) {
            g_ntok=0;
            if (!eol) break;
            p=eol+1;
            continue;
        }
        tokenize(buf);

        /* W04/W06: process only this include frame. A child must never
         * iterate back over its parent's still-active frame or open dead input. */
        if (g_ntok>0 && !strcmp(g_tok[0],"%include")) {
            if (g_if_active) {
                if(g_explain)die("intent: deferred include has no preprocessor provenance");
                handle_directive_or_label(buf);
                int idx=g_inc_depth-1, caller_line=g_line;
                const char *caller_file=g_file;
                g_file=g_inc_stack[idx].fname; g_line=0;
                process_source(g_inc_stack[idx].buf);
                free(g_inc_stack[idx].buf); g_inc_stack[idx].buf=NULL;
                g_inc_depth--;
                g_file=caller_file; g_line=caller_line;
            }
            p=eol ? eol+1 : p+strlen(p);
            continue;
        }

        /* Check conditional assembly state */
        int is_cond_directive = (g_ntok>0 && g_tok[0][0]=='%' && (
            !strcmp(g_tok[0],"%if") || !strcmp(g_tok[0],"%elif") ||
            !strcmp(g_tok[0],"%else") || !strcmp(g_tok[0],"%endif")));

        if (!g_if_active && !is_cond_directive) {
            /* Skip this line */
        } else {
            int direct_instruction=0;
            if(g_ntok>0 && !g_in_struc && (g_target_profile ||
               (g_cur!=SEC_DATA && g_cur!=SEC_RODATA && g_cur!=SEC_BSS))) {
                InsnKind kind=insn_kind(g_tok[0]);
                if(kind!=INSN_UNKNOWN){ g_prefetched_insn_kind=kind; direct_instruction=1; }
            }
            if(direct_instruction) do_instruction(); /* INV-550 */
            else if (!handle_directive_or_label(buf)) { if(g_ntok>0) do_instruction(); }
        }
        if(g_explain && g_intent_instruction)
            intent_trace_record(trace_section,trace_start,cur_off(),g_line,g_intent_form_current);
        if (!eol) break;
        p = eol + 1;
    }
    /* Tokens are ephemeral and point into the per-line stack buffer.  Clear
     * the global pointers before returning so static analyzers (and future
     * readers) know they are intentionally invalidated. */
    memset(g_tok,0,sizeof(g_tok));
    g_ntok = 0;
    g_data_source=NULL;
    free(buf);
}

static int layout_changed_and_capture(void) {
    LayoutSnapshot *s = &g_layout_snapshot;
    /* INV-777: the snapshot array tracks the live symbol pool's capacity. */
    if (s->syms_cap != g_sym_cap) {
        struct symsnap *ns = realloc(s->syms, (size_t)g_sym_cap * sizeof(*ns));
        if (!ns) die("out of memory (layout snapshot)");
        s->syms = ns;
        s->syms_cap = g_sym_cap;
        s->valid = 0;
    }
    int changed = !s->valid || s->textlen != g_textlen || s->datalen != g_datalen ||
        s->rodatalen != g_rodatalen || s->bsslen != g_bsslen ||
        s->nsyms != g_nsyms || s->nconsts != g_nconsts ||
        s->ncustom != g_ncustom || s->nsecorder != g_nsecorder;
    if (!changed) {
        for (int i=0;i<g_ncustom;i++) if (s->custom_len[i] != g_custom_len[i]) { changed=1; break; }
    }
    if (!changed) {
        for (int i=0;i<g_nsecorder;i++) if (s->secorder[i] != g_secorder[i]) { changed=1; break; }
    }
    if (!changed) {
        for (int i=0;i<g_nsyms;i++) {
            Sym *sym=&g_syms[i];
            if (s->syms[i].section != sym->section || s->syms[i].offset != sym->offset ||
                s->syms[i].defined != sym->defined || s->syms[i].global != sym->global) {
                changed=1; break;
            }
        }
    }
    if (!changed) {
        for (int i=0;i<g_nconsts;i++) if (s->const_values[i] != g_consts[i].value) { changed=1; break; }
    }
    /* W16: all tracked fields match the retained snapshot. Recopying the
     * symbol/constant arrays cannot change its next comparison result. */
    if (!changed) return 0;
    s->valid=1; s->textlen=g_textlen; s->datalen=g_datalen; s->rodatalen=g_rodatalen;
    s->bsslen=g_bsslen; s->nsyms=g_nsyms; s->nconsts=g_nconsts;
    s->ncustom=g_ncustom; s->nsecorder=g_nsecorder;
    for (int i=0;i<g_ncustom;i++) s->custom_len[i]=g_custom_len[i];
    for (int i=0;i<g_nsecorder;i++) s->secorder[i]=g_secorder[i];
    for (int i=0;i<g_nsyms;i++) {
        Sym *sym=&g_syms[i]; s->syms[i].section=sym->section; s->syms[i].offset=sym->offset;
        s->syms[i].defined=sym->defined; s->syms[i].global=sym->global;
    }
    for (int i=0;i<g_nconsts;i++) s->const_values[i]=g_consts[i].value;
    return changed;
}

static void assemble_pass(char *src) {
    intent_trace_reset_pass();
    file_spans_reset();
    g_sym_gen++; /* INV-578: same-generation redefinition is a duplicate. */
    for (int i=0;i<g_nsyms;i++) {
        free(g_syms[i].size_expr); g_syms[i].size_expr=NULL;
        g_syms[i].size_scope=NULL; g_syms[i].size=0;
        g_wrt_line[i]=0; g_pc32_line[i]=0; g_extern_sym[i]=0;
        g_syms[i].binding_decl=0;
    }
    g_textlen=0; g_datalen=0; g_rodatalen=0; g_bsslen=0; g_cur=SEC_TEXT; g_last_global[0]=0;
#ifndef BASM_PUBLIC_ONLY
    g_bits=64;
#endif
    g_default_rel=0; /* directives override these defaults each pass */
    g_secalign[SEC_TEXT]=16; g_secalign[SEC_DATA]=4; g_secalign[SEC_BSS]=4;
    g_secalign[SEC_RODATA]=4; g_secalign[SEC_NOTE]=1;
    memset(g_secrequired,0,sizeof(g_secrequired));
    /* Reset custom sections each pass; the `section` directive re-declares
     * them by name as the source is re-scanned. Author: F E R M I ∞ H A R T. */
    for (int i=0;i<CUSTOM_MAX;i++){ g_custom_len[i]=0; g_secalign[SEC_CUSTOM0+i]=1; }
    g_ncustom=0;
    g_nsecorder=0;
    g_branch_ord=0; g_nrelocs=0; g_fwd_unresolved=0;
    g_deferred_content=0;
    g_layout_contextual_seen=0;
    g_inc_depth = 0;
    g_if_depth=0; g_if_active=1;
    g_in_struc=0; g_istruc_depth=0;
    g_line = 0;
    g_file = "<stdin>";
    expr_cache_reset();
    process_source(src);
    if (g_if_depth) die("unterminated assembly conditional");
    if (g_in_struc) die("unterminated structure");
    if (g_istruc_depth) die("unterminated istruc");
    /* Cleanup any pending includes */
    while (g_inc_depth > 0) { free(g_inc_stack[--g_inc_depth].buf); }
    if (g_pass==2) {
        int line=g_line;
        validate_symbol_sizes();
        for (int i=0;i<g_nsyms;i++) if (g_pc32_line[i]) {
            Sym *s=&g_syms[i]; g_line=g_pc32_line[i];
            if (s->defined ? s->defgen!=g_sym_gen || s->section==SEC_NONE : !g_extern_sym[i])
                die2("relative data field requires a defined label or extern",s->name);
        }
        for (int i=0;i<g_nsyms;i++) if (g_wrt_line[i]) {
            Sym *s=&g_syms[i]; g_line=g_wrt_line[i];
            if (!s->global || (s->defined ? s->defgen!=g_sym_gen || s->section==SEC_NONE : !g_extern_sym[i]))
                die2("dq wrt ..sym requires a defined global or extern",s->name);
        }
        g_line=line;
    }
}
