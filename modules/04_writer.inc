/*
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ------------------------------------------------------------------ */
/* ELF64 writer                                                       */
/* ------------------------------------------------------------------ */
#define WRITE_BUF_SIZE 65536
typedef struct {
    FILE *stream;
    int fd;
    uint8_t buf[WRITE_BUF_SIZE];
    size_t len;
    long pos;
} BasmOut;

static void out_raw(BasmOut *f, const uint8_t *p, size_t n) {
    while (n) {
        long wrote;
        do { wrote = (long)write(f->fd, p, n); }
        while (wrote < 0 && errno == EINTR);
        if (wrote <= 0) die("write error"); /* INV-541/INV-543 */
        p += (size_t)wrote;
        n -= (size_t)wrote;
        f->pos += wrote;
    }
}

static void out_flush(BasmOut *f) {
    if (!f->len) return;
    out_raw(f, f->buf, f->len);
    f->len = 0;
}

/* INV-579: a name is not ownership. Keep the exclusively created stream open;
 * never truncate/follow or remove a stale file, symlink or hardlink candidate. */
static FILE *out_tmp_open(const char *path, char *tmp, size_t capacity) {
    for (unsigned int attempt=0; attempt<32; attempt++) {
        int n=attempt ? snprintf(tmp,capacity,"%s.tmp.%ld.%u",path,(long)getpid(),attempt) :
                        snprintf(tmp,capacity,"%s.tmp.%ld",path,(long)getpid());
        if(n<0 || (size_t)n>=capacity) { errno=ENAMETOOLONG; break; }
        FILE *stream=fopen(tmp,"w+bex");
        if(stream)return stream;
        if(errno!=EEXIST)break;
    }
    if(capacity)tmp[0]=0;
    return NULL;
}

static void out_open(BasmOut *f, FILE *stream) {
    /* INV-C18: every emitted byte is written before len exposes it; clearing
     * the unused 64 KiB staging buffer on each output is unnecessary. */
    f->len=0; f->pos=0;
    f->stream = stream;
    if (setvbuf(f->stream, NULL, _IONBF, 0) != 0) die("cannot disable output buffering");
    f->fd = fileno(f->stream);
    if (f->fd < 0) die("cannot get output descriptor");
}

static void out_finish(BasmOut *f) {
    out_flush(f);
    /* The caller owns close/publication and may first copy this exact stream
     * to escrow. Raw writes have completed; no final pathname is reopened. */
}

static long out_pos(const BasmOut *f) { return f->pos + (long)f->len; }

static void w8(BasmOut*f,uint8_t v){
    if (f->len == sizeof(f->buf)) out_flush(f);
    f->buf[f->len++] = v;
}
static void out_room(BasmOut *f,size_t n){ if(n>sizeof(f->buf)-f->len) out_flush(f); }
/* INV-N21: memcpy permits unaligned destinations without type punning.
 * Only a compiler-declared little-endian host uses the native representation;
 * all other compilers retain explicit byte stores for the ELF wire format. */
static void store_le16(uint8_t *p,uint16_t v){
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    memcpy(p,&v,sizeof(v));
#else
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8);
#endif
}
static void store_le32(uint8_t *p,uint32_t v){
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    memcpy(p,&v,sizeof(v));
#else
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8);
    p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
#endif
}
static void store_le64(uint8_t *p,uint64_t v){
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    memcpy(p,&v,sizeof(v));
#else
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8);
    p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
    p[4]=(uint8_t)(v>>32); p[5]=(uint8_t)(v>>40);
    p[6]=(uint8_t)(v>>48); p[7]=(uint8_t)(v>>56);
#endif
}
static void w16(BasmOut*f,uint16_t v){
    out_room(f,2); store_le16(f->buf+f->len,v); f->len+=2;
}
static void w32(BasmOut*f,uint32_t v){
    out_room(f,4); store_le32(f->buf+f->len,v); f->len+=4;
}
static void w64(BasmOut*f,uint64_t v){
    out_room(f,8); store_le64(f->buf+f->len,v); f->len+=8;
}

static void write_bytes(BasmOut *f, const void *p, size_t n) {
    const uint8_t *src = (const uint8_t*)p;
    if (n >= sizeof(f->buf)) {
        out_flush(f);
        out_raw(f, src, n);
        return;
    }
    if (n > sizeof(f->buf) - f->len) out_flush(f);
    if (n) memcpy(f->buf + f->len, src, n);
    f->len += n;
}

/* All padding is initialized before its length becomes visible to flush. */
static void out_zero(BasmOut *f,size_t n) {
    while(n){
        if(f->len==sizeof(f->buf))out_flush(f);
        size_t chunk=sizeof(f->buf)-f->len;
        if(chunk>n)chunk=n;
        memset(f->buf+f->len,0,chunk); f->len+=chunk; n-=chunk;
    }
}
static void out_pad_to(BasmOut *f,long target) {
    long pos=out_pos(f);
    if(target>pos)out_zero(f,(size_t)(target-pos));
}

static int sec_len(int sec);
static const uint8_t *sec_buf(int sec);

/* INV-C07: emit the exact bytes admitted once by the dependency registry.
 * A retained descriptor cannot prevent an in-place writer from changing a file. */
static void write_file_span(BasmOut *out, FileSpan *span) {
    if (span->file_offset<0 || span->length<0) die("invalid incbin snapshot span");
    write_bytes(out,span->data+(size_t)span->file_offset,(size_t)span->length);
}

static void write_section_contents(BasmOut *out, int sec) {
    int pos=0, len=sec_len(sec);
    const uint8_t *buf=sec_buf(sec);
    for(int i=0;i<g_nfile_spans;i++){
        FileSpan *span=&g_file_spans[i];
        if(span->section!=sec) continue;
        if(span->section_offset<pos || span->length>len-span->section_offset)
            die("invalid incbin span");
        if(span->section_offset>pos)
            write_bytes(out,buf+pos,(size_t)(span->section_offset-pos));
        write_file_span(out,span);
        pos=span->section_offset+(int)span->length;
    }
    if(len>pos) write_bytes(out,buf+pos,(size_t)(len-pos));
}

/* INV-777: string tables grow geometrically on the heap. A fixed 64 KiB
 * buffer overflowed on a real TU (bear_parse_expr lowers to ~10k live
 * labels; their names alone exceed it). Fail-closed on OOM. */
typedef struct { char *buf; int len; int cap; } Strtab;
static int strtab_add(Strtab*st,const char*s){
    if(!st->cap){
        st->cap=4096; /* Small units do not reserve a 64 KiB table twice. */
        st->buf=(char*)malloc((size_t)st->cap);
        if(!st->buf){dprintf(2,"strtab oom\n");exit(1);}
        st->buf[0]=0; st->len=1;
    }
    size_t size=strlen(s)+1;
    if(size>2147483647UL || size>(size_t)(2147483647-st->len))
        die("ELF string table too large");
    int off=st->len; int n=(int)size;
    while(st->len+n>st->cap){
        int ncap=st->cap>1073741823 ? 2147483647 : st->cap*2;
        char *nb=(char*)realloc(st->buf,(size_t)ncap);
        if(!nb){dprintf(2,"strtab oom\n");exit(1);}
        st->buf=nb; st->cap=ncap;
    }
    memcpy(st->buf+st->len,s,n); st->len+=n; return off;
}

/* N12: negative indices encode constants as -(index+1); nonnegative
 * indices address labels. The stable ordering record needs only eight bytes. */
typedef struct { int idx,seq; } SymMap;

/* INV-C17: stable O(n log n) ordering even when first-intern order is the
 * reverse of definition order. Already ordered and tiny tables avoid scratch
 * allocation. Equal-sequence entries retain their original merge order. */
static void symmap_sort(SymMap *items,int count) {
    int ordered=1;
    for(int i=1;i<count;i++)if(items[i-1].seq>items[i].seq){ordered=0;break;}
    if(ordered)return;
    if(count<=32){
        for(int i=1;i<count;i++){
            SymMap value=items[i]; int j=i;
            while(j>0 && items[j-1].seq>value.seq){items[j]=items[j-1];j--;}
            items[j]=value;
        }
        return;
    }
    SymMap *scratch=malloc((size_t)count*sizeof(*scratch));
    if(!scratch)die("out of memory (symbol order)");
    SymMap *src=items,*dst=scratch;
    for(int width=1;width<count;width*=2){
        for(int start=0;start<count;start+=width*2){
            int mid=start+width; if(mid>count)mid=count;
            int end=mid+width; if(end>count)end=count;
            int left=start,right=mid,pos=start;
            while(left<mid && right<end){
                if(src[left].seq<=src[right].seq)dst[pos++]=src[left++];
                else dst[pos++]=src[right++];
            }
            while(left<mid)dst[pos++]=src[left++];
            while(right<end)dst[pos++]=src[right++];
        }
        SymMap *swap=src;src=dst;dst=swap;
    }
    if(src!=items)memcpy(items,src,(size_t)count*sizeof(*items));
    free(scratch);
}
#define STB_LOCAL 0
#define STB_GLOBAL 1
#define STT_NOTYPE 0
#define STT_OBJECT 1
#define STT_FUNC 2
#define STT_SECTION 3
#define STT_FILE 4

/* section indices in the output are assigned dynamically (NASM order). */
static int g_sh_index[SEC_MAX]; /* SEC_* -> output section header index, or 0 */

/* W1.2: proof-carrying objects. `--emit-exec-proof` appends a synthetic
 * `.note.TinaProof` section (SHT_NOTE, ALLOC) AFTER all source sections, so
 * existing headers, symbols and relocations are byte-identical with the flag
 * off AND all previously emitted bytes stay put with the flag on. Unsigned
 * unless `--sign-exec-proof KEY` fills the signature field. */
static int g_exec_proof = 0;
static uint8_t g_exec_proof_seed[32];
static int g_exec_proof_signed = 0;
static const char *g_exec_sign_key = NULL; /* global, not a main local: keeps main's frame small */
#define EXEC_PROOF_BUFSZ 4096
static uint8_t g_proof_buf[EXEC_PROOF_BUFSZ];
static int build_exec_proof_note(uint8_t *out, size_t cap);

/* Uniform section accessors so the ELF writer treats fixed + custom sections
 * identically. Author: F E R M I ∞ H A R T. */
static int sec_len(int sec){
    if (sec>=SEC_CUSTOM0) return g_custom_len[custom_idx(sec)];
    return (sec==SEC_TEXT)?g_textlen : (sec==SEC_DATA)?g_datalen :
           (sec==SEC_RODATA)?g_rodatalen : (sec==SEC_BSS)?(int)g_bsslen : 0;
}
static const uint8_t *sec_buf(int sec){
    if (sec>=SEC_CUSTOM0) return g_custom_buf[custom_idx(sec)];
    return (sec==SEC_TEXT)?g_text : (sec==SEC_DATA)?g_data :
           (sec==SEC_RODATA)?g_rodata : NULL;
}
static int sec_has_content(int sec){ /* progbits-like (occupies file space) */
    if (sec>=SEC_CUSTOM0) return g_custom_type[custom_idx(sec)]!=8;
    return sec==SEC_TEXT||sec==SEC_DATA||sec==SEC_RODATA;
}
static const char *secname(int sec){
    if (sec>=SEC_CUSTOM0) return g_custom_name[custom_idx(sec)];
    return sec>=0 ? g_fixed_sec_names[sec] : ".note.GNU-stack";
}

static void write_bin(FILE *stream) {
    /* Raw binary: dump .text + .data + .rodata in appearance order.
     * No ELF headers, no relocations, no symbol table. */
    if (g_exec_proof) die("exec proof requires elf64 output"); /* W1.2 */
    if (g_nrelocs) die("bin output cannot contain relocations"); /* INV-541 */
    /* INV-592: instructions before the first SECTION belong to .text. If it
     * was never explicitly selected, preserve those bytes before later sections. */
    if(g_textlen>0){
        int found=0;
        for(int i=0;i<g_nsecorder;i++)if(g_secorder[i]==SEC_TEXT)found=1;
        if(!found){
            if(g_nsecorder>=SEC_MAX)die("too many output sections");
            memmove(g_secorder+1,g_secorder,(size_t)g_nsecorder*sizeof(g_secorder[0]));
            g_secorder[0]=SEC_TEXT; g_nsecorder++;
        }
    }
    BasmOut storage; BasmOut *f = &storage; out_open(f, stream);
    for (int i=0;i<g_nsecorder;i++){
        int sec = g_secorder[i];
        if (sec_has_content(sec)) write_section_contents(f,sec);
    }
    out_finish(f);
}

/* INV-586: serialize the common ELF64 section-header layout only once. */
static void write_shdr(BasmOut *f, int name, int type, uint64_t flags,
                       uint64_t offset, uint64_t length, int link, int info,
                       uint64_t align, uint64_t entsize) {
    out_room(f,64);
    uint8_t *p=f->buf+f->len;
    store_le32(p,(uint32_t)name); store_le32(p+4,(uint32_t)type);
    store_le64(p+8,flags); store_le64(p+16,0); store_le64(p+24,offset);
    store_le64(p+32,length); store_le32(p+40,(uint32_t)link); store_le32(p+44,(uint32_t)info);
    store_le64(p+48,align); store_le64(p+56,entsize); f->len+=64;
}

/* Bound every planned .strtab offset by the pre-existing signed-int limit. */
static void symbol_name_add_size(uint32_t *length,size_t bytes) {
    if (bytes>(size_t)(2147483647U-*length)) die("ELF string table too large");
    *length+=(uint32_t)bytes;
}

static void write_symbol(BasmOut *out,uint32_t name,uint8_t info,uint8_t other,
                         uint16_t section,uint64_t value,uint64_t size) {
    w32(out,name); w8(out,info); w8(out,other); w16(out,section);
    w64(out,value); w64(out,size);
}

static void write_elf(FILE *stream) {
    if (g_nsecorder == 0 || g_textlen > 0) secorder_touch(SEC_TEXT);
    secorder_touch(SEC_NOTE);

    /* Which content sections have relocations (in appearance order) -> each
     * gets a .rela.<sec> section. NASM section order:
     *   NULL, <content in appearance order>, .shstrtab, .symtab, .strtab,
     *   .rela.<sec> for each content sec with relocs (appearance order). */
    int has_rela[SEC_MAX]={0};
    for (int i=0;i<g_nrelocs;i++) has_rela[g_relocs[i].section]=1;

    for (int i=0;i<SEC_MAX;i++) g_sh_index[i]=0;
    int shidx = 1;
    for (int i=0;i<g_nsecorder;i++) g_sh_index[g_secorder[i]] = shidx++;
    int idx_shstr  = shidx++;
    int idx_symtab = shidx++;
    int idx_strtab = shidx++;
    int rela_shidx[SEC_MAX]={0};
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i];
        if (has_rela[sec]) rela_shidx[sec]=shidx++; }
    int idx_proof = 0;
    if (g_exec_proof) idx_proof = shidx++;
    int nsec = shidx;
    int shstrndx = idx_shstr;
    (void)idx_proof; /* position is last-content; headers are located by name */

    /* ---- symbol plan ---- */
    /* N12: plan indices and string lengths, then stream ELF records directly.
     * No duplicate E64Sym array or full symbol-name string table is resident.
     * Every emitted name contributes once to this checked length plan. */
    int nloc=0, nglobal=0;
    uint32_t strtab_len=1;
    size_t source_name_size=strlen(g_srcname)+1;
    symbol_name_add_size(&strtab_len,source_name_size);
    for (int i=0;i<g_nconsts;i++) if (g_consts[i].emit_sym) {
        nloc++; symbol_name_add_size(&strtab_len,strlen(g_consts[i].name)+1);
    }
    for (int i=0;i<g_nsyms;i++) {
        Sym *symbol=&g_syms[i];
        if (symbol->global) nglobal++;
        else if (symbol->defined) nloc++;
        else continue;
        symbol_name_add_size(&strtab_len,(size_t)symbol->name_len+1);
    }
    int first_global=2+g_nsecorder+nloc;
    int nsym=first_global+nglobal;
    SymMap *loc=nloc ? malloc((size_t)nloc*sizeof(*loc)) : NULL;
    if (nloc && !loc) die("out of memory (ELF local symbol order)");

    /* Unreferenced symbols need no additional dense index map. A section-only
     * relocation table likewise uses sec_sym_index, without per-label storage. */
    int need_named_index=0;
    for (int i=0;i<g_nrelocs;i++) if (!g_relocs[i].sym_kind) { need_named_index=1; break; }
    int *sym_index_of=NULL;
    if (need_named_index && g_nsyms) {
        sym_index_of=malloc((size_t)g_nsyms*sizeof(*sym_index_of));
        if (!sym_index_of) die("out of memory (ELF relocation symbol index)");
        for (int i=0;i<g_nsyms;i++) sym_index_of[i]=-1;
    }
    int sec_sym_index[SEC_MAX];
    for (int i=0;i<SEC_MAX;i++) sec_sym_index[i]=-1;
    for (int i=0;i<g_nsecorder;i++) sec_sym_index[g_secorder[i]]=2+i;

    /* Local constants and labels retain source-definition order. Equal keys
     * retain the original constants-before-labels order in the stable sort. */
    int local_at=0;
    for (int i=0;i<g_nconsts;i++) if (g_consts[i].emit_sym) {
        loc[local_at].idx=-i-1; loc[local_at].seq=g_consts[i].defseq; local_at++;
    }
    for (int i=0;i<g_nsyms;i++) {
        Sym *symbol=&g_syms[i];
        if (symbol->defined && !symbol->global) {
            loc[local_at].idx=i; loc[local_at].seq=symbol->defseq; local_at++;
        }
    }
    if (local_at!=nloc) die("ELF symbol planning mismatch");
    symmap_sort(loc,nloc);
    if (sym_index_of) {
        for (int i=0;i<nloc;i++) if (loc[i].idx>=0)
            sym_index_of[loc[i].idx]=2+g_nsecorder+i;
        int global_at=first_global;
        for (int i=0;i<g_nsyms;i++) if (g_syms[i].global) sym_index_of[i]=global_at++;
    }

    /* ---- section header string table (NASM order: content, shstrtab,
     * symtab, strtab, rela.*) ---- */
    Strtab shstr={0}; strtab_add(&shstr,"");
    int sh_name[SEC_MAX]={0};
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i];
        sh_name[sec]=strtab_add(&shstr,secname(sec)); }
    int shn_shstr =strtab_add(&shstr,".shstrtab");
    int shn_symtab=strtab_add(&shstr,".symtab");
    int shn_strtab=strtab_add(&shstr,".strtab");
    int shn_proof = 0;
    if (g_exec_proof) shn_proof = strtab_add(&shstr,".note.TinaProof"); /* W1.2: opted-in only */
    int rela_name[SEC_MAX]={0};
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i]; if(!has_rela[sec])continue;
        /* INV-BASM-STANDALONE-004: every admitted section name must survive
         * the .rela prefix exactly; a fixed 96-byte buffer collapsed distinct
         * long section names into the same silently truncated spelling. */
        char nm[NAME_MAX+5];
        const char *section_name=secname(sec);
        size_t name_len=strlen(section_name);
        if(name_len>sizeof(nm)-sizeof(".rela"))die("relocation section name too long");
        memcpy(nm,".rela",sizeof(".rela")-1);
        memcpy(nm+sizeof(".rela")-1,section_name,name_len+1);
        rela_name[sec]=strtab_add(&shstr,nm); }

    /* count relocs per section */
    int rela_count[SEC_MAX]={0};
    for (int i=0;i<g_nrelocs;i++) rela_count[g_relocs[i].section]++;

    /* ---- file layout: NASM places the section header table immediately after
     * the ELF header (offset 64), then section contents, then shstrtab,
     * symtab, strtab, rela.* ---- */
    uint64_t shoff = 64;
    uint64_t off = 64 + (uint64_t)nsec*64;
    uint64_t sec_off[SEC_MAX]={0};
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i];
        while(off%16)off++;            /* NASM aligns every section's file offset to 16 */
        sec_off[sec]=off;
        if (sec_has_content(sec)) off+=sec_len(sec);
        /* bss/note: no file content */
    }
    /* W1.2: proof bytes ride right after source contents, before shstrtab,
     * mirroring emission order below. */
    uint64_t proof_off = 0; int proof_len = 0;
    if (g_exec_proof) {
        proof_len = build_exec_proof_note(g_proof_buf, sizeof(g_proof_buf));
        if (proof_len <= 0) die("exec proof too large");
        while(off%16)off++;
        proof_off = off; off += (uint64_t)proof_len;
    }
    while(off%16)off++;
    uint64_t shstr_off=off; off+=shstr.len;
    while(off%16)off++;
    uint64_t symtab_off=off; off+=(uint64_t)nsym*24;
    while(off%16)off++;
    uint64_t strtab_off=off; off+=strtab_len;
    uint64_t rela_off[SEC_MAX]={0};
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i]; if(!has_rela[sec])continue;
        while(off%16)off++;
        rela_off[sec]=off; off+=(uint64_t)rela_count[sec]*24; }

    BasmOut storage; BasmOut *f=&storage; out_open(f,stream);
    w8(f,0x7f);w8(f,'E');w8(f,'L');w8(f,'F');w8(f,2);w8(f,1);w8(f,1);w8(f,0);
    out_zero(f,8);
    w16(f,1); w16(f,0x3e); w32(f,1); w64(f,0); w64(f,0); w64(f,shoff);
    w32(f,0); w16(f,64); w16(f,0); w16(f,0); w16(f,64); w16(f,nsec); w16(f,shstrndx);

    /* ---- section headers (immediately after ELF header) ---- */
    out_zero(f,64); /* null */
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i];
        if (sec==SEC_TEXT){ write_shdr(f,sh_name[sec],1,0x6,sec_off[sec],g_textlen,0,0,g_secalign[sec],0); }
        else if (sec==SEC_DATA){ write_shdr(f,sh_name[sec],1,0x3,sec_off[sec],g_datalen,0,0,g_secalign[sec],0); }
        else if (sec==SEC_RODATA){ write_shdr(f,sh_name[sec],1,0x2,sec_off[sec],g_rodatalen,0,0,g_secalign[sec],0); }
        else if (sec==SEC_BSS){ write_shdr(f,sh_name[sec],8,0x3,sec_off[sec],(uint64_t)g_bsslen,0,0,g_secalign[sec],0); }
        else if (sec>=SEC_CUSTOM0){ int ci=custom_idx(sec);
            write_shdr(f,sh_name[sec],g_custom_type[ci],g_custom_flags[ci],sec_off[sec],
                       (uint64_t)g_custom_len[ci],0,0,g_secalign[sec],0); }
        else { write_shdr(f,sh_name[sec],1,0,sec_off[sec],0,0,0,1,0); }
    }
    write_shdr(f,shn_shstr,3,0,shstr_off,shstr.len,0,0,1,0);
    write_shdr(f,shn_symtab,2,0,symtab_off,(uint64_t)nsym*24,idx_strtab,first_global,8,24);
    write_shdr(f,shn_strtab,3,0,strtab_off,strtab_len,0,0,1,0);
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i]; if(!has_rela[sec])continue;
        write_shdr(f,rela_name[sec],4,0,rela_off[sec],(uint64_t)rela_count[sec]*24,
                   idx_symtab,g_sh_index[sec],8,24);
    }
    if (g_exec_proof) write_shdr(f,shn_proof,7,0x2,proof_off,(uint64_t)proof_len,0,0,4,0);

    /* ---- section contents in appearance order ---- */
    for (int i=0;i<g_nsecorder;i++){ int sec=g_secorder[i];
        out_pad_to(f,(long)sec_off[sec]);
        if (sec_has_content(sec)) write_section_contents(f,sec);
    }
    if (g_exec_proof) {
        out_pad_to(f,(long)proof_off);
        write_bytes(f, g_proof_buf, (size_t)proof_len);
    }
    out_pad_to(f,(long)shstr_off);
    write_bytes(f, shstr.buf, (size_t)shstr.len);
    out_pad_to(f,(long)symtab_off);
    write_symbol(f,0,0,0,0,0,0); /* NULL */
    uint32_t name_off=1;
    write_symbol(f,name_off,(STB_LOCAL<<4)|STT_FILE,0,0xfff1,0,0);
    name_off+=(uint32_t)source_name_size;
    for (int i=0;i<g_nsecorder;i++)
        write_symbol(f,0,(STB_LOCAL<<4)|STT_SECTION,0,g_sh_index[g_secorder[i]],0,0);
    for (int i=0;i<nloc;i++) {
        int index=loc[i].idx;
        if (index<0) {
            Const *constant=&g_consts[-index-1];
            write_symbol(f,name_off,(STB_LOCAL<<4)|STT_NOTYPE,0,0xfff1,(uint64_t)constant->value,0);
            name_off+=(uint32_t)strlen(constant->name)+1;
        } else {
            Sym *symbol=&g_syms[index];
            int type=symbol->is_func?STT_FUNC:symbol->is_object?STT_OBJECT:STT_NOTYPE;
            write_symbol(f,name_off,(STB_LOCAL<<4)|type,0,g_sh_index[symbol->section],symbol->offset,symbol->size);
            name_off+=(uint32_t)symbol->name_len+1;
        }
    }
    for (int i=0;i<g_nsyms;i++) {
        Sym *symbol=&g_syms[i]; if (!symbol->global) continue;
        int bind=symbol->weak ? 2 /* STB_WEAK */ : STB_GLOBAL;
        int type=symbol->is_func?STT_FUNC:symbol->is_object?STT_OBJECT:STT_NOTYPE;
        write_symbol(f,name_off,(bind<<4)|(symbol->defined?type:STT_NOTYPE),symbol->hidden?2:0,
                     symbol->defined?g_sh_index[symbol->section]:0,
                     symbol->defined?(uint64_t)symbol->offset:0,symbol->defined?symbol->size:0);
        name_off+=(uint32_t)symbol->name_len+1;
    }
    if (name_off!=strtab_len) die("ELF symbol name planning mismatch");
    out_pad_to(f,(long)strtab_off);
    w8(f,0); write_bytes(f,g_srcname,source_name_size);
    for (int i=0;i<nloc;i++) {
        int index=loc[i].idx;
        if (index<0) {
            const char *name=g_consts[-index-1].name;
            write_bytes(f,name,strlen(name)+1);
        } else {
            Sym *symbol=&g_syms[index];
            write_bytes(f,symbol->name,(size_t)symbol->name_len+1);
        }
    }
    for (int i=0;i<g_nsyms;i++) if (g_syms[i].global)
        write_bytes(f,g_syms[i].name,(size_t)g_syms[i].name_len+1);
    for (int si=0;si<g_nsecorder;si++){ int sec=g_secorder[si]; if(!has_rela[sec])continue;
        out_pad_to(f,(long)rela_off[sec]);
        for (int i=0;i<g_nrelocs;i++){ Reloc*r=&g_relocs[i]; if(r->section!=sec)continue;
            int ix=-1;
            if (r->sym_kind==1) ix=sec_sym_index[r->target_sec];
            else { Sym*s=sym_find(r->sym); if(s && sym_index_of) ix=sym_index_of[(int)(s - g_syms)]; }
            if(ix<0) die2("reloc against unknown symbol", r->sym_kind?"<section>":r->sym);
            w64(f,(uint64_t)r->offset); w64(f,((uint64_t)ix<<32)|r->reltype); w64(f,(uint64_t)r->addend);
        }
    }

    free(sym_index_of); free(loc); free(shstr.buf);
    out_finish(f);
    (void)idx_symtab; (void)rela_shidx;
}
