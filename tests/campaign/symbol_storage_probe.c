/* N13: native internal-state assertions; this does not execute emitted code.
 * Compile against an immutable build receipt's source snapshot with
 * -DBASM_SOURCE='"/absolute/source/basm.c"' and --gc-sections. */
#define main basm_unused_entry_for_symbol_probe
#include BASM_SOURCE
#undef main
#include <assert.h>

static void probe_name(int index,char out[NAME_MAX+1]) {
    if (index==0) { strcpy(out,"declinate"); return; }
    if (index==1) { strcpy(out,"macallums"); return; }
    if (index==2) { memset(out,'z',NAME_MAX-1); out[NAME_MAX-1]=0; return; }
    if (index==3) { strcpy(out,"costarring"); return; }
    if (index==4) { strcpy(out,"liquid"); return; }
    snprintf(out,NAME_MAX+1,"probe_symbol_%06d",index);
}

int main(int argc,char **argv) {
    assert(NAME_MAX==256 && SYM_HARD_CAP==262144); /* public capacity contract */
    const char *mode=argc>1 ? argv[1] : "ordinary";
    if (!strcmp(mode,"long-refusal")) {
        char invalid[NAME_MAX+1]; memset(invalid,'q',NAME_MAX); invalid[NAME_MAX]=0;
        sym_intern(invalid); return 90;
    }
    int count=(!strcmp(mode,"hard-cap") || !strcmp(mode,"overflow")) ? SYM_HARD_CAP : 10000;
    const char *anchors[5]={0};
    int growths=0, previous_cap=0;
    for (int i=0;i<count;i++) {
        char name[NAME_MAX+1]; probe_name(i,name);
        Sym *symbol=sym_intern(name);
        assert(symbol==&g_syms[i] && g_nsyms==i+1);
        assert(!strcmp(symbol->name,name) && symbol->name_len==strlen(name));
        assert(!symbol->defined && !symbol->global && !symbol->is_func && !symbol->is_object);
        assert(!symbol->hidden && !symbol->binding_decl && !symbol->weak && !symbol->is_local);
        assert(!symbol->size && !symbol->size_expr && !symbol->size_scope && !symbol->size_line);
        assert(symbol->section==SEC_NONE && symbol->defseq==-1 && !symbol->defgen && !symbol->offset);
        assert(!g_wrt_line[i] && !g_pc32_line[i] && !g_extern_sym[i]);
        if (i<5) anchors[i]=symbol->name;
        symbol->offset=i; symbol->defined=1; symbol->defseq=count-i; symbol->defgen=7;
        symbol->global=(uint8_t)(i&1); symbol->is_func=(uint8_t)(i%3==0);
        g_wrt_line[i]=i+11; g_pc32_line[i]=i+13; g_extern_sym[i]=(uint8_t)(i&1);
        memset(name,'!',sizeof(name)); /* names must own bytes, not this buffer */
        if (g_sym_cap!=previous_cap) { growths++; previous_cap=g_sym_cap; }
        if (i>=4) for (int j=0;j<5;j++) {
            char expected[NAME_MAX+1]; probe_name(j,expected);
            assert(g_syms[j].name==anchors[j] && !strcmp(anchors[j],expected));
        }
    }
    assert(g_sym_cap<=SYM_HARD_CAP && g_sym_ht_cap==g_sym_cap*2);
    assert(str_hash("declinate",9)==str_hash("macallums",9));
    assert(sym_find("declinate")!=sym_find("macallums"));
    for (int i=count-1;i>=0;i--) {
        char name[NAME_MAX+1]; probe_name(i,name);
        Sym *symbol=sym_intern(name);
        assert(symbol==&g_syms[i] && sym_find(name)==symbol && g_nsyms==count);
        assert(symbol->offset==i && symbol->defseq==count-i && symbol->defgen==7);
        assert(symbol->global==(i&1) && symbol->is_func==(i%3==0));
        assert(g_wrt_line[i]==i+11 && g_pc32_line[i]==i+13 && g_extern_sym[i]==(i&1));
    }
    assert(!sym_find("not_in_the_pool"));
    char overlong[NAME_MAX+1]; memset(overlong,'q',NAME_MAX); overlong[NAME_MAX]=0;
    assert(!sym_find(overlong));
    size_t blocks=0,used=0;
    for (SymNameBlock *b=g_sym_name_blocks;b;b=b->next) {
        assert(b->used<=sizeof(b->bytes)); blocks++; used+=b->used;
    }
    printf("{\"mode\":\"%s\",\"symbols\":%d,\"record_bytes\":%zu,\"hash_entry_bytes\":%zu,"
           "\"symbol_capacity\":%d,\"hash_capacity\":%d,\"growth_events\":%d,"
           "\"name_blocks\":%zu,\"name_bytes_used\":%zu,\"names_reserved_bytes\":%zu,"
           "\"record_reserved_bytes\":%zu,\"hash_reserved_bytes\":%zu,"
           "\"annotation_reserved_bytes\":%zu,\"status\":\"PASS\"}\n",
           mode,g_nsyms,sizeof(Sym),sizeof(*g_sym_ht),g_sym_cap,g_sym_ht_cap,growths,
           blocks,used,blocks*sizeof(SymNameBlock),(size_t)g_sym_cap*sizeof(Sym),
           (size_t)g_sym_ht_cap*sizeof(*g_sym_ht),
           (size_t)g_sym_cap*(sizeof(*g_wrt_line)+sizeof(*g_pc32_line)+sizeof(*g_extern_sym)));
    if (!strcmp(mode,"overflow")) { sym_intern("one_symbol_too_many"); return 91; }
    return 0;
}
