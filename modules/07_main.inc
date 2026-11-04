/*
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ------------------------------------------------------------------ */
#include "../version.h"

static const char *cli_build_profile(void) {
#ifdef BASM_PUBLIC_ONLY
    return "public-only";
#else
    return "bootstrap-capable";
#endif
}

static int cli_version(void) {
    printf("BearBasm %s (%s)\n", BASM_VERSION, cli_build_profile());
    return fflush(stdout) != 0 || ferror(stdout) ? 1 : 0;
}

static int cli_help(void) {
    printf("BearBasm %s (%s) - NASM-syntax x86-64 assembler subset\n\n",
           BASM_VERSION, cli_build_profile());
    fputs("Usage:\n"
          "  basm [options] input.basm\n"
          "  basm --verify-attestation[-strict] FILE [--trusted-key KEY]\n"
          "  basm --batch JOBS.tsv [--jobs N]\n"
          "  basm --help | --version\n\n"
          "Assembly:\n"
          "  -f elf64|bin                  Output format (default: elf64)\n"
          "  -o FILE                       Output path (default: a.out.o)\n"
          "  -I PATH, -IPATH                Add an include path; repeatable\n"
          "  -D NAME[=VALUE]                Define a preprocessor name; repeatable\n"
          "  --                            End options before a filename starting with -\n",
          stdout);
#ifdef BASM_PUBLIC_ONLY
    fputs("  --target-profile public       Public build: 64-bit mode only\n", stdout);
#else
    fputs("  --target-profile public|beyond Select an explicit 64-bit target policy\n"
          "  --bootstrap ap-trampoline-v1   Exact pinned Beyond bootstrap source only\n",
          stdout);
#endif
    fputs("\nInspection:\n"
          "  --capabilities                Print JSON target capabilities\n"
          "  --list-instructions           Print registered instruction vocabulary\n"
          "  --list-forms                  Print modeled instruction forms\n"
          "  --explain                     Print assembly trace JSON (explicit profile)\n"
          "  --diagnostics-json            Print errors as JSON on stderr\n"
          "  --profile                     Print timing telemetry on stderr\n\n"
          "Integrity evidence:\n"
          "  --emit-attestation FILE        Write object/source integrity evidence\n"
          "  --emit-attestation-v4 FILE     Also bind consumed inputs (explicit profile)\n"
          "  --sign KEY                    Sign evidence using a 32-byte seed or hex key\n"
          "  --verify-attestation FILE      Verify evidence integrity\n"
          "  --verify-attestation-strict FILE  Require signed evidence\n"
          "  --trusted-key KEY             Pin the signer when verifying evidence\n"
          "  --emit-exec-proof              Include an optional execution-proof note\n"
          "  --sign-exec-proof KEY          Sign that note\n\n"
          "Batch and cache:\n"
          "  --batch JOBS.tsv               Rows: format<TAB>output<TAB>input\n"
          "  --jobs N                       Batch concurrency, 1..32 (default: 8)\n"
          "  --rel8-escrow DIR --rel8-key KEY  Use the bounded authenticated cache\n\n"
          "  -h, --help                    Show this help\n"
          "  --version                     Show the distribution version and build profile\n\n"
          "Singleton options cannot be repeated. Help/version accept only an optional\n"
          "target profile. NASM -g, -F and warning switches are compatibility no-ops;\n"
          "debug information is not emitted. Integrity evidence does not prove code\n"
          "semantics or signer identity without an external trust anchor. See\n"
          "SUPPORTED-SUBSET.md for the supported language and format boundary.\n",
          stdout);
    return fflush(stdout) != 0 || ferror(stdout) ? 1 : 0;
}

/* This scan only selects error formatting and starts the timing clock. Option
 * values and names following -- are data, even if they look like flags. Keep
 * the arity list aligned with the parser; no file is opened by either scan. */
static int cli_option_takes_value(const char *arg) {
    return !strcmp(arg,"--target-profile") || !strcmp(arg,"--bootstrap") ||
        !strcmp(arg,"--jobs") || !strcmp(arg,"--batch") ||
        !strcmp(arg,"-f") || !strcmp(arg,"-o") || !strcmp(arg,"-F") ||
        !strcmp(arg,"-I") || !strcmp(arg,"-D") ||
        !strcmp(arg,"--emit-attestation") || !strcmp(arg,"--emit-attestation-v4") ||
        !strcmp(arg,"--trusted-key") || !strcmp(arg,"--sign-exec-proof") ||
        !strcmp(arg,"--sign") || !strcmp(arg,"--verify-attestation") ||
        !strcmp(arg,"--verify-attestation-strict") ||
        !strcmp(arg,"--rel8-escrow") || !strcmp(arg,"--rel8-key");
}

static const char *cli_option_value(int argc,char **argv,int *index) {
    if(*index+1>=argc || !argv[*index+1][0])
        die2("option requires an argument",argv[*index]);
    (*index)++;
    return argv[*index];
}

static unsigned long long profile_now_ns(void) {
#ifdef BEAR_TIME_H
    struct bear_timespec ts;
    if (bear_clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
#endif
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

/* INV-C07: cap aggregate source scanning across all fixpoint passes. */
#define BASM_ASSEMBLY_SCAN_MAX (512ULL * 1024ULL * 1024ULL)
static void assembly_scan_charge(size_t bytes,unsigned long long *used) {
    if((unsigned long long)bytes>BASM_ASSEMBLY_SCAN_MAX-*used)
        die("assembly work budget exceeded");
    *used+=(unsigned long long)bytes;
}

/* INV-C11/INV-N22: each validation phase observes each path identity once.
 * Lazy file/parent identities avoid repeated stats of one output against every
 * dependency. The local records do not survive this call: checks after further
 * input discovery and immediately before publication still re-observe paths.
 * No path is opened for writing. Concurrent hostile directory replacement
 * remains outside the local publication contract. */
typedef struct {
    const char *path,*base;
    uint64_t file_dev,file_ino,parent_dev,parent_ino;
    int file_ready,file_exists,parent_ready,parent_exists;
} OutputPath;

static void output_path_init(OutputPath *entry,const char *path) {
    entry->path=path;
    const char *slash=strrchr(path,'/');
    entry->base=slash?slash+1:path;
    entry->file_ready=entry->parent_ready=0;
}
static int output_file_identity(OutputPath *entry) {
    if(!entry->file_ready){
        struct stat st;
        entry->file_exists=stat(entry->path,&st)==0;
        if(entry->file_exists){entry->file_dev=(uint64_t)st.st_dev;entry->file_ino=(uint64_t)st.st_ino;}
        entry->file_ready=1;
    }
    return entry->file_exists;
}
static int output_parent_identity(OutputPath *entry) {
    if(!entry->parent_ready){
        char parent[1050];
        size_t length=entry->base==entry->path?0:(size_t)(entry->base-entry->path-1);
        if(length>=sizeof(parent))die("publication path too long");
        if(entry->base==entry->path)strcpy(parent,".");
        else if(!length)strcpy(parent,"/");
        else {memcpy(parent,entry->path,length);parent[length]=0;}
        struct stat st;
        entry->parent_exists=stat(parent,&st)==0;
        if(entry->parent_exists){entry->parent_dev=(uint64_t)st.st_dev;entry->parent_ino=(uint64_t)st.st_ino;}
        entry->parent_ready=1;
    }
    return entry->parent_exists;
}
static int output_path_alias(OutputPath *a,OutputPath *b) {
    if(!strcmp(a->path,b->path))return 1;
    if(output_file_identity(a) && output_file_identity(b) &&
       a->file_dev==b->file_dev && a->file_ino==b->file_ino)return 1;
    if(strcmp(a->base,b->base))return 0;
    return output_parent_identity(a) && output_parent_identity(b) &&
        a->parent_dev==b->parent_dev && a->parent_ino==b->parent_ino;
}

static void output_paths_check(const char *out,const char *attest) {
    OutputPath object,proof;
    output_path_init(&object,out);
    if(attest){
        output_path_init(&proof,attest);
        if(output_path_alias(&object,&proof))die("object and attestation paths alias");
    }
    for(size_t i=0;i<(size_t)basm_dependency_count();i++){
        const BasmDependency *dep=basm_dependency_at(i);
        OutputPath input; output_path_init(&input,dep->path);
        if(output_path_alias(&object,&input) || (attest && output_path_alias(&proof,&input)))
            die2("publication would replace an input dependency",dep->path);
    }
}

static void output_secret_paths_check(const char *out,const char *attest,
                                      const char *sign_key,const char *cache_key) {
    const char *keys[3]={sign_key,g_exec_sign_key,cache_key};
    OutputPath object,proof;
    output_path_init(&object,out);
    if(attest)output_path_init(&proof,attest);
    for(int i=0;i<3;i++)if(keys[i]){
        OutputPath key; output_path_init(&key,keys[i]);
        if(output_path_alias(&object,&key) || (attest && output_path_alias(&proof,&key)))
            die("publication would replace a signing or cache key");
    }
}

int main(int argc,char **argv);

#define BASM_BATCH_JOB_MAX 4096
#define BASM_BATCH_MANIFEST_MAX ((size_t)8 * 1024 * 1024)
typedef struct {
    uint64_t dir_dev,dir_ino,file_dev,file_ino;
    const char *base;
    int exists;
} BatchPath;
typedef struct { char *fmt,*out,*in; BatchPath output,input; } BatchJob;

static BatchPath batch_path_identity(const char *path,int source) {
    BatchPath result; memset(&result,0,sizeof(result));
    const char *slash=strrchr(path,'/');
    result.base=slash?slash+1:path;
    if(!*result.base || !strcmp(result.base,".") || !strcmp(result.base,".."))
        die("invalid batch file path");
    char parent[1050]; size_t len=slash?(size_t)(slash-path):0;
    if(len>=sizeof(parent))die("batch path too long");
    if(slash){ if(len){memcpy(parent,path,len);parent[len]=0;}else strcpy(parent,"/"); }
    else strcpy(parent,".");
    struct stat st;
    if(stat(parent,&st)!=0 || !S_ISDIR(st.st_mode))die2("batch parent directory unavailable",parent);
    result.dir_dev=(uint64_t)st.st_dev; result.dir_ino=(uint64_t)st.st_ino;
    if(stat(path,&st)==0){
        if(!S_ISREG(st.st_mode))die("batch inputs and existing outputs must be regular files");
        result.exists=1; result.file_dev=(uint64_t)st.st_dev; result.file_ino=(uint64_t)st.st_ino;
    }else if(source || errno!=ENOENT)die2("batch file unavailable",path);
    return result;
}

static int batch_path_alias(const BatchPath *a,const BatchPath *b) {
    return (a->exists && b->exists && a->file_dev==b->file_dev && a->file_ino==b->file_ino) ||
        (a->dir_dev==b->dir_dev && a->dir_ino==b->dir_ino && !strcmp(a->base,b->base));
}

static int batch_manifest_row(char *line,char **fmt,char **out,char **in) {
    char *comment=line;
    while(char_in(*comment," \t"))comment++;
    if(!*comment || *comment=='#')return 0;
    char *p=line; while(*p==' ')p++;
    *fmt=p;
    char *tab=strchr(p,'\t'); if(!tab)return -1; *tab=0; *out=tab+1;
    tab=strchr(*out,'\t'); if(!tab)return -1; *tab=0; *in=tab+1;
    if(!**fmt || !**out || !**in || strchr(*in,'\t') ||
       (strcmp(*fmt,"elf64") && strcmp(*fmt,"bin")))return -1;
    return 1;
}

static int batch_wait_one(int *active,int *failed) {
    int status=0;
    while(waitpid(-1,&status,0)<0){
        if(errno==EINTR)continue;
        *failed=1; *active=0; return -1;
    }
    (*active)--;
    if(!WIFEXITED(status) || WEXITSTATUS(status)!=0)*failed=1;
    return 0;
}

static int run_batch(const char *self,const char *manifest,int concurrency) {
    FILE *f=basm_open_regular(manifest);
    if(!f){perror("batch manifest");return 1;}
    const BasmDependency *dependency=basm_snapshot_file(f,manifest,BASM_DEP_SOURCE);
    if(dependency->len>BASM_BATCH_MANIFEST_MAX)die("batch manifest byte budget exceeded");
    size_t bytes=dependency->len;
    char *text=malloc(bytes+1);
    BatchJob *jobs=calloc(BASM_BATCH_JOB_MAX,sizeof(*jobs));
    if(!text || !jobs)die("out of memory (batch manifest)");
    memcpy(text,dependency->data,bytes); text[bytes]=0;
    int declared=0;
    for(char *p=text;*p;){
        char *end=strchr(p,'\n');
        size_t length=end?(size_t)(end-p):strlen(p);
        if(length>2047)die("malformed batch manifest line");
        if(end)*end=0;
        if(length && p[length-1]=='\r')p[length-1]=0;
        char *fmt=NULL,*out=NULL,*in=NULL;
        int row=batch_manifest_row(p,&fmt,&out,&in);
        if(row<0)die("malformed batch manifest line");
        if(row){
            if(in[0]=='-')die("batch input beginning with - requires ./ prefix");
            if(declared>=BASM_BATCH_JOB_MAX)die("batch job budget exceeded");
            jobs[declared].fmt=fmt; jobs[declared].out=out; jobs[declared].in=in;
            declared++;
        }
        if(!end)break;
        p=end+1;
    }
    if(!declared)die("empty batch manifest");
    BatchPath manifest_path=batch_path_identity(manifest,1);
    for(int i=0;i<declared;i++){
        jobs[i].output=batch_path_identity(jobs[i].out,0);
        jobs[i].input=batch_path_identity(jobs[i].in,1);
    }
    /* INV-C21: one immutable manifest, complete validation before the first
     * fork, and no shared destination/input paths among independent jobs.
     * Pair checks use cached inode keys: no quadratic filesystem queries. */
    for(int i=0;i<declared;i++){
        if(batch_path_alias(&jobs[i].output,&manifest_path))die("batch output aliases manifest");
        for(int j=0;j<declared;j++){
            if(batch_path_alias(&jobs[i].output,&jobs[j].input))die("batch output aliases an input");
            if(j<i && batch_path_alias(&jobs[i].output,&jobs[j].output))die("duplicate batch output");
        }
    }
    int active=0,launched=0,failed=0;
    for(int i=0;i<declared;i++){
        int wait_failed=0;
        while(active>=concurrency){
            if(batch_wait_one(&active,&failed)!=0){wait_failed=1;break;}
        }
        if(wait_failed)break;
        long pid=(long)fork();
        if(pid<0){perror("fork");failed=1;break;}
        if(pid==0){
            char *child_argv[9]; int child_argc=0;
            child_argv[child_argc++]=(char*)self;
            if(g_target_profile){
                child_argv[child_argc++]="--target-profile";
                child_argv[child_argc++]=(char*)target_profile_name();
            }
            child_argv[child_argc++]="-f"; child_argv[child_argc++]=jobs[i].fmt;
            child_argv[child_argc++]="-o"; child_argv[child_argc++]=jobs[i].out;
            child_argv[child_argc++]=jobs[i].in; child_argv[child_argc]=NULL;
            basm_dependencies_reset(); /* child's source admission starts fresh */
            _exit(main(child_argc,child_argv));
        }
        active++; launched++;
    }
    while(active>0)if(batch_wait_one(&active,&failed)!=0)break;
    if(!failed)dprintf(2,"basm: batch complete jobs=%d concurrency=%d\n",launched,concurrency);
    free(jobs); free(text); basm_dependencies_reset();
    return failed;
}

 int main(int argc, char **argv) {
    int profile=0;
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--"))break;
        if(!strcmp(argv[i],"--diagnostics-json"))g_json_diagnostics=1;
        if(!strcmp(argv[i],"--profile"))profile=1;
        if(cli_option_takes_value(argv[i]) && i+1<argc)i++;
    }
    unsigned long long total_started=profile?profile_now_ns():0;
    profile=0; /* A lookahead match may be an option value; only CLI parsing enables reporting. */
    const char *out="a.out.o"; const char *in=NULL; const char *fmt="elf64";
    const char *batch=NULL;
    int jobs=8,jobs_seen=0;
    int explain_requested=0, list_forms=0;
    int target_seen=0, capabilities=0, bootstrap_requested=0, output_seen=0, format_seen=0;
    int options_ended=0, help_requested=0, version_requested=0, diagnostics_seen=0;
    int debug_seen=0, debug_format_seen=0, warning_seen=0;
    const char *attest = NULL;
    const char *sign_key = NULL;
    const char *trusted_key = NULL;
    const char *verify_attest = NULL;
    const char *rel8_dir = NULL;
    const char *rel8_key = NULL;
    int verify_attest_strict = 0;
    unsigned long long source_ns=0, preprocess_ns=0, layout_ns=0, emit_ns=0, write_ns=0, tick=0;
    unsigned long long cache_ns=0,attestation_ns=0,explain_ns=0,cleanup_ns=0;
    int layout_passes=0, final_pass=0;
    unsigned long long assembly_scan_bytes=0;
    for (int i=1;i<argc;i++){
        if(options_ended){
            if(in)die2("multiple input files",argv[i]);
            in=argv[i];
        }
        else if(!strcmp(argv[i],"--")){ options_ended=1; }
        else if(!strcmp(argv[i],"--help") || !strcmp(argv[i],"-h")){
            if(help_requested++)die("duplicate help request");
        }
        else if(!strcmp(argv[i],"--version")){
            if(version_requested++)die("duplicate --version");
        }
        else if(!strcmp(argv[i],"--target-profile")){
            if(target_seen++)die("duplicate --target-profile");
            const char *value=cli_option_value(argc,argv,&i);
            if(!strcmp(value,"public"))g_target_profile=2;
#ifndef BASM_PUBLIC_ONLY
            else if(!strcmp(value,"beyond"))g_target_profile=1;
#endif
            else die2("unavailable target profile",value);
        }
        else if(!strcmp(argv[i],"--capabilities")){
            if(capabilities++)die("duplicate --capabilities");
        }
        else if(!strcmp(argv[i],"--explain")){
            if(explain_requested++)die("duplicate --explain"); g_explain=1;
        }
        else if(!strcmp(argv[i],"--diagnostics-json")){
            if(diagnostics_seen++)die("duplicate --diagnostics-json"); g_json_diagnostics=1;
        }
        else if(!strcmp(argv[i],"--list-forms")){
            if(list_forms)die("duplicate instruction inventory request"); list_forms=1;
        }
        else if(!strcmp(argv[i],"--list-instructions")){
            if(list_forms)die("duplicate instruction inventory request"); list_forms=2;
        }
        else if(!strcmp(argv[i],"--bootstrap")){
            if(bootstrap_requested++)die("duplicate --bootstrap");
            if(strcmp(cli_option_value(argc,argv,&i),"ap-trampoline-v1"))die("unknown bootstrap exception");
        }
        else if(!strcmp(argv[i],"--jobs")){
            if(jobs_seen++)die("duplicate --jobs");
            if(++i>=argc || !argv[i][0])die("--jobs requires 1..32");
            unsigned int value=0;
            for(const char *p=argv[i];*p;p++){
                if(*p<'0' || *p>'9')die("--jobs requires 1..32");
                value=value*10+(unsigned int)(*p-'0');
                if(value>32)die("--jobs requires 1..32");
            }
            if(!value)die("--jobs requires 1..32");
            jobs=(int)value;
        }
        else if(!strcmp(argv[i],"--batch")){
            if(batch)die("duplicate --batch");
            batch=cli_option_value(argc,argv,&i);
        }
        else if(!strcmp(argv[i],"-f")){
            if(format_seen++)die("duplicate -f"); fmt=cli_option_value(argc,argv,&i);
            if(strcmp(fmt,"elf64")&&strcmp(fmt,"bin"))die2("only elf64,bin",fmt); }
        else if(!strcmp(argv[i],"-o")){
            if(output_seen++)die("duplicate -o"); out=cli_option_value(argc,argv,&i);
        }
        else if(argv[i][0]=='-'&&argv[i][1]=='g'){
            if(debug_seen++)die("duplicate debug option");
        }
        else if(!strcmp(argv[i],"-F")){
            if(debug_format_seen++)die("duplicate -F");
            (void)cli_option_value(argc,argv,&i);
        }
        else if(!strcmp(argv[i],"--emit-attestation") || !strcmp(argv[i],"--emit-attestation-v4")){
            if(attest)die("duplicate attestation output");
            if(!strcmp(argv[i],"--emit-attestation-v4"))g_attestation_v4=1;
            attest=cli_option_value(argc,argv,&i);
        }
        else if(!strcmp(argv[i],"--trusted-key")){
            if(trusted_key)die("duplicate --trusted-key");
            trusted_key=cli_option_value(argc,argv,&i);
        }
        else if(!strcmp(argv[i],"--emit-exec-proof")){
            if(g_exec_proof++)die("duplicate --emit-exec-proof");
        }
        else if(!strcmp(argv[i],"--sign-exec-proof")){
            if(g_exec_sign_key)die("duplicate --sign-exec-proof");
            g_exec_sign_key=cli_option_value(argc,argv,&i);
        }
        else if(!strcmp(argv[i],"--sign")){
            if(sign_key)die("duplicate --sign"); sign_key=cli_option_value(argc,argv,&i);
        }
        else if(!strcmp(argv[i],"--verify-attestation") || !strcmp(argv[i],"--verify-attestation-strict")){
            if(verify_attest)die("duplicate attestation verification request");
            verify_attest_strict=!strcmp(argv[i],"--verify-attestation-strict");
            verify_attest=cli_option_value(argc,argv,&i);
        }
        else if(!strcmp(argv[i],"--rel8-escrow")){
            if(rel8_dir)die("duplicate --rel8-escrow"); rel8_dir=cli_option_value(argc,argv,&i);
        }
        else if(!strcmp(argv[i],"--rel8-key")){
            if(rel8_key)die("duplicate --rel8-key"); rel8_key=cli_option_value(argc,argv,&i);
        }
        else if(!strcmp(argv[i],"--profile")){
            if(profile++)die("duplicate --profile");
        }
        else if(argv[i][0]=='-'&&argv[i][1]=='I'){
            /* -Ipath or -I path */
            if(g_nincpaths>=INCPATH_MAX) die("too many include paths"); /* INV-394 */
            if(argv[i][2]) g_incpaths[g_nincpaths++]=argv[i]+2;
            else g_incpaths[g_nincpaths++]=cli_option_value(argc,argv,&i);
        }
        else if(argv[i][0]=='-'&&argv[i][1]=='D'){
            const char *def=argv[i]+2; if(!*def)def=cli_option_value(argc,argv,&i);
            const char *eq=strchr(def,'='); char name[NAME_MAX]; const char *value="1";
            size_t n=eq?(size_t)(eq-def):strlen(def); if(n==0||n>=sizeof(name))die("invalid -D name");
            memcpy(name,def,n); name[n]=0; if(eq)value=eq+1;
            if(pp_ndef>=PP_MAXDEF)die("too many -D definitions");
            basm_name_copy(pp_defs[pp_ndef].name,name);
            pp_defs[pp_ndef].value=pp_copy_text(value,strlen(value)); pp_defs[pp_ndef].nparam=-1;
            ht_insert(pp_def_ht,PPDEF_HT_CAP,str_hash(name,n),(uint8_t)n,pp_ndef++);
        }
        else if(!strcmp(argv[i],"-Wall") || !strncmp(argv[i],"-w",2)) { warning_seen=1; /* accepted NASM warning controls */ }
        else if(argv[i][0]=='-') die2("unknown option",argv[i]);
        else { if(in)die2("multiple input files",argv[i]); in=argv[i]; }
    }
    if(help_requested || version_requested){
        if((help_requested && version_requested) || in || batch || capabilities || list_forms ||
           bootstrap_requested || jobs_seen || attest || sign_key || trusted_key || verify_attest ||
           rel8_dir || rel8_key || pp_ndef || g_nincpaths || profile || output_seen || format_seen ||
           explain_requested || diagnostics_seen || g_exec_proof || g_exec_sign_key ||
           debug_seen || debug_format_seen || warning_seen)
            die("help/version take only an optional target profile");
        return help_requested?cli_help():cli_version();
    }
    if(jobs_seen && !batch)die("--jobs requires --batch");
    if(bootstrap_requested && (g_target_profile!=1 || pp_ndef || g_nincpaths || batch || capabilities || list_forms))
        die("bootstrap requires beyond source with no -D, -I, batch or capabilities");
    if(capabilities || list_forms){
        if(in || batch || attest || sign_key || trusted_key || verify_attest || rel8_dir || rel8_key ||
           pp_ndef || g_nincpaths || profile || output_seen || format_seen || explain_requested ||
           g_exec_proof || g_exec_sign_key ||
           (capabilities && list_forms))die("inventory takes only target-profile");
        if(list_forms==2){
            insn_ht_init(); int count=0;
            printf("{\"schema\":\"basm-instructions-v1\",\"profile\":\"%s\",\"scope\":\"registered vocabulary, not complete operand coverage\",\"instructions\":[",target_profile_name());
            for(int i=0;i<INSN_HT_CAP;i++){
                const InsnHTEntry *entry=&g_insn_ht[i];
                if(!entry->hash)continue;
                if(g_target_profile && (entry->kind==INSN_popa || entry->kind==INSN_popad ||
                   entry->kind==INSN_pusha || entry->kind==INSN_pushad))continue;
                int forms=0;
                for(int j=0;j<INTENT_FORM_COUNT;j++)if(!strcmp(entry->name,g_intent_forms[j].mnemonic))forms++;
                if(count++)fputc(',',stdout);
                printf("{\"mnemonic\":\"%s\",\"modeled_forms\":%d}",entry->name,forms);
            }
            printf("],\"count\":%d}\n",count); return fflush(stdout)!=0 || ferror(stdout)?1:0;
        }
        if(list_forms==1){
            printf("{\"schema\":\"basm-forms-v1\",\"mode\":64,\"verification\":\"unimplemented\",\"forms\":[");
            for(int i=0;i<INTENT_FORM_COUNT;i++){
                const IntentForm *f=&g_intent_forms[i];
                if(i)fputc(',',stdout);
                printf("{\"id\":\"%s\",\"mnemonic\":\"%s\",\"operands\":\"%s\",\"width\":%d,\"features\":\"%s\"}",
                       f->id,f->mnemonic,f->operands,f->width,f->features);
            }
            printf("]}\n"); return fflush(stdout)!=0 || ferror(stdout)?1:0;
        }
#ifdef BASM_PUBLIC_ONLY
        const char *build="public-only";
#else
        const char *build="bootstrap-capable";
#endif
        printf("{\"schema\":\"basm-capabilities-v1\",\"policy\":\"%s\",\"target_profile\":\"%s\",\"build\":\"%s\",\"modes\":\"%s\",\"formats\":[\"elf64\",\"bin\"],\"modeled_forms\":%d,\"instruction_model\":\"partial\",\"semantic_verification\":\"unimplemented\"}\n",
               target_policy_id(),target_profile_name(),build,g_target_profile ? "64" : "16,32,64",INTENT_FORM_COUNT);
        return fflush(stdout)!=0 || ferror(stdout)?1:0;
    }
    if(batch){
        if(in || attest || sign_key || trusted_key || verify_attest || rel8_dir || rel8_key || pp_ndef ||
           g_nincpaths || profile || output_seen || format_seen || explain_requested || g_json_diagnostics ||
           g_exec_proof || g_exec_sign_key)
            die("batch takes only target-profile");
        return run_batch(argv[0],batch,jobs);
    }
    if (verify_attest) {
        if(target_seen || bootstrap_requested || in || attest || sign_key || rel8_dir ||
           rel8_key || pp_ndef || g_nincpaths || profile || output_seen || format_seen ||
           g_exec_proof || g_exec_sign_key)
            die("verification takes only the attestation path");
        if(explain_requested)die("verification does not assemble an explanation");
        return verify_basm_attestation(verify_attest, verify_attest_strict, trusted_key);
    }
    if(trusted_key)die("--trusted-key requires attestation verification");
    if(g_attestation_v4 && !g_target_profile)die("attestation v4 requires an explicit target profile");
    if (sign_key && !attest) { dprintf(2, "basm: --sign requires --emit-attestation\n"); return 1; } /* INV-541 */
    output_secret_paths_check(out,attest,sign_key,rel8_key);
    if(sign_key && basm_attestation_load_signer(sign_key)!=0)die("cannot load signing key");
    if (g_exec_sign_key && !g_exec_proof) { dprintf(2, "basm: --sign-exec-proof requires --emit-exec-proof\n"); return 1; } /* W1.2 */
    /* W1.2: optional exec-proof key. Loaded before assembly so the writer
     * can sign the proof note; failures refuse before any output exists. */
    if (g_exec_sign_key && load_exec_proof_key(g_exec_sign_key)) return 1;
    if (!!rel8_dir != !!rel8_key) { dprintf(2,"basm: rel8 escrow requires both directory and key\n"); return 1; }
    if(!in){ if(g_json_diagnostics)die("missing source input"); dprintf(2,"usage: basm -f elf64 -o out.o [-Ipath] [--emit-attestation FILE] [--sign KEY] in.basm\n       basm --verify-attestation[-strict] FILE.basmproof\n"); return 1; }
    if(g_json_diagnostics)g_explain=1; /* collect origins without printing a trace */
    if(g_explain && !g_target_profile)die("intent explanation requires an explicit target profile");
    g_fmt = fmt;  /* set global format for cur_off() org handling */
    g_file=in;
    g_srcname=in;   /* STT_FILE symbol name (NASM parity) */
    /* record the source directory for incbin relative resolution */
    { const char *slash=strrchr(in,'/');
      if(slash){ size_t n=(size_t)(slash-in); if(n>=sizeof(g_srcdir))die("source directory path too long");
                 memcpy(g_srcdir,in,n); g_srcdir[n]=0; } }
    if(profile) tick=profile_now_ns();
    FILE*f=basm_open_regular(in); if(!f){if(g_json_diagnostics)die2("cannot open input",in);perror("fopen");return 1;}
    const BasmDependency *root_dependency=basm_snapshot_file(f,in,BASM_DEP_SOURCE);
    long sz=(long)root_dependency->len;
    char *src=malloc((size_t)sz+1);
    if(!src)die("out of memory (source workspace)");
    memcpy(src,root_dependency->data,(size_t)sz); src[sz]=0;
    if(attest || g_exec_proof)basm_attestation_capture_source(src,(size_t)sz);
    if(bootstrap_requested){
#ifdef BASM_PUBLIC_ONLY
        die("bootstrap unavailable in public build");
#else
        /* INV-589: pin the loaded source, not its pathname. This unit has no
         * includes/incbin; -D/-I are refused above, before authorization. */
        basm_sha_ctx c; uint8_t digest[32]; char hex[65];
        basm_sha_init(&c); basm_sha_update(&c,src,(size_t)sz); basm_sha_final(&c,digest);
        basm_hex32(digest,hex);
        if(strcmp(hex,"f0f6ba9d486c1ee1620ccbd6bfaff9f95584a90cb60a3df35fc98aed473cf02e"))
            die("bootstrap source identity mismatch");
        g_bootstrap=1;
#endif
    }
    if(profile){ unsigned long long now=profile_now_ns(); source_ns=now-tick; tick=now; }

    /* NASM-subset preprocessor pass: expands %define/%macro, resolves
     * %if/%endif, and consumes [BITS 64]. The assembler proper then runs on
     * the expanded source, unchanged. */
    src = preprocess(src, sz);
    if(g_attestation_v4)basm_attestation_capture_expanded(src);
    size_t expanded_bytes=strlen(src);
    output_paths_check(out,attest);
    if(profile){ unsigned long long now=profile_now_ns(); preprocess_ns=now-tick; tick=now; }

    int rel8_hit=0;
    char rel8_id[65]={0}; uint8_t rel8_key_id[32]={0},rel8_secret[32]={0};
    if(rel8_dir){
        if(rel8_prepare(rel8_dir,rel8_key,src,in,fmt,rel8_id,rel8_key_id,rel8_secret)!=0){
            dprintf(2,"basm: rel8 escrow preparation failed\n"); free(src); return 1;
        }
        /* Trace needs current expanded origins and instruction spans. Reassemble
         * rather than returning a cache hit without its explanation. INV-596. */
        output_paths_check(out,attest);
        if(!g_explain)rel8_hit=rel8_restore(rel8_dir,rel8_id,rel8_key_id,rel8_secret,out);
        if(rel8_hit<0){ dprintf(2,"basm: rel8 escrow receipt rejected\n"); free(src); return 1; }
        if(rel8_hit) dprintf(2,"basm: rel8 escrow hit %s\n",rel8_id);
    }
    if(profile){
        unsigned long long now=profile_now_ns();
        cache_ns=rel8_dir?now-tick:0; tick=now;
    }

    if(!rel8_hit){
        /* Pre-scan EQU definitions so simple constants (e.g. banner_len) used
         * as immediates in .text are known during the first assembly pass. */
        assembly_scan_charge(expanded_bytes,&assembly_scan_bytes);
        prescan_equ(src);

    /* Branch sizing fixpoint: NASM picks the shortest stable encoding. We
     * iterate to a fixed point — each iteration recomputes every branch size
     * optimistically (rel8 if it fits with CURRENT layout), and we repeat until
     * the size assignment stops changing. This converges to the minimal stable
     * encoding (same as NASM), unlike a monotonic-grow-only scheme. */
    /* INV-BASM-BRANCH-GROWTH-001: reset decisions, retaining bounded capacity. */
    if (g_branch_capacity)
        memset(g_branch_long, 0, g_branch_capacity * sizeof(*g_branch_long));
    memset(&g_layout_snapshot, 0, sizeof(g_layout_snapshot));
    g_sizing = 1; g_pass = 1;
    int layout_stable = 0;
    for (int iter=0; iter<128; iter++) {
        layout_passes++;
        assembly_scan_charge(expanded_bytes,&assembly_scan_bytes);
        assemble_pass(src);                 /* records branch positions + target syms */
        int branches_changed = branch_decide(g_branch_ord);
        if(iter==0 && g_branch_ord==0 && !g_deferred_content &&
           !g_fwd_unresolved && !g_layout_contextual_seen){
            layout_stable=1; /* INV-545: first pass is final without layout dependencies. */
            break;
        }
        int layout_changed = layout_changed_and_capture(); /* INV-545 */
        if (!branches_changed && !layout_changed) {
            layout_stable = 1;
            break;
        }
    }
        if (!layout_stable) die("layout did not converge");
        if(profile){ unsigned long long now=profile_now_ns(); layout_ns=now-tick; tick=now; }
        if (g_branch_ord == 0 && !g_deferred_content && !g_fwd_unresolved) {
            /* The stable sizing pass already holds final bytes. */
            g_sizing = 0; g_pass = 2; /* INV-545 */
        } else {
            g_sizing = 0; g_pass = 2;
            final_pass=1;
            assembly_scan_charge(expanded_bytes,&assembly_scan_bytes);
            assemble_pass(src);
        }
        if(profile){ unsigned long long now=profile_now_ns(); emit_ns=now-tick; tick=now; }
        /* INV-579: atomic publish. A crash, signal (SIGXFSZ) or ENOSPC
         * mid-write must never leave a truncated object at the final
         * path: make would treat it as fresh and link garbage (stale-
         * artifact poisoning). The writer targets a sibling temp; only a
         * fully-written, successfully closed object is renamed over the target.
         * The cleanup funnel is armed only after exclusive creation. Signals
         * may strand an owned temporary; no handler rolls back a published file. */
        {
            output_paths_check(out,attest);
            char tmp_out[1050];
            FILE *object=out_tmp_open(out,tmp_out,sizeof(tmp_out));
            if(!object)die("cannot create output temporary");
            g_out_tmp_len=snprintf(g_out_tmp,sizeof(g_out_tmp),"%s",tmp_out);
            if(g_out_tmp_len<=0||g_out_tmp_len>=(int)sizeof(g_out_tmp))die("output path too long");
            if (!strcmp(fmt,"bin")) write_bin(object); else write_elf(object);
            if(attest && basm_attestation_capture_output(object)!=0){
                fclose(object); die("cannot capture completed object digest");
            }
            /* Cache evidence comes from our still-open completed object, before
             * exposing the shared final name. A later rename failure can leave
             * a valid cache entry, never a receipt for another job's output. */
            if(rel8_dir && rel8_publish(rel8_dir,rel8_id,rel8_key_id,rel8_secret,object)!=0){
                fclose(object); die("rel8 escrow publication failed");
            }
            if(fclose(object)!=0)die("write error");
            if(rename(tmp_out,out)!=0)die("cannot publish output");
            g_out_tmp[0]=0; g_out_tmp_len=0;
        }
    }
    if(profile){
        unsigned long long now=profile_now_ns();
        write_ns=rel8_hit?0:now-tick; tick=now;
    }

    /* INV-C11: evidence is completed and signed in an owned sibling temporary.
     * Publication of a pair for concurrent consumers uses publish_generation.py. */
    if(attest && publish_basm_attestation(attest,in,out,fmt)!=0)return 1;
    if(profile){
        unsigned long long now=profile_now_ns();
        attestation_ns=attest?now-tick:0; tick=now;
    }

    if(explain_requested){
        intent_trace_write(stdout);
        if(fflush(stdout)!=0 || ferror(stdout))die("cannot complete intent explanation");
    }
    if(profile){
        unsigned long long now=profile_now_ns();
        explain_ns=explain_requested?now-tick:0; tick=now;
    }
    int output_payload_bytes=g_textlen+g_datalen+g_rodatalen;
    intent_trace_free();
    free(src);
    basm_secret_clear(rel8_secret,sizeof(rel8_secret));
    basm_secret_clear(g_attestation_seed,sizeof(g_attestation_seed));
    basm_secret_clear(g_exec_proof_seed,sizeof(g_exec_proof_seed));
    file_spans_reset();
    basm_dependencies_reset();
    arena_reset();
    free(g_text); free(g_data); free(g_rodata);
    for(int i=0;i<CUSTOM_MAX;i++) free(g_custom_buf[i]);
    if(profile){
        unsigned long long now=profile_now_ns(); cleanup_ns=now-tick;
        struct stat output_stat;
        unsigned long long file_bytes=0;
        if(stat(out,&output_stat)==0 && output_stat.st_size>=0)
            file_bytes=(unsigned long long)output_stat.st_size;
        unsigned long long total_ns=profile_now_ns()-total_started;
        /* INV-C14: successful-job timing includes proof publication, flushed
         * explanation and cleanup. The external benchmark measures startup and
         * process exit too. Cache lookup/restore has its own phase; cache entry
         * publication and object hashing remain part of write_ns. */
        dprintf(2,"BASM_PROFILE source_ns=%llu preprocess_ns=%llu layout_ns=%llu emit_ns=%llu write_ns=%llu layout_passes=%d final_pass=%d source_bytes=%ld output_bytes=%d cache_hit=%d total_ns=%llu cache_ns=%llu attestation_ns=%llu explain_ns=%llu cleanup_ns=%llu expanded_bytes=%llu scan_bytes=%llu file_bytes=%llu hash_tool_calls=%llu hash_tool_reuses=%llu hash_dependency_calls=%llu hash_dependency_reuses=%llu\n",
                source_ns,preprocess_ns,layout_ns,emit_ns,write_ns,layout_passes,final_pass,sz,
                output_payload_bytes,rel8_hit,total_ns,cache_ns,attestation_ns,explain_ns,cleanup_ns,
                (unsigned long long)expanded_bytes,assembly_scan_bytes,file_bytes,
                (unsigned long long)g_hash_tool_calls,(unsigned long long)g_hash_tool_reuses,
                (unsigned long long)g_hash_dependency_calls,(unsigned long long)g_hash_dependency_reuses);
    }
    return 0;
}
