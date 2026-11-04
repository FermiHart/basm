/* ═════════════════════════════════════════════════════════════════════════
 * ADR-0023 Phase 2 — basm self-attestation
 *
 * Bind source .asm SHA → output .o SHA in a deterministic record. Composes
 * with bear-ld's .ldproof to form a verifiable chain from C source (via
 * .bearproof) to ASM source (via .basmproof) to ELF (via .ldproof).
 *
 * Inline SHA-256 (FIPS 180-4) — same primitive used by bear-ld; ~70 LoC.
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 * ═════════════════════════════════════════════════════════════════════════ */
/* SHA-256 (FIPS 180-4) with runtime SHA-NI dispatch.
 * Centralised in sha256_ni.h and imported here with the basm_ namespace. */
#include "sign.h"
#define SHA256NI_CTX_TYPE basm_sha_ctx
#define SHA256NI_PREFIX   basm_sha_
#include "sha256_ni.h"
#define BASM_ATTEST_ARTIFACT_MAX ((uint64_t)1 << 30)
/* Reject static FIFOs/devices before fopen and confirm the opened regular file.
 * A hostile directory/inode replacement before fopen is outside this contract;
 * this preflight is deliberately not described as a race-proof open primitive. */
static FILE *basm_attest_open_regular(const char *path,uint64_t limit,uint64_t *size) {
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
static int basm_sha_file_limit(const char *path,uint64_t limit,uint8_t out[32]) {
    uint64_t remaining=0;FILE *f=basm_attest_open_regular(path,limit,&remaining);
    memset(out,0,32);if(!f)return -1;
    basm_sha_ctx c;basm_sha_init(&c);uint8_t b[65536];int ok=1;
    while(remaining){
        size_t want=remaining>sizeof(b)?sizeof(b):(size_t)remaining;
        size_t n=fread(b,1,want,f);if(n!=want){ok=0;break;}
        basm_sha_update(&c,b,n);remaining-=n;
    }
    if(ok && fgetc(f)!=EOF)ok=0;
    if(ferror(f))ok=0;if(fclose(f)!=0)ok=0;
    if(!ok)return -1;basm_sha_final(&c,out);return 0;
}
static int basm_sha_file(const char *path,uint8_t out[32]) {
    return basm_sha_file_limit(path,BASM_ATTEST_ARTIFACT_MAX,out);
}
static void basm_hex32(const uint8_t in[32], char out[65]) {
    static const char H[]="0123456789abcdef";
    for (int i=0;i<32;i++){out[i*2]=H[in[i]>>4]; out[i*2+1]=H[in[i]&15];}
    out[64]=0;
}

static const char *basm_self_exe_path(void);
static const char *target_profile_name(void);
static const char *target_policy_id(void);
static int basm_proof_value(const char *body,const char *key,char *out,size_t outsz);
static char *basm_read_text_file(const char *path,long *out_len);

/* W08/W10/W11: capture bytes at the point of consumption. A pathname is
 * provenance metadata, not a second chance to choose what was assembled. */
static int g_attestation_v4;
static int g_attestation_source_ready,g_attestation_expanded_ready,g_attestation_output_ready;
static int g_attestation_signer_ready;
static uint8_t g_attestation_source[32],g_attestation_expanded[32],g_attestation_output[32];
static uint8_t g_attestation_configuration[32],g_attestation_seed[32];
static uint8_t g_attestation_dep_hash[4096][32],g_attestation_dep_ready[4096];
/* W19: only the current job may reuse a tool digest. No filename, mtime or
 * authenticated metadata receipt substitutes for reading the executable. */
static int g_attestation_tool_state;
static uint8_t g_attestation_tool_hash[32];
static uint64_t g_hash_tool_calls,g_hash_tool_reuses;
static uint64_t g_hash_dependency_calls,g_hash_dependency_reuses;

static int basm_tool_digest(uint8_t out[32]) {
    if(g_attestation_tool_state==0){
        const char *path=basm_self_exe_path();
        g_hash_tool_calls++;
        g_attestation_tool_state=path && basm_sha_file(path,g_attestation_tool_hash)==0?1:-1;
    }else if(g_attestation_tool_state>0)g_hash_tool_reuses++;
    if(g_attestation_tool_state<0){memset(out,0,32);return -1;}
    memcpy(out,g_attestation_tool_hash,32);return 0;
}

extern void ed25519_keypair_from_seed(const uint8_t seed[32],uint8_t pub[32],uint8_t secret[64]);

static void basm_secret_clear(void *p,size_t n) {
    volatile uint8_t *v=(volatile uint8_t*)p;
    while(n--)*v++=0;
}
static void basm_sha_u64(basm_sha_ctx *c,uint64_t value) {
    uint8_t b[8];for(int i=0;i<8;i++)b[i]=(uint8_t)(value>>(8*i));
    basm_sha_update(c,b,sizeof(b));
}
static void basm_exec_identity(uint8_t *mode,uint8_t pub[32]) {
    memset(pub,0,32);*mode=(uint8_t)(g_exec_proof?(g_exec_proof_signed?2:1):0);
    if(*mode==2){
        uint8_t sk[64];ed25519_keypair_from_seed(g_exec_proof_seed,pub,sk);basm_secret_clear(sk,sizeof(sk));
    }
}
static int basm_attestation_load_signer(const char *path) {
    g_attestation_signer_ready=0;basm_secret_clear(g_attestation_seed,sizeof(g_attestation_seed));
    if(sign_load_seed(path,g_attestation_seed)!=0)return -1;
    g_attestation_signer_ready=1;return 0;
}
static void basm_attestation_capture_source(const char *src,size_t len) {
    g_attestation_tool_state=0;g_hash_tool_calls=g_hash_tool_reuses=0;
    g_hash_dependency_calls=g_hash_dependency_reuses=0;
    memset(g_attestation_dep_ready,0,sizeof(g_attestation_dep_ready));
    basm_sha_ctx c;basm_sha_init(&c);basm_sha_update(&c,src,len);basm_sha_final(&c,g_attestation_source);
    g_attestation_source_ready=1;g_attestation_output_ready=0;g_attestation_expanded_ready=0;
    /* W20: the parser workspace is copied from dependency zero. Reuse this
     * digest only after checking that the frozen snapshot has identical bytes;
     * a pathname/length match alone never grants reuse. */
    if(basm_dependency_count()){
        const BasmDependency *root=basm_dependency_at(0);
        if(root->kind==BASM_DEP_SOURCE && root->len==len && !memcmp(root->data,src,len)){
            memcpy(g_attestation_dep_hash[0],g_attestation_source,32);
            g_attestation_dep_ready[0]=1;g_hash_dependency_calls++;
        }
    }
    basm_sha_init(&c);basm_sha_update(&c,"basm-configuration-v1",sizeof("basm-configuration-v1"));
    const char *policy=target_policy_id(),*profile=target_profile_name();
    basm_sha_update(&c,policy,strlen(policy)+1);basm_sha_update(&c,profile,strlen(profile)+1);
    basm_sha_update(&c,g_fmt,strlen(g_fmt)+1);
    uint8_t mode,pub[32];basm_exec_identity(&mode,pub);basm_sha_update(&c,&mode,1);basm_sha_update(&c,pub,32);
    basm_sha_u64(&c,(uint64_t)g_nincpaths);
    for(int i=0;i<g_nincpaths;i++)basm_sha_update(&c,g_incpaths[i],strlen(g_incpaths[i])+1);
    basm_sha_u64(&c,(uint64_t)pp_ndef);
    for(int i=0;i<pp_ndef;i++){
        basm_sha_update(&c,pp_defs[i].name,strlen(pp_defs[i].name)+1);
        basm_sha_update(&c,pp_defs[i].value,strlen(pp_defs[i].value)+1);
    }
    basm_sha_final(&c,g_attestation_configuration);
}
static void basm_attestation_capture_expanded(const char *src) {
    basm_sha_ctx c;basm_sha_init(&c);basm_sha_update(&c,src,strlen(src));
    basm_sha_final(&c,g_attestation_expanded);g_attestation_expanded_ready=1;
}
static int basm_attestation_capture_output(FILE *f) {
    if(fseek(f,0,SEEK_SET)!=0)return -1;
    int fd=fileno(f);if(fd<0)return -1;
    struct stat st;if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || st.st_size<0 ||
                     (uint64_t)st.st_size>BASM_ATTEST_ARTIFACT_MAX)return -1;
    basm_sha_ctx c;basm_sha_init(&c);uint8_t buf[65536];
    uint64_t total=0;
    for(;;){
        long n;do{n=(long)read(fd,buf,sizeof(buf));}while(n<0 && errno==EINTR);
        if(n<0)return -1;if(!n)break;
        if((uint64_t)n>BASM_ATTEST_ARTIFACT_MAX-total)return -1;
        total+=(uint64_t)n;basm_sha_update(&c,buf,(size_t)n);
    }
    basm_sha_final(&c,g_attestation_output);g_attestation_output_ready=1;return 0;
}
static int basm_dependency_digest(size_t index,uint8_t out[32]) {
    if(index>=4096 || index>=basm_dependency_count())return -1;
    const BasmDependency *d=basm_dependency_at(index);
    if(!d)return -1;
    if(!g_attestation_dep_ready[index]){
        basm_sha_ctx c;basm_sha_init(&c);basm_sha_update(&c,d->data,d->len);
        basm_sha_final(&c,g_attestation_dep_hash[index]);g_attestation_dep_ready[index]=1;
        g_hash_dependency_calls++;
    }else g_hash_dependency_reuses++;
    memcpy(out,g_attestation_dep_hash[index],32);return 0;
}
static int basm_dependency_digest_for(const BasmDependency *dep,uint8_t out[32]) {
    /* Registry entries may move during growth. Compare only the pointer just
     * returned by snapshot_open, without retaining it across registry writes. */
    size_t count=basm_dependency_count();
    for(size_t i=0;i<count;i++)if(basm_dependency_at(i)==dep)return basm_dependency_digest(i,out);
    return -1;
}
static int basm_dependency_root(uint8_t out[32]) {
    size_t n=basm_dependency_count();if(!n || n>4096)return -1;
    basm_sha_ctx c;basm_sha_init(&c);
    basm_sha_update(&c,"basm-input-closure-v1",sizeof("basm-input-closure-v1"));basm_sha_u64(&c,(uint64_t)n);
    for(size_t i=0;i<n;i++){
        const BasmDependency *d=basm_dependency_at(i);uint8_t digest[32];
        if(!d || !d->path || strlen(d->path)>1023 || d->kind<1 || d->kind>3 ||
           basm_dependency_digest(i,digest)!=0)return -1;
        uint8_t kind=(uint8_t)d->kind;basm_sha_update(&c,&kind,1);basm_sha_u64(&c,(uint64_t)d->len);
        basm_sha_update(&c,d->path,strlen(d->path)+1);basm_sha_update(&c,digest,32);
    }
    basm_sha_final(&c,out);return 0;
}

#ifdef BEAR_TIME_H
typedef bear_sha256_ctx rel8_sha_ctx;
#define rel8_sha_init bear_sha256_init
#define rel8_sha_update bear_sha256_update
#define rel8_sha_final bear_sha256_final
#else
typedef basm_sha_ctx rel8_sha_ctx;
#define rel8_sha_init basm_sha_init
#define rel8_sha_update basm_sha_update
#define rel8_sha_final basm_sha_final
#endif

static int rel8_sha_file(const char *path,uint8_t out[32]) {
    uint64_t remaining=0;FILE *f=basm_attest_open_regular(path,BASM_ATTEST_ARTIFACT_MAX,&remaining);
    if(!f)return -1;
    rel8_sha_ctx c; rel8_sha_init(&c); uint8_t buf[65536];
    int ok=1;
    while(remaining){
        size_t want=remaining>sizeof(buf)?sizeof(buf):(size_t)remaining;
        size_t got=fread(buf,1,want,f);
        if(got!=want){ok=0;break;}
        rel8_sha_update(&c,buf,got);remaining-=got;
    }
    if(ok && fgetc(f)!=EOF)ok=0;
    if(ferror(f))ok=0;if(fclose(f)!=0)ok=0;if(!ok)return -1;
    rel8_sha_final(&c,out); return 0;
}

static int basm_unhex(const char *in,uint8_t *out,int n) {
    for(int i=0;i<n;i++){
        int hi,lo; char a=in[i*2],b=in[i*2+1];
        if(a>='0'&&a<='9')hi=a-'0'; else if(a>='a'&&a<='f')hi=10+a-'a'; else if(a>='A'&&a<='F')hi=10+a-'A'; else return -1;
        if(b>='0'&&b<='9')lo=b-'0'; else if(b>='a'&&b<='f')lo=10+b-'a'; else if(b>='A'&&b<='F')lo=10+b-'A'; else return -1;
        out[i]=(uint8_t)((hi<<4)|lo);
    }
    return 0;
}

static void rel8_hmac(const uint8_t secret[32],const uint8_t key[32],
                      const uint8_t output[32],uint8_t tag[32]) {
    uint8_t pad[64],inner[32];
    for(int i=0;i<64;i++)pad[i]=(uint8_t)((i<32?secret[i]:0)^0x36);
    rel8_sha_ctx c; rel8_sha_init(&c); rel8_sha_update(&c,pad,64);
    rel8_sha_update(&c,"BASM_REL8_ESCROW_V1",20); rel8_sha_update(&c,key,32);
    rel8_sha_update(&c,output,32); rel8_sha_final(&c,inner);
    for(int i=0;i<64;i++)pad[i]=(uint8_t)((i<32?secret[i]:0)^0x5c);
    rel8_sha_init(&c); rel8_sha_update(&c,pad,64); rel8_sha_update(&c,inner,32);
    rel8_sha_final(&c,tag); memset(pad,0,sizeof(pad)); /* INV-559 */
}

static int rel8_ct_equal(const uint8_t *a,const uint8_t *b,size_t n) {
    uint8_t diff=0;
    for(size_t i=0;i<n;i++)diff|=(uint8_t)(a[i]^b[i]);
    return diff==0;
}

static int rel8_hash_incbin_dependencies(rel8_sha_ctx *key,const char *src) {
    /* INV-567: recognize the directive token, never text inside data strings. */
    const char *line=src;
    while(*line){
        const char *eol=strchr(line,'\n');
        if(!eol) eol=line+strlen(line);
        const char *p=line;
        while(p<eol && char_in(*p, " \t"))p++;
        if(p<eol && *p!=';'){
            const char *word=p;
            while(p<eol && !char_in(*p, " \t:;"))p++;
            if(p<eol && *p==':'){
                p++; while(p<eol && char_in(*p, " \t"))p++;
                word=p; while(p<eol && !char_in(*p, " \t;"))p++;
            }
            /* W20: macro-generated directives execute only during assembly.
             * A cache hit would bypass their includes/defines/conditionals, so
             * their input closure is not known here. Refuse that cache mode.
             * This checks a directive token, never strings or comment text. */
            if(p>word && word[0]=='%')die("rel8 escrow: deferred preprocessor directive after expansion");
            if(p-word==6 && !memcmp(word,"incbin",6)){
                /* Share the assembler's filename framing, including comments,
                 * spaces and backticks. A second ad-hoc lexer can bind the
                 * cache to a different file than handle_incbin_directive. */
                char args[3][BASM_LINE_CAP],path[BASM_LINE_CAP];
                const char *saved_source=g_data_source;g_data_source=word;
                (void)incbin_arguments(args);filename_token(args[0],path,sizeof(path));
                g_data_source=saved_source;
                const BasmDependency *dep=basm_snapshot_open(path,BASM_DEP_INCBIN);
                uint8_t digest[32];if(!dep || basm_dependency_digest_for(dep,digest)!=0)return -1;
                rel8_sha_update(key,"incbin",7);rel8_sha_update(key,digest,32);
            }
        }
        line=*eol?eol+1:eol;
    }
    return 0;
}

#define BASM_REL8_BUILD_ID "bearbasm-output-v2"

static int rel8_prepare(const char *dir,const char *key_path,const char *src,
                        const char *src_path,const char *fmt,char id[65],
                        uint8_t key_id[32],uint8_t secret[32]) {
    extern unsigned int getuid(void);
    struct stat st;
    if(mkdir(dir,0700)!=0 && errno!=EEXIST) return -1;
    if(lstat(dir,&st)!=0 || !S_ISDIR(st.st_mode) || st.st_uid!=getuid() || (st.st_mode&077)!=0) return -1;
    uint8_t digest[32];
    extern int sign_load_seed(const char*,uint8_t[32]);
    if(sign_load_seed(key_path,secret)!=0) return -1;
    rel8_sha_ctx kid; rel8_sha_init(&kid); rel8_sha_update(&kid,"BASM_REL8_KEY_V1",17);
    rel8_sha_update(&kid,secret,32); rel8_sha_final(&kid,key_id);
    uint8_t tool_digest[32];
    if(basm_tool_digest(tool_digest)!=0)return -1;
    rel8_sha_ctx c; rel8_sha_init(&c);
    rel8_sha_update(&c,"BASM_REL8_ESCROW_V1",20);
    rel8_sha_update(&c,BASM_REL8_BUILD_ID,sizeof(BASM_REL8_BUILD_ID));
    rel8_sha_update(&c,tool_digest,sizeof(tool_digest)); /* INV-562 */
    rel8_sha_update(&c,key_id,32);
    /* INV-589: a compatibility hit must never bypass public validation.
     * Main sets g_bootstrap only after validating the pinned raw AP input. */
    const char *profile=target_profile_name(), *policy=target_policy_id();
    const char *bootstrap=g_bootstrap?"ap-trampoline-v1":"none";
    rel8_sha_update(&c,policy,strlen(policy)+1);
    rel8_sha_update(&c,profile,strlen(profile)+1);
    rel8_sha_update(&c,bootstrap,strlen(bootstrap)+1);
    rel8_sha_update(&c,fmt,strlen(fmt)+1); rel8_sha_update(&c,src_path,strlen(src_path)+1);
    rel8_sha_update(&c,src,strlen(src));
    if(rel8_hash_incbin_dependencies(&c,src)!=0)return -1;
    /* W08: every output-affecting proof choice belongs to the cache contract.
     * The signer is the public identity derived from the already-loaded seed. */
    uint8_t proof_mode,proof_pub[32],dependencies[32];
    basm_exec_identity(&proof_mode,proof_pub);
    rel8_sha_update(&c,&proof_mode,1);rel8_sha_update(&c,proof_pub,32);
    if(basm_dependency_root(dependencies)!=0)return -1;
    rel8_sha_update(&c,dependencies,32);
    rel8_sha_final(&c,digest); basm_hex32(digest,id);
    return 0;
}

static int rel8_copy_stream(FILE *in,FILE *out) {
    if(fseek(in,0,SEEK_SET)!=0)return -1;
    int fd=fileno(in);
    if(fd<0)return -1;
    struct stat st;if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || st.st_size<0 ||
                     (uint64_t)st.st_size>BASM_ATTEST_ARTIFACT_MAX)return -1;
    uint8_t *buf=(uint8_t*)malloc(65536); if(!buf)return -1;
    int ok=1;uint64_t total=0;
    while(1){
        /* Match the object writer's descriptor I/O. The source may be its
         * unbuffered update stream; fseek above synchronizes stream state. */
        long got;
        do { got=(long)read(fd,buf,65536); } while(got<0 && errno==EINTR);
        if(got<0){ok=0;break;}
        if(!got)break;
        if((uint64_t)got>BASM_ATTEST_ARTIFACT_MAX-total){ok=0;break;}
        total+=(uint64_t)got;
        if(fwrite(buf,1,(size_t)got,out)!=(size_t)got){ok=0;break;}
    }
    free(buf);
    return ok?0:-1;
}

static int rel8_copy_file(const char *src,const char *dst,char *tmp,size_t capacity) {
    FILE *in=basm_attest_open_regular(src,BASM_ATTEST_ARTIFACT_MAX,NULL);
    if(!in)return -1;
    FILE *out=out_tmp_open(dst,tmp,capacity);
    if(!out){fclose(in);return -1;}
    int ok=rel8_copy_stream(in,out)==0;
    if(fclose(in)!=0)ok=0;
    if(fclose(out)!=0)ok=0;
    if(!ok)remove(tmp);
    return ok?0:-1;
}

static void rel8_paths(const char *dir,const char *id,char object[1024],char receipt[1024]) {
    if(snprintf(object,1024,"%s/%s.o",dir,id)>=1024 ||
       snprintf(receipt,1024,"%s/%s.receipt",dir,id)>=1024) die("rel8 path too long");
}

/* W08: the cache receipt is a closed wire form. No ignored algorithm,
 * duplicate field, truncated value, embedded NUL or trailing record is accepted. */
static int rel8_receipt_valid(const char *body,long len) {
    static const char header[]="basm rel8 escrow v1\n";
    static const char *keys[]={"cache_key","output_sha256","auth_alg","key_id","auth"};
    if(!body || len<(long)(sizeof(header)-1) || len>1024 || strlen(body)!=(size_t)len ||
       memcmp(body,header,sizeof(header)-1))return 0;
    const char *p=body+sizeof(header)-1;
    for(int i=0;i<5;i++){
        const char *end=strchr(p,'\n');size_t k=strlen(keys[i]);
        if(!end || (size_t)(end-p)<k+2 || memcmp(p,keys[i],k) || p[k]!=':' || p[k+1]!=' ')return 0;
        const char *v=p+k+2;size_t n=(size_t)(end-v);
        if(i==2){if(n!=11 || memcmp(v,"hmac-sha256",11))return 0;}
        else{
            if(n!=64)return 0;
            for(size_t j=0;j<n;j++)if(!((v[j]>='0'&&v[j]<='9')||(v[j]>='a'&&v[j]<='f')))return 0;
        }
        p=end+1;
    }
    return !*p;
}

static int rel8_restore(const char *dir,const char *id,const uint8_t expected_key_id[32],
                        const uint8_t secret[32],const char *out) {
    extern unsigned int getuid(void);
    char object[1024],receipt[1024]; rel8_paths(dir,id,object,receipt);
    struct stat os,rs;
    int have_object=lstat(object,&os)==0,have_receipt=lstat(receipt,&rs)==0;
    if(!have_object && !have_receipt)return 0;
    /* INV-583: a half-present entry is a concurrent publish in flight
     * (object lands before receipt) or a partial failure — never proof
     * of tampering, and the HMAC below still guards every byte we
     * accept. Treat as a miss so the build heals by reassembling; a
     * forger cannot benefit because only fully-authenticated pairs
     * restore, and the threat model already excludes same-uid writers
     * (0700 dir). */
    if(!have_object || !have_receipt)return 0;
    if(!S_ISREG(os.st_mode) || !S_ISREG(rs.st_mode) ||
       os.st_uid!=getuid() || rs.st_uid!=getuid() || (os.st_mode&077)!=0 || (rs.st_mode&077)!=0)return -1;
    long body_len=0; char *body=basm_read_text_file(receipt,&body_len);
    if(!rel8_receipt_valid(body,body_len)){free(body);return -1;}
    char rid[65],out_hex[65],key_id_hex[65],auth_hex[65];
    int ok=basm_proof_value(body,"cache_key",rid,sizeof(rid)) &&
           basm_proof_value(body,"output_sha256",out_hex,sizeof(out_hex)) &&
           basm_proof_value(body,"key_id",key_id_hex,sizeof(key_id_hex)) &&
           basm_proof_value(body,"auth",auth_hex,sizeof(auth_hex));
    uint8_t output_hash[32],key_id[32],auth[32],key_raw[32],expected_auth[32];
    if(!ok || strcmp(rid,id) || basm_unhex(out_hex,output_hash,32)!=0 ||
       basm_unhex(key_id_hex,key_id,32)!=0 || basm_unhex(auth_hex,auth,32)!=0 ||
        !rel8_ct_equal(key_id,expected_key_id,32) || basm_unhex(rid,key_raw,32)!=0){
        free(body);return -1;
    }
    rel8_hmac(secret,key_raw,output_hash,expected_auth);
    if(!rel8_ct_equal(auth,expected_auth,32)){
        free(body);return -1;
    }
    free(body);
    /* INV-583: copy to a private temp, hash WHAT WAS COPIED, then rename.
     * Verifying `object` and copying it afterwards is a TOCTOU (a
     * concurrent publish can swap the file between the two reads); it
     * also bypassed the W2 atomic publish by writing `out` directly. */
    {
        char tmp_out[1100];
        uint8_t staged[32];
        if(rel8_copy_file(object,out,tmp_out,sizeof(tmp_out))!=0)return -1;
        if(rel8_sha_file(tmp_out,staged)!=0 || !rel8_ct_equal(staged,output_hash,32)){remove(tmp_out);return -1;}
        if(rename(tmp_out,out)!=0){remove(tmp_out);return -1;}
        memcpy(g_attestation_output,staged,32);g_attestation_output_ready=1;
        return 1;
    }
}

static int rel8_publish(const char *dir,const char *id,const uint8_t key_id[32],
                        const uint8_t secret[32],FILE *source) {
    char object[1024],receipt[1024],tmp_object[1100],tmp_receipt[1100];
    rel8_paths(dir,id,object,receipt);
    /* INV-583: bind the receipt to this job's open stream, not a final output
     * pathname that another publisher can replace between rename and copy. */
    FILE *staged=out_tmp_open(object,tmp_object,sizeof(tmp_object));
    if(!staged)return -1;
    int copied=rel8_copy_stream(source,staged)==0;
    if(fclose(staged)!=0)copied=0;
    if(!copied || chmod(tmp_object,0600)!=0){remove(tmp_object);return -1;}
    uint8_t output_hash[32],key_raw[32],auth[32];
    char output_hex[65],key_id_hex[65],auth_hex[65];
    if(rel8_sha_file(tmp_object,output_hash)!=0 || basm_unhex(id,key_raw,32)!=0){remove(tmp_object);return -1;}
    rel8_hmac(secret,key_raw,output_hash,auth);
    basm_hex32(output_hash,output_hex); basm_hex32(key_id,key_id_hex); basm_hex32(auth,auth_hex);
    FILE *f=out_tmp_open(receipt,tmp_receipt,sizeof(tmp_receipt)); if(!f){remove(tmp_object);return -1;}
    int ok=fprintf(f,"basm rel8 escrow v1\ncache_key: %s\noutput_sha256: %s\nauth_alg: hmac-sha256\nkey_id: %s\nauth: %s\n",
                   id,output_hex,key_id_hex,auth_hex)>=0;
    if(fclose(f)!=0)ok=0;
    if(!ok || chmod(tmp_receipt,0600)!=0){remove(tmp_object);remove(tmp_receipt);return -1;}
    /* INV-583: on failure remove only our tmps, never the live entry: a
     * concurrent publisher may have just installed a good pair, and our
     * failure must not destroy it (a half entry heals as a miss). */
    if(rename(tmp_object,object)!=0){remove(tmp_object);remove(tmp_receipt);return -1;}
    if(rename(tmp_receipt,receipt)!=0){remove(tmp_receipt);return -1;}
    return 0;
}

static int basm_hex_eq32(const uint8_t h[32], const char *hex) {
    char got[65];
    basm_hex32(h, got);
    return hex && strlen(hex) == 64 && memcmp(got, hex, 64) == 0;
}

static int basm_proof_value(const char *body, const char *key, char *out, size_t outsz) {
    size_t klen = strlen(key);
    const char *p = body;
    while ((p = strstr(p, key)) != NULL) {
        if ((p == body || p[-1] == '\n') && p[klen] == ':' && p[klen + 1] == ' ') {
            const char *v = p + klen + 2;
            const char *e = strchr(v, '\n');
            size_t n = e ? (size_t)(e - v) : strlen(v);
            if (!outsz || n >= outsz) return 0;
            memcpy(out, v, n);
            out[n] = 0;
            return 1;
        }
        p += klen;
    }
    return 0;
}

static char *basm_read_text_file(const char *path, long *out_len) {
    FILE *f = basm_attest_open_regular(path,SIGN_ATTESTATION_MAX_BYTES,NULL);
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0 || (unsigned long long)n > SIGN_ATTESTATION_MAX_BYTES) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got=fread(buf,1,(size_t)n,f);
    int extra=fgetc(f),bad=ferror(f);if(fclose(f)!=0)bad=1;
    if(got!=(size_t)n || extra!=EOF || bad){free(buf);return NULL;}
    buf[n] = 0;
    if (out_len) *out_len = n;
    return buf;
}

/* INV-589: v3 is a closed, single-valued schema. Validate before the legacy
 * value reader can truncate anything, and keep all evidence before the signer
 * boundary. Returns the field count, or zero for invalid data. The optional
 * PQC fields remain sign.c's placeholder, not PQC proof. */
static int basm_proof_v3_fields(const char *body) {
    static const char *keys[] = {
        "tool", "tool_sha256", "source_path", "source_sha256", "output_path",
        "output_sha256", "output_format", "merkle_node_id", "build_epoch",
        "policy", "target_profile", "bootstrap", "signature",
        "ddc_compiler_sha256", "ddc_compiler_path", "signature_alg", "signature_pub",
        "signature_pqc_alg", "signature_pqc_pub", "signature_pqc"
    };
    static const int caps[] = {5,65,1024,65,1024,65,64,65,21,64,32,32,129,65,1024,32,65,32,65,129};
    unsigned seen=0, signed_fields=(1u<<15)|(1u<<16), pqc_fields=7u<<17;
    int trailer=0, is_unsigned=0, fields=0;
    const char *p=strchr(body,'\n')+1;
    while(*p){
        const char *end=strchr(p,'\n'), *colon=strchr(p,':');
        if(!end || !colon || colon>=end || colon+1>=end || colon[1]!=' ')return 0;
        int i;
        for(i=0;i<20;i++)if(strlen(keys[i])==(size_t)(colon-p) && !memcmp(p,keys[i],(size_t)(colon-p)))break;
        if(i==20 || (seen&(1u<<i)))return 0;
        int is_tail=i==12 || i>=15;
        if(trailer && !is_tail)return 0;
        if(is_tail)trailer=1;
        size_t len=(size_t)(end-colon-2);
        if(!len || len>=(size_t)caps[i])return 0;
        char value[1024]; memcpy(value,colon+2,len); value[len]=0;
        if(value[0]==' ')return 0;
        for(size_t j=0;j<len;j++)if((unsigned char)value[j]<32 || value[j]==127)return 0;
        int hexlen=(i==1||i==3||i==5||i==7||i==13||i==16||i==18)?64:0;
        if(i==12){is_unsigned=!strcmp(value,"unsigned"); if(!is_unsigned)hexlen=128;}
        if(i==19)hexlen=128;
        if(hexlen){
            if(len!=(size_t)hexlen)return 0;
            for(size_t j=0;j<len;j++)if(!((value[j]>='0'&&value[j]<='9')||(value[j]>='a'&&value[j]<='f')))return 0;
        }
        if(i==0 && strcmp(value,"basm"))return 0;
        if(i==8){
            for(size_t j=0;j<len;j++)if(value[j]<'0'||value[j]>'9')return 0;
            if(len==20 && strcmp(value,"18446744073709551615")>0)return 0;
        }
        if(i==15 && (strcmp(value,"ed25519-over-sha256") || seen&(1u<<12)))return 0;
        if(i==16 && !(seen&(1u<<15)))return 0;
        if(i==12 && !is_unsigned && (seen&signed_fields)!=signed_fields)return 0;
        if(i>=17 && !(seen&(1u<<12)))return 0;
        if(i==17 && strcmp(value,"dilithium3-placeholder"))return 0;
        seen|=1u<<i; fields++; p=end+1;
    }
    if((seen&8191u)!=8191u)return 0; /* first thirteen fields are mandatory */
    if(is_unsigned)return (seen&(signed_fields|pqc_fields))?0:fields;
    return (seen&signed_fields)==signed_fields && (!(seen&pqc_fields)||(seen&pqc_fields)==pqc_fields)?fields:0;
}

/* NUL-terminated domain and strings; the three digests are fixed-width.
 * This binds recorded policy identity, not the semantics of the assembly. */
static void basm_proof_merkle(const uint8_t tool[32],const uint8_t src[32],
                              const uint8_t out[32],int v3,const char *fmt,
                              const char *policy,const char *profile,
                              const char *bootstrap,uint8_t hash[32]) {
    basm_sha_ctx c; basm_sha_init(&c);
    if(v3)basm_sha_update(&c,"basm-attestation-v3",sizeof("basm-attestation-v3"));
    basm_sha_update(&c,tool,32); basm_sha_update(&c,src,32); basm_sha_update(&c,out,32);
    if(v3){
        basm_sha_update(&c,fmt,strlen(fmt)+1);
        basm_sha_update(&c,policy,strlen(policy)+1);
        basm_sha_update(&c,profile,strlen(profile)+1);
        basm_sha_update(&c,bootstrap,strlen(bootstrap)+1);
    }
    basm_sha_final(&c,hash);
}

/* V4 is local input-closure evidence, not a semantic or bootstrap certificate.
 * Paths are hex encoded to make dependency records unambiguous. All hashes and
 * numeric encodings are canonical; the source entry is bound to the root input. */
typedef struct {
    uint64_t count;
    uint8_t root[32],expanded[32],configuration[32];
} BasmProofV4;
static int basm_decimal(const char *s,size_t len,uint64_t *out) {
    if(!len || len>20 || (len>1 && s[0]=='0'))return 0;
    uint64_t value=0;
    for(size_t i=0;i<len;i++){
        if(s[i]<'0' || s[i]>'9')return 0;
        unsigned digit=(unsigned)(s[i]-'0');
        if(value>(UINT64_MAX-digit)/10)return 0;
        value=value*10+digit;
    }
    *out=value;return 1;
}
static int basm_lower_hex(const char *s,size_t len) {
    for(size_t i=0;i<len;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;
    return 1;
}
static int basm_dep_record(const char *p,size_t len,int *kind,uint64_t *size,
                            uint8_t hash[32],char path[1024]) {
    if(len<1+1+1+1+64+1+2 || p[0]<'1'||p[0]>'3'||p[1]!=' ')return 0;
    *kind=p[0]-'0';p+=2;len-=2;
    const char *sp=(const char*)memchr(p,' ',len);if(!sp)return 0;
    size_t num=(size_t)(sp-p);
    if(!basm_decimal(p,num,size))return 0;
    p=sp+1;len-=num+1;
    if(len<67 || p[64]!=' ' || !basm_lower_hex(p,64) || basm_unhex(p,hash,32)!=0)return 0;
    p+=65;len-=65;
    if(!len || (len&1) || len>2046 || !basm_lower_hex(p,len) ||
       basm_unhex(p,(uint8_t*)path,(int)(len/2))!=0)return 0;
    size_t n=len/2;if(memchr(path,0,n))return 0;path[n]=0;return 1;
}
static int basm_hash_dependency_file(const char *path,uint64_t expected_size,uint8_t hash[32]) {
    uint64_t actual_size=0;
    FILE *f=basm_attest_open_regular(path,expected_size,&actual_size);if(!f)return 0;
    if(actual_size!=expected_size){fclose(f);return 0;}
    basm_sha_ctx c;basm_sha_init(&c);uint8_t buf[65536];uint64_t remaining=expected_size;
    int ok=1;
    while(remaining){
        size_t want=remaining>sizeof(buf)?sizeof(buf):(size_t)remaining;
        size_t n=fread(buf,1,want,f);
        if(n!=want){ok=0;break;}
        basm_sha_update(&c,buf,n);remaining-=n;
    }
    if(ok && fgetc(f)!=EOF)ok=0;
    if(ferror(f))ok=0;if(fclose(f)!=0)ok=0;
    if(ok)basm_sha_final(&c,hash);return ok;
}
static int basm_proof_v4_fields(const char *body,BasmProofV4 *proof,int check_files) {
    size_t bodylen=strlen(body);
    if(bodylen<20 || bodylen>SIGN_ATTESTATION_MAX_BYTES || memcmp(body,"basm attestation v4\n",20))return 0;
    char *base=(char*)malloc(32768);if(!base)return 0;
    memcpy(base,body,20);size_t used=20;int ok=1,seen=0,trailer=0;
    uint64_t records=0,total_bytes=0;basm_sha_ctx closure;uint8_t actual[32];
    char source_path[1024],source_hex[65];
    if(!basm_proof_value(body,"source_path",source_path,sizeof(source_path)) ||
       !basm_proof_value(body,"source_sha256",source_hex,sizeof(source_hex)))ok=0;
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
                if(seen || !basm_decimal(v,vn,&proof->count) || !proof->count || proof->count>4096){ok=0;break;}
                seen=1;basm_sha_init(&closure);
                basm_sha_update(&closure,"basm-input-closure-v1",sizeof("basm-input-closure-v1"));
                basm_sha_u64(&closure,proof->count);
            }else if(field<=4){
                int expected=(1<<(field-1))-1;
                uint8_t *dest=field==2?proof->root:field==3?proof->expanded:proof->configuration;
                if(seen!=expected || vn!=64 || !basm_lower_hex(v,vn) || basm_unhex(v,dest,32)!=0){ok=0;break;}
                seen|=1<<(field-1);
            }else{
                int kind;uint64_t size;uint8_t digest[32];char path[1024];
                if(seen!=15 || records>=proof->count || !basm_dep_record(v,vn,&kind,&size,digest,path)) {ok=0;break;}
                uint64_t limit=kind==BASM_DEP_INCBIN?BASM_BINARY_BYTES_MAX:BASM_SOURCE_BYTES_MAX;
                if(size>limit || size>BASM_DEP_BYTES_MAX-total_bytes){ok=0;break;}total_bytes+=size;
                if(records==0){
                    if(kind!=BASM_DEP_SOURCE || strcmp(path,source_path) || !basm_hex_eq32(digest,source_hex)){ok=0;break;}
                }else if(kind==BASM_DEP_SOURCE){ok=0;break;}
                uint8_t k=(uint8_t)kind;basm_sha_update(&closure,&k,1);basm_sha_u64(&closure,size);
                basm_sha_update(&closure,path,strlen(path)+1);basm_sha_update(&closure,digest,32);records++;
                if(check_files){
                    uint8_t filehash[32];
                    if(!basm_hash_dependency_file(path,size,filehash) || memcmp(filehash,digest,32)){ok=0;break;}
                }
            }
        }else{
            if(n>=10 && (!memcmp(p,"signature:",10) || !memcmp(p,"signature_",10)))trailer=1;
            if(n>=14 && !memcmp(p,"signature_pqc",13)){ok=0;break;}
            if(n+1>32767-used){ok=0;break;}
            memcpy(base+used,p,n+1);used+=n+1;
        }
        p=end+1;
    }
    if(ok && (seen!=15 || records!=proof->count))ok=0;
    if(ok){basm_sha_final(&closure,actual);if(memcmp(actual,proof->root,32))ok=0;}
    base[used]=0;
    if(ok && !basm_proof_v3_fields(base))ok=0;
    free(base);return ok;
}
static void basm_proof_merkle_v4(const uint8_t tool[32],const uint8_t source[32],
                                 const uint8_t output[32],const char *fmt,const char *policy,
                                 const char *profile,const char *bootstrap,const BasmProofV4 *proof,
                                 uint8_t hash[32]) {
    basm_sha_ctx c;basm_sha_init(&c);
    basm_sha_update(&c,"basm-attestation-v4",sizeof("basm-attestation-v4"));
    basm_sha_update(&c,tool,32);basm_sha_update(&c,source,32);basm_sha_update(&c,output,32);
    basm_sha_update(&c,fmt,strlen(fmt)+1);basm_sha_update(&c,policy,strlen(policy)+1);
    basm_sha_update(&c,profile,strlen(profile)+1);basm_sha_update(&c,bootstrap,strlen(bootstrap)+1);
    basm_sha_update(&c,proof->expanded,32);basm_sha_update(&c,proof->configuration,32);
    basm_sha_update(&c,proof->root,32);basm_sha_final(&c,hash);
}

static int verify_basm_attestation(const char *attest_path, int require_signature, const char *trusted_key) {
    long n = 0;
    char *body = basm_read_text_file(attest_path, &n);
    if (!body) { dprintf(2, "basm: cannot read attestation '%s'\n", attest_path); return 1; }
    int v3=n>=20 && !memcmp(body,"basm attestation v3\n",20);
    int v4=n>=20 && !memcmp(body,"basm attestation v4\n",20);
    BasmProofV4 closure;memset(&closure,0,sizeof(closure));
    if (n < 20 || strlen(body)!=(size_t)n || sign_attestation_signature_state(body,(size_t)n)<0 ||
        (!v3 && !v4 && memcmp(body, "basm attestation v2\n", 20))) {
        dprintf(2, "basm: bad attestation header '%s'\n", attest_path);
        free(body); return 1;
    }
    /* Authenticate the exact proof snapshot before following its file paths. */
    int signed_state=sign_attestation_signature_state(body,(size_t)n);
    uint8_t trusted_pub[32];
    if(trusted_key && sign_load_public_key(trusted_key,trusted_pub)!=0){
        free(body);dprintf(2,"basm: cannot load trusted public key\n");return 1;
    }
    if(!signed_state && (require_signature || trusted_key)){
        free(body);dprintf(2,"basm: unsigned attestation rejected '%s'\n",attest_path);return 1;
    }
    if(signed_state && sign_verify_attestation_buffer(body,(size_t)n,trusted_key?trusted_pub:NULL,NULL)!=0){
        free(body);dprintf(2,"basm: attestation signature invalid '%s'\n",attest_path);return 1;
    }

    if ((v4 && !basm_proof_v4_fields(body,&closure,1)) || (v3 && !basm_proof_v3_fields(body)) ||
        (!v3 && !v4 && (strstr(body,"\npolicy") || strstr(body,"\ntarget_profile") || strstr(body,"\nbootstrap") ||
                      strstr(body,"\ndependency") || strstr(body,"\nexpanded_sha256") || strstr(body,"\nconfiguration_sha256")))) {
        dprintf(2,"basm: invalid attestation fields '%s'\n",attest_path);
        free(body); return 1;
    }
    char src[1024], out[1024], fmt[64], src_hex[65], out_hex[65], tool_hex[65], merkle_hex[65], sig[129];
    char policy[64]="", profile[32]="", bootstrap[32]="";
    int ok = 1;
    ok &= basm_proof_value(body, "source_path", src, sizeof(src));
    ok &= basm_proof_value(body, "output_path", out, sizeof(out));
    ok &= basm_proof_value(body, "output_format", fmt, sizeof(fmt));
    ok &= basm_proof_value(body, "source_sha256", src_hex, sizeof(src_hex));
    ok &= basm_proof_value(body, "output_sha256", out_hex, sizeof(out_hex));
    ok &= basm_proof_value(body, "tool_sha256", tool_hex, sizeof(tool_hex));
    ok &= basm_proof_value(body, "merkle_node_id", merkle_hex, sizeof(merkle_hex));
    ok &= basm_proof_value(body, "signature", sig, sizeof(sig));
    if (!ok) { dprintf(2, "basm: incomplete attestation '%s'\n", attest_path); free(body); return 1; }
    if (strcmp(fmt, "elf64") && strcmp(fmt, "bin")) {
        dprintf(2, "basm: unsupported attested format '%s'\n", fmt);
        free(body); return 1;
    }
    if(v3 || v4){
        ok &= basm_proof_value(body,"policy",policy,sizeof(policy));
        ok &= basm_proof_value(body,"target_profile",profile,sizeof(profile));
        ok &= basm_proof_value(body,"bootstrap",bootstrap,sizeof(bootstrap));
        if(!ok || strcmp(policy,target_policy_id()) ||
           (strcmp(profile,"beyond") && strcmp(profile,"public")) ||
           (strcmp(bootstrap,"none") && strcmp(bootstrap,"ap-trampoline-v1")) ||
           (!strcmp(bootstrap,"ap-trampoline-v1") && strcmp(profile,"beyond"))) {
            dprintf(2,"basm: invalid attestation policy '%s'\n",attest_path);
            free(body); return 1;
        }
    }

    uint8_t th[32]={0}, sh[32]={0}, oh[32]={0}, mh[32];
    if (basm_tool_digest(th) != 0) { dprintf(2, "basm: cannot hash tool\n"); ok = 0; }
    if (basm_sha_file_limit(src,BASM_SOURCE_BYTES_MAX,sh) != 0) { dprintf(2, "basm: cannot hash source '%s'\n", src); ok = 0; }
    if (basm_sha_file(out, oh) != 0) { dprintf(2, "basm: cannot hash output '%s'\n", out); ok = 0; }
    if(v4)basm_proof_merkle_v4(th,sh,oh,fmt,policy,profile,bootstrap,&closure,mh);
    else basm_proof_merkle(th,sh,oh,v3,fmt,policy,profile,bootstrap,mh);

    if (!basm_hex_eq32(th, tool_hex)) { dprintf(2, "basm: tool hash mismatch in '%s'\n", attest_path); ok = 0; }
    if (!basm_hex_eq32(sh, src_hex)) { dprintf(2, "basm: source hash mismatch in '%s'\n", attest_path); ok = 0; }
    if (!basm_hex_eq32(oh, out_hex)) { dprintf(2, "basm: output hash mismatch in '%s'\n", attest_path); ok = 0; }
    if (!basm_hex_eq32(mh, merkle_hex)) { dprintf(2, "basm: merkle hash mismatch in '%s'\n", attest_path); ok = 0; }

    free(body);
    return ok ? 0 : 1;
}

/* Locate the running executable. Linux uses /proc/self/exe; macOS uses
 * _NSGetExecutablePath. Evidence/cache callers fail closed if this fails. */
static const char *basm_self_exe_path(void) {
#ifdef BASM_NO_PROC_SELF_EXE
    static char path[4096];
    uint32_t sz = sizeof(path);
    if (_NSGetExecutablePath(path, &sz) == 0) return path;
    return NULL;
#else
    return "/proc/self/exe";
#endif
}

static int basm_metadata_value(const char *s,size_t cap) {
    if(!s || !*s || *s==' ' || strlen(s)>=cap)return 0;
    for(const unsigned char *p=(const unsigned char*)s;*p;p++)if(*p<32 || *p==127)return 0;
    return 1;
}
static int basm_same_file(const char *a,const char *b) {
    if(!strcmp(a,b))return 1;
    struct stat x,y;
    return stat(a,&x)==0 && stat(b,&y)==0 && x.st_dev==y.st_dev && x.st_ino==y.st_ino;
}
static int emit_basm_attestation_stream(FILE *f,const char *src_path,const char *out_path,const char *fmt) {
    if(!g_attestation_source_ready || !g_attestation_output_ready ||
       (g_attestation_v4 && (!g_target_profile || !g_attestation_expanded_ready)) ||
       !basm_metadata_value(src_path,1024) || !basm_metadata_value(out_path,1024))return -1;
    const char *ddc_hash=getenv("BASM_DDC_COMPILER_HASH"),*ddc_path=getenv("BASM_DDC_COMPILER_PATH");
    if(ddc_hash && (strlen(ddc_hash)!=64 || !basm_lower_hex(ddc_hash,64)))return -1;
    if(ddc_path && !basm_metadata_value(ddc_path,1024))return -1;
    uint64_t epoch=0;const char *sde=getenv("SOURCE_DATE_EPOCH");
    if(sde && !basm_decimal(sde,strlen(sde),&epoch))return -1;
    uint8_t self_h[32],merkle_h[32];char self_hex[65],src_hex[65],out_hex[65],merkle_hex[65];
    if(basm_tool_digest(self_h)!=0)return -1;
    basm_hex32(self_h,self_hex);basm_hex32(g_attestation_source,src_hex);basm_hex32(g_attestation_output,out_hex);
    const char *policy=target_policy_id(),*profile=target_profile_name();
    const char *bootstrap=g_bootstrap?"ap-trampoline-v1":"none";
    int version=g_attestation_v4?4:g_target_profile?3:2;
    BasmProofV4 proof;memset(&proof,0,sizeof(proof));
    if(version==4){
        proof.count=(uint64_t)basm_dependency_count();
        if(basm_dependency_root(proof.root)!=0)return -1;
        memcpy(proof.expanded,g_attestation_expanded,32);memcpy(proof.configuration,g_attestation_configuration,32);
        basm_proof_merkle_v4(self_h,g_attestation_source,g_attestation_output,fmt,policy,profile,bootstrap,&proof,merkle_h);
    }else basm_proof_merkle(self_h,g_attestation_source,g_attestation_output,version==3,fmt,policy,profile,bootstrap,merkle_h);
    basm_hex32(merkle_h,merkle_hex);
    int ok=1;
    ok&=fprintf(f,"basm attestation v%d\ntool: basm\ntool_sha256: %s\n",version,self_hex)>=0;
    ok&=fprintf(f,"source_path: %s\nsource_sha256: %s\noutput_path: %s\noutput_sha256: %s\noutput_format: %s\n",
                src_path,src_hex,out_path,out_hex,fmt)>=0;
    if(version>=3)ok&=fprintf(f,"policy: %s\ntarget_profile: %s\nbootstrap: %s\n",policy,profile,bootstrap)>=0;
    if(version==4){
        char root_hex[65],expanded_hex[65],config_hex[65];
        basm_hex32(proof.root,root_hex);basm_hex32(proof.expanded,expanded_hex);basm_hex32(proof.configuration,config_hex);
        ok&=fprintf(f,"dependency_count: %llu\ndependency_root: %s\nexpanded_sha256: %s\nconfiguration_sha256: %s\n",
                    (unsigned long long)proof.count,root_hex,expanded_hex,config_hex)>=0;
        for(size_t i=0;i<(size_t)proof.count && ok;i++){
            const BasmDependency *d=basm_dependency_at(i);uint8_t h[32];char hex[65],path_hex[2047];
            if(!d || basm_dependency_digest(i,h)!=0)return -1;
            basm_hex32(h,hex);size_t n=strlen(d->path);
            if(n>1023)return -1;
            static const char digits[]="0123456789abcdef";
            for(size_t j=0;j<n;j++){unsigned char ch=(unsigned char)d->path[j];path_hex[j*2]=digits[ch>>4];path_hex[j*2+1]=digits[ch&15];}
            path_hex[n*2]=0;
            ok&=fprintf(f,"dependency: %d %llu %s %s\n",d->kind,(unsigned long long)d->len,hex,path_hex)>=0;
        }
    }
    ok&=fprintf(f,"merkle_node_id: %s\nbuild_epoch: %llu\n",merkle_hex,(unsigned long long)epoch)>=0;
    /* These DDC fields are recorded declarations, never a DDC verification. */
    if(ddc_hash)ok&=fprintf(f,"ddc_compiler_sha256: %s\n",ddc_hash)>=0;
    if(ddc_path)ok&=fprintf(f,"ddc_compiler_path: %s\n",ddc_path)>=0;
    ok&=fprintf(f,"signature: unsigned\n")>=0;
    return ok?0:-1;
}

/* W10: only a complete proof reaches the caller's final name. No unsigned
 * precursor replaces an old proof when signing fails. Object+proof publication
 * is still two artifacts; a generation manifest is a separate consumer protocol. */
static int publish_basm_attestation(const char *attest_path,const char *src_path,
                                    const char *out_path,const char *fmt) {
    int rc=-1;char tmp[1100]={0};
    if(basm_same_file(attest_path,src_path) || basm_same_file(attest_path,out_path))goto done;
    for(size_t i=0;i<basm_dependency_count();i++){
        const BasmDependency *d=basm_dependency_at(i);
        if(d && basm_same_file(attest_path,d->path))goto done;
    }
    FILE *f=out_tmp_open(attest_path,tmp,sizeof(tmp));
    if(!f)goto done;
    int ok=emit_basm_attestation_stream(f,src_path,out_path,fmt)==0;
    if(fclose(f)!=0)ok=0;
    if(!ok)goto done;
    long len=0;char *body=basm_read_text_file(tmp,&len);
    if(!body || len<=0 || strlen(body)!=(size_t)len){free(body);goto done;}
    if(g_attestation_v4){BasmProofV4 proof;ok=basm_proof_v4_fields(body,&proof,0);}
    else if(g_target_profile)ok=basm_proof_v3_fields(body)!=0;
    free(body);if(!ok)goto done;
    if(g_attestation_signer_ready && sign_finalise_attestation(tmp,g_attestation_seed)!=0)goto done;
    if(rename(tmp,attest_path)!=0)goto done;
    tmp[0]=0;rc=0;
 done:
    if(tmp[0])remove(tmp);
    basm_secret_clear(g_attestation_seed,sizeof(g_attestation_seed));g_attestation_signer_ready=0;
    if(rc)dprintf(2,"basm: attestation publication failed\n");
    return rc;
}

/* W1.2: proof-carrying objects. Serialize the exact emitted section table
 * plus source/tool identity into a NOTE payload. Mirrors write_elf's
 * type/flags mapping one-to-one; any drift fails the offline gate, never
 * silently. Deterministic: hashes and tables only, no time/PID/paths beyond
 * the already-recorded source identity. */
#define EXEC_PROOF_MAGIC 0x54494E50u
#define EXEC_PROOF_VERSION 1u
#define EXEC_PROOF_NOTETYPE 0x54494E41u
#define EXEC_PROOF_NAME "TinaLinux"
#define EXEC_PROOF_MAXSEC 24
#define EXEC_PROOF_DESCSZ 1536

extern void ed25519_keypair_from_seed(const uint8_t seed[32], uint8_t pk[32], uint8_t sk[64]);
extern int ed25519_sign(uint8_t sig[64], const uint8_t *msg, uint32_t len, const uint8_t sk[64]);

/* Fixed-section attributes as data, not branches: mirrors write_elf one
 * to one (NOTE falls in the typeless branch there too). Custom sections
 * keep their declared type/flags. */
static const struct { uint32_t type; uint64_t flags; } proof_fixed_attrs[] = {
    {1,0x6}, {1,0x3}, {8,0x3}, {1,0}, {1,0x2}
};
static void proof_sec_attrs(int sec, uint32_t *type, uint64_t *flags, uint64_t *align){
    if (sec>=SEC_CUSTOM0){ int ci=custom_idx(sec); *type=g_custom_type[ci]; *flags=g_custom_flags[ci]; }
    else { *type=proof_fixed_attrs[sec].type; *flags=proof_fixed_attrs[sec].flags; }
    *align=(uint64_t)g_secalign[sec];
}
/* Content rule (mirrored by the kernel and the offline gate): hash the
 * emitted file bytes of a section iff it occupies file space; zero-size
 * sections hash empty on both sides, so the rule needs no size special
 * case. Incbin spans are re-read from their files, exactly as written. */
static void hash_section_bytes(int sec, basm_sha_ctx *c){
    int pos=0, len=sec_len(sec);
    const uint8_t *buf=sec_buf(sec);
    for(int i=0;i<g_nfile_spans;i++){
        FileSpan *span=&g_file_spans[i];
        if(span->section!=sec) continue;
        if(span->section_offset<pos || span->length>len-span->section_offset)
            die("invalid incbin span");
        if(span->section_offset>pos)
            basm_sha_update(c,buf+pos,(size_t)(span->section_offset-pos));
        /* W07/W11: the writer and proof consume the same frozen bytes. */
        basm_sha_update(c,span->data+(size_t)span->file_offset,(size_t)span->length);
        pos=span->section_offset+(int)span->length;
    }
    if(len>pos) basm_sha_update(c,buf+pos,(size_t)(len-pos));
}
/* W1.2: key loading lives here (not in giant main) to keep main's frame
 * small; failures refuse before any output exists. */
static int load_exec_proof_key(const char *path){
    extern int sign_load_seed(const char *path, uint8_t seed[32]);
    uint8_t eseed[32];
    if (sign_load_seed(path, eseed) != 0) {
        dprintf(2, "basm: WARNING: cannot load exec proof key '%s'\n", path);
        return 1;
    }
    memcpy(g_exec_proof_seed, eseed, 32); g_exec_proof_signed = 1; memset(eseed,0,sizeof(eseed));
    return 0;
}
/* Struct stores need no per-byte bounds checks, unlike indexed put loops:
 * this keeps the proof emitter small enough for the binary budget. */
typedef struct { char name[32]; uint32_t type; uint64_t flags; uint64_t align; } ProofSecEntry;
typedef struct {
    uint32_t magic, version;
    uint8_t src_sha256[32], tool_sha256[32];
    uint32_t nsec;
    ProofSecEntry sec[EXEC_PROOF_MAXSEC];
    uint8_t sec_hash[EXEC_PROOF_MAXSEC][32];
    uint8_t pubkey[32], sig[64];
} ExecProofDesc;
typedef struct { uint32_t namesz, descsz, type; char name[12]; } ProofNoteHead;
static ExecProofDesc g_proof_desc;
static int build_exec_proof_note(uint8_t *out, size_t cap){
    int nsec=g_nsecorder;
    if (nsec<0 || nsec>EXEC_PROOF_MAXSEC) die("exec proof: too many sections");
    /* Entries beyond nsec are never written here; they stay BSS-fresh zeros
     * deterministically because proof mode assembles exactly once per
     * process (batch+proof is refused in main), and dlen covers them. */
    ExecProofDesc *d=&g_proof_desc;
    /* No bulk memset: every byte read below is written explicitly first, so
     * Bear emits stores instead of a 1.4 KiB zero loop. */
    d->magic=EXEC_PROOF_MAGIC; d->version=EXEC_PROOF_VERSION;
    if (!g_attestation_source_ready) die("exec proof: source snapshot missing");
    memcpy(d->src_sha256,g_attestation_source,32);
    if (basm_tool_digest(d->tool_sha256)!=0) die("exec proof: cannot hash tool");
    d->nsec=(uint32_t)nsec;
    /* Pointer walk, not indexed access: no per-iteration bound checks. */
    ProofSecEntry *e=d->sec;
    int *sp=g_secorder;
    for(int i=0;i<nsec;i++,e++,sp++){
        int sec=*sp;
        const char *nm=secname(sec);
        size_t nl=strlen(nm); if(nl>31)nl=31;
        memset(e->name,0,32);
        memcpy(e->name,nm,nl);
        proof_sec_attrs(sec,&e->type,&e->flags,&e->align);
        basm_sha_ctx sc; basm_sha_init(&sc);
        if (sec_has_content(sec)) hash_section_bytes(sec,&sc);
        basm_sha_final(&sc,d->sec_hash[i]);
    }
    memset(d->pubkey,0,32); memset(d->sig,0,64);
    if (g_exec_proof_signed){
        /* Publisher key first: the digest covers the final bytes, pub
         * included (sig field still zero here). Sign-what-you-ship. */
        uint8_t digest[32], sk[64];
        ed25519_keypair_from_seed(g_exec_proof_seed,d->pubkey,sk);
        basm_sha_ctx c; basm_sha_init(&c);
        basm_sha_update(&c,(const uint8_t*)d,(size_t)((const uint8_t*)d->sig-(const uint8_t*)d));
        basm_sha_final(&c,digest);
        if (ed25519_sign(d->sig,digest,32,sk)!=0){ memset(sk,0,sizeof(sk)); die("exec proof: signing failed"); }
        memset(sk,0,sizeof(sk)); memset(digest,0,sizeof(digest));
    }
    int dlen=(int)((const uint8_t*)d->sig+64-(const uint8_t*)d);
    if (sizeof(ProofNoteHead)+(size_t)dlen>cap) return -1;
    ProofNoteHead h;
    h.namesz=12; h.descsz=(uint32_t)dlen; h.type=EXEC_PROOF_NOTETYPE;
    memcpy(h.name,EXEC_PROOF_NAME,9); memset(h.name+9,0,3);
    memcpy(out,&h,sizeof(h)); memcpy(out+sizeof(h),d,(size_t)dlen);
    return (int)(sizeof(h)+(size_t)dlen);
}
