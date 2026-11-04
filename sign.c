/*═══════════════════════════════════════════════════════════════════════════════
 *
 *   ╔═╗╦╔═╗╔╗╔  ─  attestation signing helpers (ADR-0023 Phase 4)
 *   ╚═╗║║ ╦║║║
 *   ╚═╝╩╚═╝╝╚╝
 *
 *   Wraps bear's Ed25519 + SHA-512 implementation in a small surface
 *   that bear-ld, basm, and bearverify can all use to sign / verify
 *   their attestations.
 *
 *   The canonical Ed25519 implementation has a bounded message window, so we
 *   cannot sign multi-KB attestations directly.  We instead
 *   sign their SHA-256 digest (32 bytes; fits trivially under the
 *   1 KiB limit and is the standard approach for sig-over-hash chains).
 *
 *   Output format in the attestation file:
 *
 *       signature_alg: ed25519-over-sha256
 *       signature_pub: <hex 32 bytes>
 *       signature: <hex 64 bytes>
 *
 *   The signed bytes are EVERYTHING in the attestation file from byte 0
 *   UP TO BUT NOT INCLUDING the "signature_alg:" line.  Two-pass:
 *   write the body, hash + sign the body bytes, then append the
 *   signature lines.
 *
 *   Author: F E R M I ∞ H A R T <contact@fermihart.com>
 *   ADR:    0023 (Phase 4)
 *   SPDX-License-Identifier: Unlicense
 *
 *═══════════════════════════════════════════════════════════════════════════════*/

/* INV-SIGN-POSIX-DECL-001: this provider uses fileno/fstat in strict C11 TUs. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "sign.h"
#include <crypto/ed25519.h>   /* canonical Ed25519 tree, linked from ../../crypto/ed25519.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

/* ── SHA-256 (FIPS 180-4) — also duplicated in the three tools; central
 *    here so a future refactor pulls it from one place.  Identical to the
 *    bear-ld / basm / bearverify copies. */
/* SHA-256 (FIPS 180-4) with runtime SHA-NI dispatch.
 * Centralised in sha256_ni.h and imported here with the sgn_ namespace. */
#define SHA256NI_CTX_TYPE sgn_sha
#define SHA256NI_PREFIX   sgn_
#include "sha256_ni.h"

/* Keep the historical "finalise" spelling used throughout sign.c. */
static void sgn_finalise(sgn_sha *c, uint8_t out[32]) { sgn_final(c, out); }

/* ── helpers ──────────────────────────────────────────────────────────── */
static void sgn_hex(const uint8_t *in, int n, char *out) {
    static const char H[]="0123456789abcdef";
    for (int i=0;i<n;i++){out[i*2]=H[in[i]>>4]; out[i*2+1]=H[in[i]&15];}
    out[n*2]=0;
}
static int sgn_unhex(const char *in, uint8_t *out, int n) {
    for (int i=0;i<n;i++) {
        int hi=-1, lo=-1;
        char c = in[i*2];
        if (c>='0'&&c<='9') hi=c-'0'; else if (c>='a'&&c<='f') hi=10+c-'a';
        else if (c>='A'&&c<='F') hi=10+c-'A';
        c = in[i*2+1];
        if (c>='0'&&c<='9') lo=c-'0'; else if (c>='a'&&c<='f') lo=10+c-'a';
        else if (c>='A'&&c<='F') lo=10+c-'A';
        if (hi<0||lo<0) return -1;
        out[i] = (uint8_t)((hi<<4)|lo);
    }
    return 0;
}

/* W09: evidence is bounded before allocation, and trailer framing is parsed once
 * from the same immutable bytes whose digest is verified. Reserved signature
 * fields are an ordered, single-valued suffix, never a substring of a value. */
typedef struct {
    size_t body_len;
    int is_signed;
    uint8_t pub[32], sig[64];
} SgnTrailer;

static void sgn_wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

static int sgn_line(const char *p,size_t n,const char *key,const char **value,size_t *vlen) {
    size_t k=strlen(key);
    if(n<k+2 || memcmp(p,key,k) || p[k]!=':' || p[k+1]!=' ')return 0;
    *value=p+k+2; *vlen=n-k-2; return 1;
}

static int sgn_exact_hex(const char *p,size_t n,uint8_t *out,int bytes) {
    return n==(size_t)bytes*2 && sgn_unhex(p,out,bytes)==0;
}

static int sgn_parse_trailer(const char *body,size_t len,SgnTrailer *trailer) {
    if(!body || !len || len>SIGN_ATTESTATION_MAX_BYTES || body[len-1]!='\n' ||
       memchr(body,0,len))return -1;
    memset(trailer,0,sizeof(*trailer));
    size_t off=0; int state=0;
    while(off<len){
        const char *p=body+off,*nl=(const char*)memchr(p,'\n',len-off);
        if(!nl)return -1;
        size_t n=(size_t)(nl-p),vlen=0; const char *v=NULL;
        if(!n || n>4096)return -1;
        if(!state){
            if(n<10 || (memcmp(p,"signature:",10) && memcmp(p,"signature_",10))){
                off+=(size_t)n+1; continue;
            }
            trailer->body_len=off;
            if(!off)return -1;
            if(sgn_line(p,n,"signature",&v,&vlen) && vlen==8 && !memcmp(v,"unsigned",8)){
                return off+n+1==len ? 0 : -1;
            }
            if(!sgn_line(p,n,"signature_alg",&v,&vlen) ||
               vlen!=19 || memcmp(v,"ed25519-over-sha256",19))return -1;
            state=1;
        }else if(state==1){
            if(!sgn_line(p,n,"signature_pub",&v,&vlen) ||
               !sgn_exact_hex(v,vlen,trailer->pub,32))return -1;
            state=2;
        }else if(state==2){
            if(!sgn_line(p,n,"signature",&v,&vlen) ||
               !sgn_exact_hex(v,vlen,trailer->sig,64))return -1;
            trailer->is_signed=1; state=3;
        }else if(state==3){
            if(!sgn_line(p,n,"signature_pqc_alg",&v,&vlen) ||
               vlen!=22 || memcmp(v,"dilithium3-placeholder",22))return -1;
            state=4;
        }else if(state==4){
            uint8_t ignored[32];
            if(!sgn_line(p,n,"signature_pqc_pub",&v,&vlen) ||
               !sgn_exact_hex(v,vlen,ignored,32))return -1;
            state=5;
        }else if(state==5){
            uint8_t ignored[64];
            if(!sgn_line(p,n,"signature_pqc",&v,&vlen) ||
               !sgn_exact_hex(v,vlen,ignored,64))return -1;
            state=6;
        }else return -1;
        off+=n+1;
    }
    return state==3 || state==6 ? 0 : -1;
}

int sign_attestation_signature_state(const char *body,size_t len) {
    SgnTrailer trailer;
    return sgn_parse_trailer(body,len,&trailer)==0 ? trailer.is_signed : -1;
}

/* The preflight rejects a static FIFO/device without opening it. An actively
 * hostile directory replacement before fopen is outside this pathname API's
 * contract. fstat confirms the same regular inode and the stated size cap. */
static FILE *sgn_open_regular(const char *path,uint64_t cap,uint64_t *size) {
    struct stat before,after;
    if(!path || stat(path,&before)!=0 || !S_ISREG(before.st_mode) || before.st_size<0 ||
       (uint64_t)before.st_size>cap)return NULL;
    FILE *f=fopen(path,"rb");if(!f)return NULL;
    if(fstat(fileno(f),&after)!=0 || !S_ISREG(after.st_mode) || after.st_size<0 ||
       (uint64_t)after.st_size>cap || before.st_dev!=after.st_dev || before.st_ino!=after.st_ino){
        fclose(f);return NULL;
    }
    if(size)*size=(uint64_t)after.st_size;
    return f;
}

static char *sgn_read_file(const char *path,size_t *len) {
    FILE *f=sgn_open_regular(path,SIGN_ATTESTATION_MAX_BYTES,NULL);if(!f)return NULL;
    if(fseek(f,0,SEEK_END)!=0){fclose(f);return NULL;}
    long sz=ftell(f);
    if(sz<=0 || (unsigned long long)sz>SIGN_ATTESTATION_MAX_BYTES ||
       fseek(f,0,SEEK_SET)!=0){fclose(f);return NULL;}
    char *body=(char*)malloc((size_t)sz+1);
    if(!body){fclose(f);return NULL;}
    size_t got=fread(body,1,(size_t)sz,f);
    int extra=fgetc(f),bad=ferror(f);
    if(fclose(f)!=0)bad=1;
    if(got!=(size_t)sz || extra!=EOF || bad){free(body);return NULL;}
    body[sz]=0; *len=(size_t)sz; return body;
}

/* The same strict bounded wire form is used for a secret seed and for a public
 * trust anchor. The public-key function does not derive a key from a seed. */
static int sgn_load_key32(const char *path,uint8_t key[32]) {
    FILE *f=sgn_open_regular(path,128,NULL);if(!f)return -1;
    uint8_t buf[129],value[32]; size_t n=fread(buf,1,sizeof(buf),f);
    int bad=ferror(f); if(fclose(f)!=0)bad=1;
    int ok=0;
    if(!bad && n==32){memcpy(value,buf,32);ok=1;}
    else if(!bad && n>=64 && n<=128){
        ok=1;
        for(size_t i=64;i<n;i++)if(buf[i]!='\n' && buf[i]!='\r' && buf[i]!=' ' && buf[i]!='\t')ok=0;
        if(sgn_unhex((const char*)buf,value,32)!=0)ok=0;
    }
    if(ok)memcpy(key,value,32);
    sgn_wipe(buf,sizeof(buf));sgn_wipe(value,sizeof(value));
    return ok?0:-1;
}
int sign_load_seed(const char *path,uint8_t seed[32]) { return sgn_load_key32(path,seed); }
int sign_load_public_key(const char *path,uint8_t pub[32]) { return sgn_load_key32(path,pub); }

int sign_attestation_buffer(const char *body,size_t len,const uint8_t seed[32],
                            char **out,size_t *out_len) {
    SgnTrailer trailer;
    if(!seed || !out || !out_len || sgn_parse_trailer(body,len,&trailer)!=0 ||
       trailer.body_len>SIGN_ATTESTATION_MAX_BYTES-1024)return -1;
    *out=NULL;*out_len=0;
    uint8_t digest[32],pk[ED25519_PUBKEY],sk[ED25519_SECKEY],sig[ED25519_SIG];
    sgn_sha c;sgn_init(&c);sgn_update(&c,body,trailer.body_len);sgn_finalise(&c,digest);
    ed25519_keypair_from_seed(seed,pk,sk);
    int signed_ok=ed25519_sign(sig,digest,32,sk)==0;
    sgn_wipe(sk,sizeof(sk));
    if(!signed_ok){sgn_wipe(digest,sizeof(digest));return -1;}
    size_t cap=trailer.body_len+1024;
    char *result=(char*)malloc(cap);
    if(!result){sgn_wipe(digest,sizeof(digest));return -1;}
    memcpy(result,body,trailer.body_len);
    char pk_hex[65],sig_hex[129];sgn_hex(pk,32,pk_hex);sgn_hex(sig,64,sig_hex);
    int n=snprintf(result+trailer.body_len,cap-trailer.body_len,
                   "signature_alg: ed25519-over-sha256\nsignature_pub: %s\nsignature: %s\n",pk_hex,sig_hex);
    if(n<0 || (size_t)n>=cap-trailer.body_len){free(result);sgn_wipe(digest,32);return -1;}
    size_t used=trailer.body_len+(size_t)n;
    /* Legacy v2/v3 keep their explicit placeholder framing for wire parity.
     * V4 emits only the real Ed25519 evidence. These bytes grant no PQC claim. */
    if(len<20 || memcmp(body,"basm attestation v4\n",20)){
        uint8_t pqc_seed[32],pqc_pub[32],pqc_sig[64];
        sgn_sha x;sgn_init(&x);sgn_update(&x,digest,32);sgn_update(&x,seed,32);sgn_finalise(&x,pqc_seed);
        sgn_init(&x);sgn_update(&x,seed,32);sgn_update(&x,pqc_seed,32);sgn_finalise(&x,pqc_pub);
        sgn_init(&x);sgn_update(&x,pqc_seed,32);sgn_update(&x,digest,32);sgn_finalise(&x,pqc_sig);
        sgn_init(&x);sgn_update(&x,pqc_sig,32);sgn_update(&x,pqc_seed,32);sgn_finalise(&x,pqc_sig+32);
        char ph[65],sh[129];sgn_hex(pqc_pub,32,ph);sgn_hex(pqc_sig,64,sh);
        n=snprintf(result+used,cap-used,"signature_pqc_alg: dilithium3-placeholder\nsignature_pqc_pub: %s\nsignature_pqc: %s\n",ph,sh);
        sgn_wipe(pqc_seed,sizeof(pqc_seed));sgn_wipe(pqc_sig,sizeof(pqc_sig));
        if(n<0 || (size_t)n>=cap-used){free(result);sgn_wipe(digest,32);return -1;}
        used+=(size_t)n;
    }
    sgn_wipe(digest,sizeof(digest));
    *out=result;*out_len=used;return 0;
}

static FILE *sgn_tmp_open(const char *path,char *tmp,size_t cap) {
    for(unsigned attempt=0;attempt<32;attempt++){
        int n=snprintf(tmp,cap,"%s.sign.%ld.%u",path,(long)getpid(),attempt);
        if(n<0 || (size_t)n>=cap)return NULL;
        FILE *f=fopen(tmp,"wbex");
        if(f)return f;
        if(errno!=EEXIST)return NULL;
    }
    return NULL;
}

/* W10: standalone signing preserves the old file until a complete signed
 * replacement has closed successfully. It never truncates a guessed temp. */
int sign_finalise_attestation(const char *path,const uint8_t seed[32]) {
    size_t len=0,out_len=0;char *body=sgn_read_file(path,&len),*signed_body=NULL;
    if(!body)return -1;
    int rc=sign_attestation_buffer(body,len,seed,&signed_body,&out_len);free(body);
    if(rc!=0)return -1;
    char tmp[4160];FILE *f=sgn_tmp_open(path,tmp,sizeof(tmp));
    if(!f){free(signed_body);return -1;}
    int ok=fwrite(signed_body,1,out_len,f)==out_len;
    if(fclose(f)!=0)ok=0;
    free(signed_body);
    if(!ok || rename(tmp,path)!=0){remove(tmp);return -1;}
    return 0;
}

int sign_verify_attestation_buffer(const char *body,size_t len,
                                   const uint8_t expected_pub[32],uint8_t out_pub[32]) {
    SgnTrailer trailer;
    if(sgn_parse_trailer(body,len,&trailer)!=0 || !trailer.is_signed)return -1;
    if(expected_pub){
        uint8_t diff=0;for(int i=0;i<32;i++)diff|=(uint8_t)(expected_pub[i]^trailer.pub[i]);
        if(diff)return -1;
    }
    uint8_t digest[32];sgn_sha c;sgn_init(&c);sgn_update(&c,body,trailer.body_len);sgn_finalise(&c,digest);
    int rc=ed25519_verify(trailer.sig,digest,32,trailer.pub);
    if(rc==0 && out_pub)memcpy(out_pub,trailer.pub,32);
    return rc==0?0:-1;
}

int sign_verify_attestation_trusted(const char *path,const uint8_t expected_pub[32],uint8_t out_pub[32]) {
    size_t len=0;char *body=sgn_read_file(path,&len);if(!body)return -1;
    int rc=sign_verify_attestation_buffer(body,len,expected_pub,out_pub);free(body);return rc;
}
int sign_verify_attestation(const char *path,uint8_t out_pub[32]) {
    return sign_verify_attestation_trusted(path,NULL,out_pub);
}

/* ═════════════════════════════════════════════════════════════════════════
 * ADR-0025 (S3 EMBED) — utilities exported for bear-ld and bearverify
 * ═════════════════════════════════════════════════════════════════════════ */

void sign_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    sgn_sha c; sgn_init(&c);
    sgn_update(&c, data, len);
    sgn_finalise(&c, out);
}

int sign_core_sha256(const char *elf_path,
                     uint64_t payload_off, uint32_t payload_len,
                     uint8_t out[32]) {
    if (payload_len && payload_off > UINT64_MAX - (uint64_t)payload_len) return -1;
    uint64_t size=0;
    FILE *f = sgn_open_regular(elf_path,(uint64_t)1<<30,&size);
    if (!f) return -1;
    sgn_sha c; sgn_init(&c);

    uint8_t buf[4096];
    uint64_t pos = 0;

    /* Stream the ELF byte-for-byte; whenever a chunk overlaps the payload
     * window, substitute zeros for the overlap before hashing.  This must
     * be byte-identical to the digest a third party gets by independently
     * locating the .note.soberania payload and zeroing it on disk. */
    int bad=0;
    while (pos<size) {
        size_t want = size-pos>sizeof(buf)?sizeof(buf):(size_t)(size-pos);
        size_t got = fread(buf, 1, want, f);
        if (got != want) { bad=1; break; }

        if (payload_len > 0) {
            uint64_t chunk_start = pos;
            uint64_t chunk_end   = pos + (uint64_t)got;
            uint64_t pl_end      = payload_off + (uint64_t)payload_len;
            uint64_t ov_start = (chunk_start > payload_off) ? chunk_start : payload_off;
            uint64_t ov_end   = (chunk_end   < pl_end)      ? chunk_end   : pl_end;
            if (ov_end > ov_start) {
                size_t s = (size_t)(ov_start - chunk_start);
                size_t n = (size_t)(ov_end   - ov_start);
                memset(buf + s, 0, n);
            }
        }

        sgn_update(&c, buf, got);
        pos += (uint64_t)got;
    }

    if(!bad && fgetc(f)!=EOF)bad=1;
    if(ferror(f))bad=1;
    if (fclose(f) != 0) bad = 1;
    if (payload_len && (payload_off > pos || (uint64_t)payload_len > pos - payload_off)) bad = 1;
    if (bad) return -1;
    sgn_finalise(&c, out);
    return 0;
}
