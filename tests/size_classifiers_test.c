/* INV-572: shared classifiers preserve byte-exact membership and boundaries. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "size_inputs.inc"

int char_in(int c, const char *set);
int data_directive_unit(const char *op);
int pp_keyword(const char *p, const char *word, int allow_nul);

static unsigned long checks;

static void require(int got, int expected, const char *what) {
    checks++;
    if (got!=expected) {
        fprintf(stderr,"FAIL %s: got %d expected %d at check %lu\n",what,got,expected,checks);
        exit(1);
    }
}

static int reference_unit(const char *s) {
    if (!strcmp(s,"db")) return 1;
    if (!strcmp(s,"dw")) return 2;
    if (!strcmp(s,"dd")) return 4;
    if (!strcmp(s,"dq")) return 8;
    if (!strcmp(s,"resb")) return -1;
    if (!strcmp(s,"resw")) return -2;
    if (!strcmp(s,"resd")) return -4;
    if (!strcmp(s,"resq")) return -8;
    return 0;
}

static void check_string(const char *s, const char *word) {
    /* Exact allocation puts ASan's redzone immediately after the first NUL. */
    size_t n=strlen(s);
    char *copy=malloc(n+1);
    if (!copy) exit(2);
    memcpy(copy,s,n+1);
    require(data_directive_unit(copy),reference_unit(copy),"data directive");
    size_t wn=strlen(word);
    for (int allow=0;allow<=1;allow++) {
        int expected=0;
        if (n>=wn && !memcmp(copy,word,wn)) {
            int c=(unsigned char)copy[wn];
            expected=c==' ' || c=='\t' || (allow && c==0);
        }
        require(pp_keyword(copy,word,allow),expected,"keyword boundary");
    }
    free(copy);
}

int main(void) {
    for (size_t i=0;i<sizeof(sets)/sizeof(sets[0]);i++) {
        for (int c=-128;c<=255;c++) {
            int expected=0;
            for (const unsigned char *p=(const unsigned char *)sets[i];*p;p++)
                if (*p==(unsigned char)c) expected=1;
            require(char_in(c,sets[i]),expected,"char_in signed/unsigned byte");
            require(char_in((char)c,sets[i]),expected,"char_in plain char");
        }
    }
    for (size_t i=0;i<sizeof(words)/sizeof(words[0]);i++) {
        const char *word=words[i];
        size_t n=strlen(word);
        char s[64];
        if (n+3>sizeof(s)) exit(2);
        check_string(word,word);
        for (size_t cut=0;cut<=n;cut++) {
            memcpy(s,word,cut); s[cut]=0;
            check_string(s,word);
        }
        for (size_t pos=0;pos<=n;pos++) {
            for (int c=0;c<256;c++) {
                memcpy(s,word,n+1); s[n+1]=0; s[pos]=(char)c;
                check_string(s,word);
            }
        }
        /* Exhaust every pair after the keyword, not just one-byte suffixes. */
        for (int a=0;a<256;a++) {
            for (int b=0;b<256;b++) {
                memcpy(s,word,n); s[n]=(char)a; s[n+1]=(char)b; s[n+2]=0;
                check_string(s,word);
            }
        }
    }
    printf("PASS size classifiers: %lu checks (%zu sets, %zu words)\n",
           checks,sizeof(sets)/sizeof(sets[0]),sizeof(words)/sizeof(words[0]));
    return 0;
}
