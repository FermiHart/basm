/* Host-only alias-check harness. It never emits an object. */
#define main basm_assembly_main
#include "basm.c"
#undef main

extern int __real_stat(const char *, struct stat *);
static const char *watched;
static char parent_path[1050];
static unsigned output_stats, parent_stats;

int __wrap_stat(const char *path, struct stat *st) {
    if(watched && !strcmp(path,watched))output_stats++;
    if(watched && !strcmp(path,parent_path))parent_stats++;
    return __real_stat(path,st);
}
static void report(void) {
    fprintf(stderr,"PATH_SPY output_stats=%u parent_stats=%u\n",output_stats,parent_stats);
}
int main(int argc,char **argv) {
    if(argc<5)return 2;
    watched=argv[2];
    const char *slash=strrchr(watched,'/');
    size_t length=slash?(size_t)(slash-watched):0;
    if(length>=sizeof(parent_path))return 3;
    if(!slash)strcpy(parent_path,".");
    else if(!length)strcpy(parent_path,"/");
    else {memcpy(parent_path,watched,length);parent_path[length]=0;}
    if(atexit(report))return 4;
    const char *attest=strcmp(argv[3],"-")?argv[3]:NULL;
    if(!strcmp(argv[1],"secrets")){
        g_exec_sign_key=argc>6?argv[6]:NULL;
        output_secret_paths_check(watched,attest,argv[4],argc>5?argv[5]:NULL);
    }else{
        for(int i=4;i<argc;i++)basm_snapshot_record(argv[i],"",0,BASM_DEP_SOURCE);
        output_paths_check(watched,attest);
        if(!strcmp(argv[1],"phase-change")){
            if(link(argv[4],watched))return 5;
            output_paths_check(watched,attest);
            return 6; /* the refreshed check must refuse the newly linked alias */
        }
        basm_dependencies_reset();
    }
    puts("PATH_CHECK_OK");
    return 0;
}
