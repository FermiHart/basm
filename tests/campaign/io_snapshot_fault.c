/* Host-only fault injection for snapshot admission; never a product unit. */
#define main basm_assembly_main
#include "basm.c"
#undef main

extern ssize_t __real_read(int, void *, size_t);
extern ssize_t __real___read_chk(int, void *, size_t, size_t);
extern int __real_fstat(int, struct stat *);
extern int __real_fclose(FILE *);
static const char *mode;
static int target=-1;
static FILE *owned;
static unsigned reads, interrupted, closed, stats;
static size_t total;

static void report(void) {
    fprintf(stderr,"SNAPSHOT_SPY reads=%u interrupted=%u closed=%u stats=%u bytes=%zu\n",
            reads,interrupted,closed,stats,total);
}

ssize_t __wrap_read(int fd, void *data, size_t length) {
    if(fd!=target)return __real_read(fd,data,length);
    reads++;
    if((!strcmp(mode,"eintr") || !strcmp(mode,"short-eintr")) && !interrupted){
        interrupted++;errno=EINTR;return -1;
    }
    if(!strcmp(mode,"read-error") && total){errno=EIO;return -1;}
    if((!strcmp(mode,"short") || !strcmp(mode,"short-eintr") || !strcmp(mode,"read-error")) && length>2)
        length=2;
    ssize_t result=__real_read(fd,data,length);
    if(result>0)total+=(size_t)result;
    return result;
}

/* GCC/glibc may select the fortified entry point for a sized allocation.
 * Keep its bounds check, then apply the same deterministic I/O fault. */
ssize_t __wrap___read_chk(int fd, void *data, size_t length, size_t capacity) {
    if(length>capacity)return __real___read_chk(fd,data,length,capacity);
    return __wrap_read(fd,data,length);
}

int __wrap_fstat(int fd, struct stat *st) {
    int result=__real_fstat(fd,st);
    if(fd!=target || result)return result;
    stats++;
    if(!strcmp(mode,"stat-error")){errno=EIO;return -1;}
    if(!strcmp(mode,"growth"))st->st_size--;
    if(!strcmp(mode,"shrink"))st->st_size++;
    if(!strcmp(mode,"negative"))st->st_size=-1;
    if(!strcmp(mode,"huge"))st->st_size=1LL<<40;
    if(!strcmp(mode,"nonregular"))st->st_mode=0;
    return result;
}

int __wrap_fclose(FILE *stream) {
    int selected=stream==owned;
    int result=__real_fclose(stream);
    if(selected){
        closed++;target=-1;owned=NULL;
        if(!strcmp(mode,"close-error")){errno=EIO;return EOF;}
    }
    return result;
}

int main(int argc,char **argv) {
    if(argc!=4)return 2;
    mode=argv[1];
    FILE *stream=basm_open_regular(argv[2]);
    if(!stream)return 3;
    owned=stream;target=fileno(stream);
    if(atexit(report))return 4;
    int kind=!strcmp(argv[3],"source")?BASM_DEP_SOURCE:BASM_DEP_INCBIN;
    const BasmDependency *dep=basm_snapshot_file(stream,argv[2],kind);
    if(!dep || dep->data[dep->len]!=0 || basm_dependency_count()!=1)return 5;
    printf("{\"bytes\":%zu,\"dependencies\":%zu}\n",dep->len,basm_dependency_count());
    basm_dependencies_reset();
    return 0;
}
