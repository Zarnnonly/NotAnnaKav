/* Linux CLI: original AnnaKav compression, corrected streaming/padding. */
#define _GNU_SOURCE
#include "../headerUndUtil/sha.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <signal.h>
typedef struct { u32t hash[8]; char *name; } Signature;
static Signature *db;
static size_t count, scanned, matches, skipped;
static volatile sig_atomic_t stopped;
static void stop(int sig) { (void)sig; stopped=1; }
static int hash_file(int fd, u32t h[8]) {
    const u32t init[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(h,init,sizeof(init));
    unsigned char block[64]; size_t used=0; u64t total=0;
    for (;;) {
        if (stopped) return -1;
        ssize_t n=read(fd,block+used,64-used);
        if (n<0) { if(errno==EINTR) continue; return -1; }
        if (!n) break;
        used+=(size_t)n; total+=(u64t)n;
        if(used==64) { MultiSha(block,h,64,0); used=0; }
    }
    block[used++]=0x80;
    if(used>56) { memset(block+used,0,64-used); MultiSha(block,h,64,0); used=0; }
    memset(block+used,0,56-used); total*=8;
    for(int i=0;i<8;i++) block[63-i]=(unsigned char)(total>>(8*i));
    MultiSha(block,h,64,0); return 0;
}
static int load(const char *path) {
    DIR *dir=opendir(path); if(!dir) { perror(path); return -1; }
    struct dirent *e;
    while((e=readdir(dir))) {
        int fd=openat(dirfd(dir),e->d_name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK);
        struct stat st;
        if(fd<0) continue;
        if(fstat(fd,&st)||!S_ISREG(st.st_mode)) { close(fd); continue; }
        unsigned char b[4097]; size_t n=0; ssize_t got=0;
        while(n<sizeof(b)&&(got=read(fd,b+n,sizeof(b)-n))>0) n+=(size_t)got;
        close(fd);
        u32t h[8]={0}; int valid=got>=0;
        if(n==32) {
            for(int i=0;i<8;i++) h[i]=(u32t)b[4*i]|(u32t)b[4*i+1]<<8|(u32t)b[4*i+2]<<16|(u32t)b[4*i+3]<<24;
        } else {
            size_t a=0,z=n;
            while(a<z&&isspace(b[a])) a++;
            while(z>a&&isspace(b[z-1])) z--;
            valid=valid&&z-a==64;
            for(size_t i=0;valid&&i<64;i++) {
                int c=tolower(b[a+i]);
                if(!isxdigit(c)) { valid=0; break; }
                h[i/8]=(h[i/8]<<4)|(u32t)(c<='9'?c-'0':c-'a'+10);
            }
        }
        if(!valid) { fprintf(stderr,"Invalid signature: %s\n",e->d_name); continue; }
        Signature *next=realloc(db,(count+1)*sizeof(*db));
        if(!next) { closedir(dir); return -1; }
        db=next; db[count].name=strdup(e->d_name);
        if(!db[count].name) { closedir(dir); return -1; }
        memcpy(db[count++].hash,h,sizeof(h));
    }
    closedir(dir);
    if(!count) { fputs("No valid signatures\n",stderr); return -1; }
    return 0;
}
static int visit(const char *path,const struct stat *st,int kind,struct FTW *info) {
    (void)info;
    if(stopped) return 1;
    if(kind==FTW_NS||kind==FTW_DNR) { skipped++; fprintf(stderr,"Cannot access: %s\n",path); return 0; }
    if(kind!=FTW_F||!S_ISREG(st->st_mode)) return 0;
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK); struct stat opened; u32t h[8];
    if(fd<0||fstat(fd,&opened)||!S_ISREG(opened.st_mode)||hash_file(fd,h)) {
        if(fd>=0) close(fd);
        if(stopped) return 1;
        skipped++; fprintf(stderr,"Cannot hash: %s\n",path); return 0;
    }
    close(fd); scanned++;
    for(size_t i=0;i<count;i++) if(!memcmp(h,db[i].hash,sizeof(h))) {
        matches++; printf("MATCH\t%s\t%s\t",path,db[i].name);
        for(int j=0;j<8;j++) printf("%08x",h[j]);
        putchar('\n'); break;
    }
    return 0;
}
int main(int argc,char **argv) {
    if(argc==2&&!strcmp(argv[1],"--help")) {
        puts("Usage: annakav-cli TARGET DATABASE_DIRECTORY\nExit: 0 no matches, 1 matches, 2 error/partial, 130 stopped."); return 0;
    }
    if(argc!=3) { fprintf(stderr,"Usage: %s TARGET DATABASE_DIRECTORY\n",argv[0]); return 2; }
    int result=2;
    if(load(argv[2])) goto cleanup;
    signal(SIGINT,stop); signal(SIGTERM,stop);
    int walk=nftw(argv[1],visit,32,FTW_PHYS);
    if(walk<0) perror(argv[1]);
    printf("scanned=%zu matches=%zu skipped=%zu signatures=%zu stopped=%d\n",scanned,matches,skipped,count,(int)stopped);
    result=stopped?130:(walk||skipped)?2:matches?1:0;
cleanup:
    for(size_t i=0;i<count;i++) free(db[i].name);
    free(db); return result;
}
