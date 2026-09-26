/* r2r-relay — single-file C implementation of the R2R relay (RELAY-SPEC.md v1).
 *
 * Build:   cc -O2 -o r2r-relay relay-server.c -lpthread
 * Run:     ./r2r-relay                (prints the ws://IP:PORT line to paste into the app)
 * Options: PORT=8787 DATA_DIR=./r2r-relay-data BLOB_TTL_DAYS=30 QUEUE_TTL_DAYS=30
 *          TURN_URL=turn:1.2.3.4:3478 TURN_USER=u TURN_PASS=p   (all via env)
 *
 * Zero dependencies (POSIX + pthreads). Everything it stores is end-to-end ciphertext.
 * Crypto embedded: SHA-1 (WebSocket handshake), SHA-512 (blob ids + ed25519),
 * ed25519 verify (transliterated from TweetNaCl, public domain). Self-tests run at startup.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdarg.h>

typedef unsigned char u8; typedef uint32_t u32; typedef uint64_t u64; typedef int64_t i64;

/* ================= SHA-512 ================= */
static const u64 SHA512_K[80]={
0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL};
static const u64 SHA512_IV[8]={
0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};
typedef struct { u64 h[8]; u8 buf[128]; u64 len; size_t fill; } sha512_ctx;
static u64 ROTR64(u64 x,int n){ return (x>>n)|(x<<(64-n)); }
static void sha512_block(sha512_ctx*c,const u8*p){
  u64 w[80],a,b,d,e,f,g,h,t1,t2,cc; int i;
  for(i=0;i<16;i++) w[i]=((u64)p[i*8]<<56)|((u64)p[i*8+1]<<48)|((u64)p[i*8+2]<<40)|((u64)p[i*8+3]<<32)|((u64)p[i*8+4]<<24)|((u64)p[i*8+5]<<16)|((u64)p[i*8+6]<<8)|((u64)p[i*8+7]);
  for(i=16;i<80;i++){ u64 s0=ROTR64(w[i-15],1)^ROTR64(w[i-15],8)^(w[i-15]>>7);
    u64 s1=ROTR64(w[i-2],19)^ROTR64(w[i-2],61)^(w[i-2]>>6); w[i]=w[i-16]+s0+w[i-7]+s1; }
  a=c->h[0];b=c->h[1];cc=c->h[2];d=c->h[3];e=c->h[4];f=c->h[5];g=c->h[6];h=c->h[7];
  for(i=0;i<80;i++){
    u64 S1=ROTR64(e,14)^ROTR64(e,18)^ROTR64(e,41);
    u64 ch=(e&f)^((~e)&g);
    t1=h+S1+ch+SHA512_K[i]+w[i];
    u64 S0=ROTR64(a,28)^ROTR64(a,34)^ROTR64(a,39);
    u64 mj=(a&b)^(a&cc)^(b&cc);
    t2=S0+mj;
    h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;
  }
  c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;c->h[4]+=e;c->h[5]+=f;c->h[6]+=g;c->h[7]+=h;
}
static void sha512_init(sha512_ctx*c){ memcpy(c->h,SHA512_IV,sizeof c->h); c->len=0; c->fill=0; }
static void sha512_update(sha512_ctx*c,const u8*d,size_t n){
  c->len+=n;
  while(n){ size_t k=128-c->fill; if(k>n)k=n; memcpy(c->buf+c->fill,d,k); c->fill+=k; d+=k; n-=k;
    if(c->fill==128){ sha512_block(c,c->buf); c->fill=0; } }
}
static void sha512_final(sha512_ctx*c,u8 out[64]){
  u64 bits=c->len*8; int i;
  u8 pad=0x80; sha512_update(c,&pad,1);
  u8 z=0; while(c->fill!=112) sha512_update(c,&z,1);
  u8 lenb[16]; memset(lenb,0,8);
  for(i=0;i<8;i++) lenb[8+i]=(u8)(bits>>(56-8*i));
  sha512_update(c,lenb,16);
  for(i=0;i<8;i++){ out[i*8]=(u8)(c->h[i]>>56); out[i*8+1]=(u8)(c->h[i]>>48); out[i*8+2]=(u8)(c->h[i]>>40); out[i*8+3]=(u8)(c->h[i]>>32); out[i*8+4]=(u8)(c->h[i]>>24); out[i*8+5]=(u8)(c->h[i]>>16); out[i*8+6]=(u8)(c->h[i]>>8); out[i*8+7]=(u8)c->h[i]; }
}
static void sha512(u8 out[64],const u8*d,size_t n){ sha512_ctx c; sha512_init(&c); sha512_update(&c,d,n); sha512_final(&c,out); }

/* ================= SHA-1 (WebSocket handshake only) ================= */
static u32 ROTL32(u32 x,int n){ return (x<<n)|(x>>(32-n)); }
static void sha1(u8 out[20],const u8*data,size_t len){
  u32 h[5]={0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0};
  u64 ml=(u64)len*8; size_t total=((len+8)/64+1)*64;
  u8*m=calloc(total,1); memcpy(m,data,len); m[len]=0x80;
  for(int i=0;i<8;i++) m[total-1-i]=(u8)(ml>>(8*i));
  for(size_t off=0;off<total;off+=64){
    u32 w[80];
    for(int i=0;i<16;i++) w[i]=((u32)m[off+i*4]<<24)|((u32)m[off+i*4+1]<<16)|((u32)m[off+i*4+2]<<8)|m[off+i*4+3];
    for(int i=16;i<80;i++) w[i]=ROTL32(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
    u32 a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
    for(int i=0;i<80;i++){
      u32 f,k;
      if(i<20){f=(b&c)|((~b)&d);k=0x5A827999;}
      else if(i<40){f=b^c^d;k=0x6ED9EBA1;}
      else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDC;}
      else{f=b^c^d;k=0xCA62C1D6;}
      u32 t=ROTL32(a,5)+f+e+k+w[i]; e=d;d=c;c=ROTL32(b,30);b=a;a=t;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;
  }
  free(m);
  for(int i=0;i<5;i++){ out[i*4]=(u8)(h[i]>>24); out[i*4+1]=(u8)(h[i]>>16); out[i*4+2]=(u8)(h[i]>>8); out[i*4+3]=(u8)h[i]; }
}

/* ================= ed25519 verify (TweetNaCl, public domain) ================= */
typedef i64 gf[16];
static const gf gf0={0}, gf1={1};
static const gf D={0x78a3,0x1359,0x4dca,0x75eb,0xd8ab,0x4141,0x0a4d,0x0070,0xe898,0x7779,0x4079,0x8cc7,0xfe73,0x2b6f,0x6cee,0x5203};
static const gf D2={0xf159,0x26b2,0x9b94,0xebd6,0xb156,0x8283,0x149a,0x00e0,0xd130,0xeef3,0x80f2,0x198e,0xfce7,0x56df,0xd9dc,0x2406};
static const gf Xb={0xd51a,0x8f25,0x2d60,0xc956,0xa7b2,0x9525,0xc760,0x692c,0xdc5c,0xfdd6,0xe231,0xc0a4,0x53fe,0xcd6e,0x36d3,0x2169};
static const gf Yb={0x6658,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666};
static const gf Ico={0xa0b0,0x4a0e,0x1b27,0xc4ee,0xe478,0xad2f,0x1806,0x2f43,0xd7a7,0x3dfb,0x0099,0x2b4d,0xdf0b,0x4fc1,0x2480,0x2b83};
static const u8 L[32]={0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10};
static void set25519(gf r,const gf a){ for(int i=0;i<16;i++) r[i]=a[i]; }
static void car25519(gf o){ i64 c=1; for(int i=0;i<16;i++){ i64 v=o[i]+c+65535; c=v>>16; o[i]=v-(c<<16); } o[0]+=c-1+37*(c-1); }
static void sel25519(gf p,gf q,int b){ i64 t,c=~(i64)(b-1); for(int i=0;i<16;i++){ t=c&(p[i]^q[i]); p[i]^=t; q[i]^=t; } }
static void pack25519(u8*o,const gf n){
  int i,j,b; gf m,t;
  for(i=0;i<16;i++) t[i]=n[i];
  car25519(t); car25519(t); car25519(t);
  for(j=0;j<2;j++){
    m[0]=t[0]-0xffed;
    for(i=1;i<15;i++){ m[i]=t[i]-0xffff-((m[i-1]>>16)&1); m[i-1]&=0xffff; }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1);
    b=(int)((m[15]>>16)&1); m[14]&=0xffff;
    sel25519(t,m,1-b);
  }
  for(i=0;i<16;i++){ o[2*i]=(u8)(t[i]&0xff); o[2*i+1]=(u8)(t[i]>>8); }
}
static void unpack25519(gf o,const u8*n){ for(int i=0;i<16;i++) o[i]=n[2*i]+((i64)n[2*i+1]<<8); o[15]&=0x7fff; }
static void Ag(gf o,const gf a,const gf b){ for(int i=0;i<16;i++) o[i]=a[i]+b[i]; }
static void Zg(gf o,const gf a,const gf b){ for(int i=0;i<16;i++) o[i]=a[i]-b[i]; }
static void Mg(gf o,const gf a,const gf b){
  i64 t[31]; int i,j;
  for(i=0;i<31;i++) t[i]=0;
  for(i=0;i<16;i++) for(j=0;j<16;j++) t[i+j]+=a[i]*b[j];
  for(i=0;i<15;i++) t[i]+=38*t[i+16];
  for(i=0;i<16;i++) o[i]=t[i];
  car25519(o); car25519(o);
}
static void Sg(gf o,const gf a){ Mg(o,a,a); }
static void inv25519(gf o,const gf i){ gf c; int a; set25519(c,i); for(a=253;a>=0;a--){ Sg(c,c); if(a!=2&&a!=4) Mg(c,c,i); } set25519(o,c); }
static void pow2523(gf o,const gf i){ gf c; int a; set25519(c,i); for(a=250;a>=0;a--){ Sg(c,c); if(a!=1) Mg(c,c,i); } set25519(o,c); }
static int vn(const u8*x,const u8*y,int n){ u32 d=0; for(int i=0;i<n;i++) d|=x[i]^y[i]; return (1&((d-1)>>8))-1; }
static int neq25519(const gf a,const gf b){ u8 c[32],d[32]; pack25519(c,a); pack25519(d,b); return vn(c,d,32); }
static u8 par25519(const gf a){ u8 d[32]; pack25519(d,a); return d[0]&1; }
static int unpackneg(gf r[4],const u8 p[32]){
  gf t,chk,num,den,den2,den4,den6;
  set25519(r[2],gf1); unpack25519(r[1],p);
  Sg(num,r[1]); Mg(den,num,D); Zg(num,num,r[2]); Ag(den,r[2],den);
  Sg(den2,den); Sg(den4,den2); Mg(den6,den4,den2); Mg(t,den6,num); Mg(t,t,den);
  pow2523(t,t); Mg(t,t,num); Mg(t,t,den); Mg(t,t,den); Mg(r[0],t,den);
  Sg(chk,r[0]); Mg(chk,chk,den); if(neq25519(chk,num)) Mg(r[0],r[0],Ico);
  Sg(chk,r[0]); Mg(chk,chk,den); if(neq25519(chk,num)) return -1;
  if(par25519(r[0])==(p[31]>>7)) Zg(r[0],gf0,r[0]);
  Mg(r[3],r[0],r[1]);
  return 0;
}
static void addp(gf p[4],gf q[4]){
  gf a,b,c,d,t,e,f,g,h;
  Zg(a,p[1],p[0]); Zg(t,q[1],q[0]); Mg(a,a,t);
  Ag(b,p[0],p[1]); Ag(t,q[0],q[1]); Mg(b,b,t);
  Mg(c,p[3],q[3]); Mg(c,c,D2);
  Mg(d,p[2],q[2]); Ag(d,d,d);
  Zg(e,b,a); Zg(f,d,c); Ag(g,d,c); Ag(h,b,a);
  Mg(p[0],e,f); Mg(p[1],h,g); Mg(p[2],g,f); Mg(p[3],e,h);
}
static void cswap(gf p[4],gf q[4],u8 b){ for(int i=0;i<4;i++) sel25519(p[i],q[i],b); }
static void packp(u8*r,gf p[4]){ gf tx,ty,zi; inv25519(zi,p[2]); Mg(tx,p[0],zi); Mg(ty,p[1],zi); pack25519(r,ty); r[31]^=par25519(tx)<<7; }
static void scalarmult(gf p[4],gf q[4],const u8*s){
  set25519(p[0],gf0); set25519(p[1],gf1); set25519(p[2],gf1); set25519(p[3],gf0);
  for(int i=255;i>=0;--i){ u8 b=(s[i/8]>>(i&7))&1; cswap(p,q,b); addp(q,p); addp(p,p); cswap(p,q,b); }
}
static void scalarbase(gf p[4],const u8*s){ gf q[4]; set25519(q[0],Xb); set25519(q[1],Yb); set25519(q[2],gf1); Mg(q[3],Xb,Yb); scalarmult(p,q,s); }
static void modL(u8*r,i64 x[64]){
  i64 carry; int i,j;
  for(i=63;i>=32;--i){
    carry=0;
    for(j=i-32;j<i-12;++j){ x[j]+=carry-16*x[i]*L[j-(i-32)]; carry=(x[j]+128)>>8; x[j]-=carry<<8; }
    x[j]+=carry; x[i]=0;
  }
  carry=0;
  for(j=0;j<32;++j){ x[j]+=carry-(x[31]>>4)*L[j]; carry=x[j]>>8; x[j]&=255; }
  for(j=0;j<32;++j) x[j]-=carry*L[j];
  for(i=0;i<32;++i){ x[i+1]+=x[i]>>8; r[i]=(u8)(x[i]&255); }
}
static void reduce64(u8 r[64]){ i64 x[64]; int i; for(i=0;i<64;i++){ x[i]=(u64)r[i]; r[i]=0; } modL(r,x); }
/* verify sig(64) by pk(32) over msg */
static int ed25519_verify(const u8*msg,size_t n,const u8 sig[64],const u8 pk[32]){
  u8 t[32],h[64]; gf p[4],q[4];
  if(unpackneg(q,pk)) return 0;
  sha512_ctx c; sha512_init(&c);
  sha512_update(&c,sig,32); sha512_update(&c,pk,32); sha512_update(&c,msg,n);
  sha512_final(&c,h);
  reduce64(h);
  scalarmult(p,q,h);
  scalarbase(q,sig+32);
  addp(p,q);
  packp(t,p);
  return vn(sig,t,32)==0;
}

/* ================= small utils ================= */
static const char*B64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void b64enc(char*out,const u8*in,int n){
  int i,o=0;
  for(i=0;i+2<n;i+=3){ out[o++]=B64[in[i]>>2]; out[o++]=B64[((in[i]&3)<<4)|(in[i+1]>>4)]; out[o++]=B64[((in[i+1]&15)<<2)|(in[i+2]>>6)]; out[o++]=B64[in[i+2]&63]; }
  if(i<n){ out[o++]=B64[in[i]>>2];
    if(i+1<n){ out[o++]=B64[((in[i]&3)<<4)|(in[i+1]>>4)]; out[o++]=B64[(in[i+1]&15)<<2]; }
    else { out[o++]=B64[(in[i]&3)<<4]; out[o++]='='; }
    out[o++]='='; }
  out[o]=0;
}
static int hexval(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
static int unhex(u8*out,const char*s,int bytes){ for(int i=0;i<bytes;i++){ int a=hexval(s[i*2]),b=hexval(s[i*2+1]); if(a<0||b<0) return 0; out[i]=(u8)((a<<4)|b); } return 1; }
static void tohex(char*out,const u8*in,int n){ for(int i=0;i<n;i++) sprintf(out+i*2,"%02x",in[i]); }
static int is_hex(const char*s,int len){ if((int)strlen(s)!=len) return 0; for(int i=0;i<len;i++) if(hexval(s[i])<0) return 0; return 1; }
static u64 now_ms(void){ struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts); return (u64)ts.tv_sec*1000+ts.tv_nsec/1000000; }

/* ================= config / state ================= */
static int PORT=8787;
static char DATADIR[512]="./r2r-relay-data";
static double BLOB_TTL_DAYS=30, QUEUE_TTL_DAYS=30;
static double DEFAULT_QUOTA_MB=1;      /* per-account journal storage; owner raises via admin key */
static char ADMIN_KEY[65]={0};
static int IP_REQS_PER_MIN=240;   /* pre-auth per-IP limiter; env-overridable; loopback exempt */
#define IPRATE_SLOTS 512
static struct { char ip[46]; time_t win; int n; } IPRATE[IPRATE_SLOTS];
static pthread_mutex_t IPRATE_MU=PTHREAD_MUTEX_INITIALIZER;
/* fixed-window count per hashed IP slot, checked BEFORE signature verification
   (anti CPU-flood). Hash collisions share a bucket — acceptable for this scale. */
static int ip_ok(int fd){
  struct sockaddr_storage sa; socklen_t sl=sizeof sa; char ip[46]="";
  if(getpeername(fd,(struct sockaddr*)&sa,&sl)) return 1;
  if(sa.ss_family==AF_INET) inet_ntop(AF_INET,&((struct sockaddr_in*)&sa)->sin_addr,ip,sizeof ip);
  else if(sa.ss_family==AF_INET6) inet_ntop(AF_INET6,&((struct sockaddr_in6*)&sa)->sin6_addr,ip,sizeof ip);
  if(!ip[0]||!strcmp(ip,"127.0.0.1")||!strcmp(ip,"::1")||!strcmp(ip,"::ffff:127.0.0.1")) return 1;
  unsigned h=5381; for(char*p=ip;*p;p++) h=h*33+(unsigned char)*p;
  time_t now=time(NULL); int ok=1; int i=h%IPRATE_SLOTS;
  pthread_mutex_lock(&IPRATE_MU);
  if(strcmp(IPRATE[i].ip,ip)||now-IPRATE[i].win>=60){ snprintf(IPRATE[i].ip,sizeof IPRATE[i].ip,"%s",ip); IPRATE[i].win=now; IPRATE[i].n=0; }
  if(++IPRATE[i].n>IP_REQS_PER_MIN) ok=0;
  pthread_mutex_unlock(&IPRATE_MU);
  return ok;
}
#define MAX_BLOB (17*1024*1024)
#define MAX_EVENT (600*1024)
#define MAX_PAYLOAD (64*1024)
#define MAX_CLIENTS 4096
static u64 T0;
/* stats */
static pthread_mutex_t G=PTHREAD_MUTEX_INITIALIZER;
static u64 st_msgs_relayed=0, st_sigs=0, st_blobs=0, st_bytes_in=0, st_bytes_out=0;

typedef struct Client {
  int fd; int alive;
  char pub[65];
  char pres[8];              /* online / away */
  char (*watch)[65]; int nwatch;
  pthread_mutex_t wlock;
  u64 rate_t; int rate_n;
} Client;
static Client *CLIENTS[MAX_CLIENTS];

static Client* find_client(const char*pub){
  for(int i=0;i<MAX_CLIENTS;i++){ Client*c=CLIENTS[i]; if(c&&c->alive&&!strcmp(c->pub,pub)) return c; }
  return NULL;
}

/* ================= WS framing ================= */
static int ws_send_frame(Client*c,const char*txt,size_t len){
  if(!c||!c->alive) return -1;
  u8 head[10]; size_t hl;
  head[0]=0x81;
  if(len<126){ head[1]=(u8)len; hl=2; }
  else if(len<65536){ head[1]=126; head[2]=(u8)(len>>8); head[3]=(u8)len; hl=4; }
  else { head[1]=127; for(int i=0;i<8;i++) head[2+i]=(u8)(len>>(56-8*i)); hl=10; }
  pthread_mutex_lock(&c->wlock);
  int ok=0;
  if(c->alive){
    ssize_t r1=send(c->fd,head,hl,MSG_NOSIGNAL);
    ssize_t r2=(r1==(ssize_t)hl)?send(c->fd,txt,len,MSG_NOSIGNAL):-1;
    ok=(r2==(ssize_t)len);
  }
  pthread_mutex_unlock(&c->wlock);
  if(ok){ pthread_mutex_lock(&G); st_bytes_out+=len; pthread_mutex_unlock(&G); }
  return ok?0:-1;
}
static int ws_sendf(Client*c,const char*fmt,...){
  char stackbuf[1024]; char*buf=stackbuf;
  va_list ap; va_start(ap,fmt);
  int n=vsnprintf(stackbuf,sizeof stackbuf,fmt,ap); va_end(ap);
  if(n<0) return -1;
  if((size_t)n>=sizeof stackbuf){
    buf=malloc(n+1); va_start(ap,fmt); vsnprintf(buf,n+1,fmt,ap); va_end(ap);
  }
  int r=ws_send_frame(c,buf,n);
  if(buf!=stackbuf) free(buf);
  return r;
}

/* read exactly n bytes */
static int read_n(int fd,u8*buf,size_t n){ size_t got=0; while(got<n){ ssize_t r=recv(fd,buf+got,n-got,0); if(r<=0) return -1; got+=r; } return 0; }

/* ================= tiny JSON field extraction =================
   Our protocol values are [A-Za-z0-9+/=:_.-] (hex, base64, simple words) — no JSON
   escapes ever needed. Extract "key":"value"; reject values containing '\'. */
static char* json_str(const char*json,const char*key,size_t maxlen){
  char pat[64]; snprintf(pat,sizeof pat,"\"%s\"",key);
  const char*p=strstr(json,pat); if(!p) return NULL;
  p+=strlen(pat);
  while(*p==' '||*p=='\t') p++;
  if(*p!=':') return NULL; p++;
  while(*p==' '||*p=='\t') p++;
  if(*p!='"') return NULL; p++;
  const char*e=p;
  while(*e&&*e!='"'){ if(*e=='\\') return NULL; e++; }
  if(*e!='"') return NULL;
  size_t len=e-p; if(len>maxlen) return NULL;
  char*out=malloc(len+1); memcpy(out,p,len); out[len]=0;
  return out;
}

/* ================= disk queue =================
   DATA/queue/<pub>/<id> : line1 = from, line2 = ts(ms), rest = payload */
static void mkdirs(const char*p){ mkdir(p,0700); }
static void qdir(char*out,size_t cap,const char*pub){ snprintf(out,cap,"%s/queue/%s",DATADIR,pub); }
static int q_store(const char*to,const char*id,const char*from,u64 ts,const char*payload){
  char d[700]; qdir(d,sizeof d,to); mkdirs(d);
  char f[900]; snprintf(f,sizeof f,"%s/%s",d,id);
  struct stat sb; if(stat(f,&sb)==0) return 1;  /* idempotent */
  /* cap: 500 queued per recipient */
  DIR*dir=opendir(d); int n=0; if(dir){ struct dirent*e; while((e=readdir(dir))) if(e->d_name[0]!='.') n++; closedir(dir); }
  if(n>=500) return 0;
  FILE*fp=fopen(f,"w"); if(!fp) return 0;
  fprintf(fp,"%s\n%llu\n%s",from,(unsigned long long)ts,payload);
  fclose(fp);
  return 1;
}
typedef struct { char id[64]; char from[65]; u64 ts; char*payload; } QMsg;
static int q_load_one(const char*pub,const char*id,QMsg*m){
  char f[900]; snprintf(f,sizeof f,"%s/queue/%s/%s",DATADIR,pub,id);
  FILE*fp=fopen(f,"r"); if(!fp) return 0;
  char from[80]={0}, tsl[40]={0};
  if(!fgets(from,sizeof from,fp)||!fgets(tsl,sizeof tsl,fp)){ fclose(fp); return 0; }
  from[strcspn(from,"\n")]=0;
  long start=ftell(fp); fseek(fp,0,SEEK_END); long end=ftell(fp); fseek(fp,start,SEEK_SET);
  long plen=end-start; if(plen<0||plen>MAX_PAYLOAD){ fclose(fp); return 0; }
  m->payload=malloc(plen+1);
  size_t r = fread(m->payload,1,plen,fp); (void)r; m->payload[plen]=0; fclose(fp);
  snprintf(m->id,sizeof m->id,"%s",id);
  snprintf(m->from,sizeof m->from,"%s",from);
  m->ts=strtoull(tsl,NULL,10);
  return 1;
}
static int qcmp(const void*a,const void*b){ const QMsg*x=a,*y=b; return x->ts<y->ts?-1:(x->ts>y->ts?1:0); }
static void q_flush_to(Client*c){
  char d[700]; qdir(d,sizeof d,c->pub);
  DIR*dir=opendir(d); if(!dir) return;
  QMsg*list=NULL; int n=0,cap=0; struct dirent*e;
  while((e=readdir(dir))){
    if(e->d_name[0]=='.') continue;
    if(n==cap){ cap=cap?cap*2:32; list=realloc(list,cap*sizeof(QMsg)); }
    if(q_load_one(c->pub,e->d_name,&list[n])) n++;
  }
  closedir(dir);
  qsort(list,n,sizeof(QMsg),qcmp);
  for(int i=0;i<n;i++){
    ws_sendf(c,"{\"type\":\"msg\",\"id\":\"%s\",\"from\":\"%s\",\"ts\":%llu,\"payload\":\"%s\"}",
      list[i].id,list[i].from,(unsigned long long)list[i].ts,list[i].payload);
    free(list[i].payload);
  }
  free(list);
}

/* ================= presence ================= */
static void push_presence(const char*pub){
  char state[8]="offline"; u64 seen=now_ms();
  Client*t=find_client(pub); if(t) snprintf(state,sizeof state,"%s",t->pres);
  for(int i=0;i<MAX_CLIENTS;i++){
    Client*c=CLIENTS[i]; if(!c||!c->alive) continue;
    int watching=0;
    for(int j=0;j<c->nwatch;j++) if(!strcmp(c->watch[j],pub)){ watching=1; break; }
    if(watching) ws_sendf(c,"{\"type\":\"presence\",\"pub\":\"%s\",\"state\":\"%s\",\"seen\":%llu}",pub,state,(unsigned long long)seen);
  }
}

/* ================= WS message handling ================= */
static void handle_ws_msg(Client*c,char*json){
  char*type=json_str(json,"type",16); if(!type) return;
  if(!strcmp(type,"ping")){ ws_sendf(c,"{\"type\":\"pong\"}"); }
  else if(!strcmp(type,"presence")){
    char*stv=json_str(json,"state",8);
    snprintf(c->pres,sizeof c->pres,"%s",(stv&&!strcmp(stv,"away"))?"away":"online");
    free(stv); push_presence(c->pub);
  }
  else if(!strcmp(type,"watch")){
    /* parse "pubs":[ "hex", ... ] */
    pthread_mutex_lock(&G);
    free(c->watch); c->watch=NULL; c->nwatch=0;
    const char*p=strstr(json,"\"pubs\"");
    if(p){ p=strchr(p,'['); const char*end=p?strchr(p,']'):NULL;
      if(p&&end){
        int cap=0;
        while((p=strchr(p,'"'))&&p<end){
          const char*q=strchr(p+1,'"'); if(!q||q>end) break;
          int len=(int)(q-p-1);
          if(len==64&&c->nwatch<5000){
            if(c->nwatch==cap){ cap=cap?cap*2:32; c->watch=realloc(c->watch,cap*65); }
            memcpy(c->watch[c->nwatch],p+1,64); c->watch[c->nwatch][64]=0;
            int ok=1; for(int i=0;i<64;i++) if(hexval(c->watch[c->nwatch][i])<0){ ok=0; break; }
            if(ok) c->nwatch++;
          }
          p=q+1;
        }
      }
    }
    pthread_mutex_unlock(&G);
    /* reply current state for each */
    for(int j=0;j<c->nwatch;j++){
      Client*t=find_client(c->watch[j]);
      ws_sendf(c,"{\"type\":\"presence\",\"pub\":\"%s\",\"state\":\"%s\",\"seen\":%llu}",
        c->watch[j],t?t->pres:"offline",(unsigned long long)now_ms());
    }
  }
  else if(!strcmp(type,"send")){
    char*to=json_str(json,"to",64); char*id=json_str(json,"id",32); char*payload=json_str(json,"payload",MAX_PAYLOAD);
    if(to&&id&&payload&&is_hex(to,64)&&strlen(id)>=4&&strlen(id)<=32){
      int hexid=1; for(size_t i=0;i<strlen(id);i++) if(hexval(id[i])<0){ hexid=0; break; }
      u64 now=now_ms();
      if(hexid){
        if(now-c->rate_t>60000){ c->rate_t=now; c->rate_n=0; }
        if(++c->rate_n>60){ ws_sendf(c,"{\"type\":\"sent\",\"id\":\"%s\",\"queued\":false,\"error\":\"rate\"}",id); goto done_send; }
        q_store(to,id,c->pub,now,payload);
        Client*rc=find_client(to);
        if(rc) ws_sendf(rc,"{\"type\":\"msg\",\"id\":\"%s\",\"from\":\"%s\",\"ts\":%llu,\"payload\":\"%s\"}",id,c->pub,(unsigned long long)now,payload);
        ws_sendf(c,"{\"type\":\"sent\",\"id\":\"%s\",\"queued\":%s}",id,rc?"false":"true");
        pthread_mutex_lock(&G); st_msgs_relayed++; st_bytes_in+=strlen(payload); pthread_mutex_unlock(&G);
      }
    }
    done_send:
    free(to); free(id); free(payload);
  }
  else if(!strcmp(type,"ack")){
    char*id=json_str(json,"id",32);
    if(id){
      QMsg m; m.payload=NULL;
      if(q_load_one(c->pub,id,&m)){
        char f[900]; snprintf(f,sizeof f,"%s/queue/%s/%s",DATADIR,c->pub,id); unlink(f);
        free(m.payload);
        Client*snd=find_client(m.from);
        if(snd) ws_sendf(snd,"{\"type\":\"delivered\",\"id\":\"%s\"}",id);
      }
    }
    free(id);
  }
  else if(!strcmp(type,"sig")){
    char*to=json_str(json,"to",64); char*payload=json_str(json,"payload",MAX_PAYLOAD);
    if(to&&payload&&is_hex(to,64)){
      Client*rc=find_client(to);
      if(rc) ws_sendf(rc,"{\"type\":\"sig\",\"from\":\"%s\",\"payload\":\"%s\"}",c->pub,payload);
      pthread_mutex_lock(&G); st_sigs++; pthread_mutex_unlock(&G);
    }
    free(to); free(payload);
  }
  free(type);
}

/* ================= auth ================= */
static char* qparam(const char*query,const char*key){
  size_t kl=strlen(key);
  const char*p=query;
  while(p&&*p){
    if(!strncmp(p,key,kl)&&p[kl]=='='){
      const char*v=p+kl+1; const char*e=strchr(v,'&'); size_t len=e?(size_t)(e-v):strlen(v);
      char*out=malloc(len+1); memcpy(out,v,len); out[len]=0; return out;
    }
    p=strchr(p,'&'); if(p)p++;
  }
  return NULL;
}
static int auth_ok(const char*query,char pub_out[65]){
  char*pub=qparam(query,"pub"); char*ts=qparam(query,"ts"); char*sig=qparam(query,"sig");
  int ok=0;
  if(pub&&ts&&sig&&is_hex(pub,64)&&is_hex(sig,128)){
    long long t=atoll(ts); long long now=(long long)(now_ms()/1000);
    if(llabs(now-t)<=600){
      u8 pk[32],sg[64];
      if(unhex(pk,pub,32)&&unhex(sg,sig,64)){
        char msg[64]; int n=snprintf(msg,sizeof msg,"R2R-AUTH|%s",ts);
        if(ed25519_verify((u8*)msg,n,sg,pk)){ memcpy(pub_out,pub,64); pub_out[64]=0; ok=1; }
      }
    }
  }
  free(pub); free(ts); free(sig);
  return ok;
}

/* ================= HTTP helpers ================= */
static void http_json(int fd,int code,const char*status,const char*body){
  char head[512];
  int n=snprintf(head,sizeof head,
    "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n"
    "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET,POST,OPTIONS\r\nAccess-Control-Allow-Headers: *\r\nConnection: close\r\n\r\n",
    code,status,strlen(body));
  send(fd,head,n,MSG_NOSIGNAL); send(fd,body,strlen(body),MSG_NOSIGNAL);
}
static u64 dir_bytes(const char*path,int*count){
  u64 total=0; int n=0;
  DIR*d=opendir(path);
  if(d){ struct dirent*e;
    while((e=readdir(d))){ if(e->d_name[0]=='.') continue;
      char f[1024]; snprintf(f,sizeof f,"%s/%s",path,e->d_name);
      struct stat sb;
      if(stat(f,&sb)==0){ if(S_ISDIR(sb.st_mode)){ int sub=0; total+=dir_bytes(f,&sub); n+=sub; } else { total+=sb.st_size; n++; } } }
    closedir(d); }
  if(count)*count=n;
  return total;
}

/* ---------- per-account archive: DATA/accounts/<pub>/{journal/<seq>, quota} ---------- */
static void acct_path(char*out,size_t cap,const char*pub,const char*sub){ if(sub) snprintf(out,cap,"%s/accounts/%s/%s",DATADIR,pub,sub); else snprintf(out,cap,"%s/accounts/%s",DATADIR,pub); }
static long long acct_quota_bytes(const char*pub){
  char f[700]; acct_path(f,sizeof f,pub,"quota");
  FILE*fp=fopen(f,"r");
  if(fp){ double mb=DEFAULT_QUOTA_MB; if(fscanf(fp,"%lf",&mb)!=1) mb=DEFAULT_QUOTA_MB; fclose(fp);
    if(mb<0) return -1; return (long long)(mb*1048576.0); }
  return (long long)(DEFAULT_QUOTA_MB*1048576.0);
}
static u64 acct_used(const char*pub){ char d[700]; acct_path(d,sizeof d,pub,"journal"); int n; return dir_bytes(d,&n); }
/* per-account blob TTL in days; -1 = keep forever; default = BLOB_TTL_DAYS for unknown users */
static double acct_ttl_days(const char*pub){
  char f[700]; acct_path(f,sizeof f,pub,"ttl");
  FILE*fp=fopen(f,"r");
  if(fp){ double d; if(fscanf(fp,"%lf",&d)==1){ fclose(fp); return d<0?-1:d; } fclose(fp); }
  return BLOB_TTL_DAYS;
}
static u64 next_seq(const char*pub){
  char d[700]; acct_path(d,sizeof d,pub,NULL); mkdirs(d);
  acct_path(d,sizeof d,pub,"journal"); mkdirs(d);
  u64 mx=0; DIR*dir=opendir(d);
  if(dir){ struct dirent*e; while((e=readdir(dir))){ if(e->d_name[0]=='.') continue; u64 v=strtoull(e->d_name,NULL,10); if(v>mx) mx=v; } closedir(dir); }
  return mx+1;
}

/* ================= connection thread ================= */
typedef struct { int fd; } ThreadArg;
static void* conn_thread(void*argp){
  int fd=((ThreadArg*)argp)->fd; free(argp);
  char req[8192]; size_t got=0;
  /* read request head */
  while(got<sizeof req-1){
    ssize_t r=recv(fd,req+got,sizeof req-1-got,0);
    if(r<=0){ close(fd); return NULL; }
    got+=r; req[got]=0;
    if(strstr(req,"\r\n\r\n")) break;
  }
  char*hdr_end=strstr(req,"\r\n\r\n");
  if(!hdr_end){ close(fd); return NULL; }
  char method[8]={0},url[2048]={0};
  sscanf(req,"%7s %2047s",method,url);
  char*path=url; char*query=strchr(url,'?');
  if(query){ *query=0; query++; } else query=(char*)"";

  if(!ip_ok(fd)){ http_json(fd,429,"Too Many Requests","{\"error\":\"rate\"}"); close(fd); return NULL; }

  if(!strcmp(method,"OPTIONS")){ http_json(fd,204,"No Content",""); close(fd); return NULL; }

  /* ---- WebSocket upgrade ---- */
  char*upg=strcasestr(req,"Upgrade: websocket");
  if(upg&&!strcmp(path,"/ws")){
    char pub[65];
    char*keyh=strcasestr(req,"Sec-WebSocket-Key:");
    if(!keyh||!auth_ok(query,pub)){
      const char*r401="HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
      send(fd,r401,strlen(r401),MSG_NOSIGNAL); close(fd); return NULL;
    }
    keyh+=18; while(*keyh==' ')keyh++;
    char wskey[128]={0}; sscanf(keyh,"%127[^\r\n]",wskey);
    char cat[192]; snprintf(cat,sizeof cat,"%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11",wskey);
    u8 dig[20]; sha1(dig,(u8*)cat,strlen(cat));
    char acc[40]; b64enc(acc,dig,20);
    char resp[256];
    int n=snprintf(resp,sizeof resp,"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",acc);
    send(fd,resp,n,MSG_NOSIGNAL);
    int one=1; setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof one);

    Client*c=calloc(1,sizeof(Client));
    c->fd=fd; c->alive=1; snprintf(c->pub,sizeof c->pub,"%s",pub);
    snprintf(c->pres,sizeof c->pres,"online");
    pthread_mutex_init(&c->wlock,NULL);
    pthread_mutex_lock(&G);
    /* replace an existing connection for this key */
    for(int i=0;i<MAX_CLIENTS;i++){ Client*o=CLIENTS[i]; if(o&&o->alive&&!strcmp(o->pub,pub)){ o->alive=0; shutdown(o->fd,SHUT_RDWR); } }
    int slot=-1;
    for(int i=0;i<MAX_CLIENTS;i++) if(!CLIENTS[i]){ CLIENTS[i]=c; slot=i; break; }
    pthread_mutex_unlock(&G);
    if(slot<0){ close(fd); free(c); return NULL; }
    push_presence(pub);
    q_flush_to(c);

    /* frame loop */
    for(;;){
      u8 h2[2];
      if(read_n(fd,h2,2)) break;
      int op=h2[0]&0x0f, masked=h2[1]&0x80;
      u64 len=h2[1]&0x7f;
      if(len==126){ u8 x[2]; if(read_n(fd,x,2))break; len=((u64)x[0]<<8)|x[1]; }
      else if(len==127){ u8 x[8]; if(read_n(fd,x,8))break; len=0; for(int i=0;i<8;i++) len=(len<<8)|x[i]; }
      if(len>1024*1024) break;
      u8 mask[4]={0};
      if(masked&&read_n(fd,mask,4)) break;
      u8*data=malloc(len+1);
      if(len&&read_n(fd,data,len)){ free(data); break; }
      if(masked) for(u64 i=0;i<len;i++) data[i]^=mask[i&3];
      data[len]=0;
      if(op==8){ free(data); break; }
      if(op==9){ /* ping → pong */
        u8 ph[2]={0x8A,(u8)len};
        pthread_mutex_lock(&c->wlock); send(fd,ph,2,MSG_NOSIGNAL); if(len)send(fd,data,len,MSG_NOSIGNAL); pthread_mutex_unlock(&c->wlock);
        free(data); continue; }
      if(op==1) handle_ws_msg(c,(char*)data);
      free(data);
    }
    pthread_mutex_lock(&G);
    if(CLIENTS[slot]==c) CLIENTS[slot]=NULL;
    c->alive=0;
    pthread_mutex_unlock(&G);
    push_presence(pub);
    close(fd);
    /* small grace so a racing writer under wlock finishes */
    usleep(50000);
    free(c->watch); pthread_mutex_destroy(&c->wlock); free(c);
    return NULL;
  }

  /* ---- HTTP routes ---- */
  if(!strcmp(path,"/info")&&!strcmp(method,"GET")){
    char qd[600]; snprintf(qd,sizeof qd,"%s/queue",DATADIR);
    int qn=0; dir_bytes(qd,&qn);
    char body[256]; snprintf(body,sizeof body,"{\"name\":\"r2r-relay\",\"version\":1,\"impl\":\"c\",\"ws\":\"/ws\",\"maxBlob\":%d,\"queued\":%d}",MAX_BLOB,qn);
    http_json(fd,200,"OK",body); close(fd); return NULL;
  }
  if(!strcmp(path,"/stats")&&!strcmp(method,"GET")){
    char qd[600],bd[600]; snprintf(qd,sizeof qd,"%s/queue",DATADIR); snprintf(bd,sizeof bd,"%s/blobs",DATADIR);
    int qn=0,bn=0; u64 qb=dir_bytes(qd,&qn), bb=dir_bytes(bd,&bn);
    pthread_mutex_lock(&G);
    int online=0; for(int i=0;i<MAX_CLIENTS;i++) if(CLIENTS[i]&&CLIENTS[i]->alive) online++;
    char body[512];
    snprintf(body,sizeof body,
      "{\"uptimeSec\":%llu,\"online\":%d,\"msgsRelayed\":%llu,\"sigsForwarded\":%llu,"
      "\"queuedMsgs\":%d,\"queuedBytes\":%llu,\"blobs\":%d,\"blobBytes\":%llu,"
      "\"bytesIn\":%llu,\"bytesOut\":%llu}",
      (unsigned long long)((now_ms()-T0)/1000),online,
      (unsigned long long)st_msgs_relayed,(unsigned long long)st_sigs,
      qn,(unsigned long long)qb,bn,(unsigned long long)bb,
      (unsigned long long)st_bytes_in,(unsigned long long)st_bytes_out);
    pthread_mutex_unlock(&G);
    http_json(fd,200,"OK",body); close(fd); return NULL;
  }
  char pub[65];
  if(!strcmp(path,"/ice")&&!strcmp(method,"GET")){
    if(!auth_ok(query,pub)){ http_json(fd,401,"Unauthorized","{\"error\":\"auth\"}"); close(fd); return NULL; }
    const char*tu=getenv("TURN_URL");
    char body[1024];
    if(tu) snprintf(body,sizeof body,"{\"iceServers\":[{\"urls\":\"stun:stun.l.google.com:19302\"},{\"urls\":\"%s\",\"username\":\"%s\",\"credential\":\"%s\"}],\"ttl\":600}",tu,getenv("TURN_USER")?getenv("TURN_USER"):"",getenv("TURN_PASS")?getenv("TURN_PASS"):"");
    else snprintf(body,sizeof body,"{\"iceServers\":[{\"urls\":\"stun:stun.l.google.com:19302\"}],\"ttl\":600}");
    http_json(fd,200,"OK",body); close(fd); return NULL;
  }
  if(!strcmp(path,"/blob")&&!strcmp(method,"POST")){
    if(!auth_ok(query,pub)){ http_json(fd,401,"Unauthorized","{\"error\":\"auth\"}"); close(fd); return NULL; }
    char*cl=strcasestr(req,"Content-Length:");
    long long len=cl?atoll(cl+15):-1;
    if(len<=0||len>MAX_BLOB){ http_json(fd,413,"Payload Too Large","{\"error\":\"too_big\"}"); close(fd); return NULL; }
    u8*body=malloc(len);
    size_t have=got-((hdr_end+4)-req);
    if(have>(size_t)len) have=len;
    memcpy(body,hdr_end+4,have);
    if(have<(size_t)len&&read_n(fd,body+have,len-have)){ free(body); close(fd); return NULL; }
    u8 dig[64]; sha512(dig,body,len);
    char id[33]; tohex(id,dig,16);
    char f[700]; snprintf(f,sizeof f,"%s/blobs/%s",DATADIR,id);
    FILE*fp=fopen(f,"wb");
    if(fp){ fwrite(body,1,len,fp); fclose(fp);
      /* per-blob expiry: TTL follows the uploading account (owner-adjustable); never shortened */
      double td=acct_ttl_days(pub);
      char xf[750]; snprintf(xf,sizeof xf,"%s.exp",f);
      long long oldx=0; int hasx=0; FILE*xp=fopen(xf,"r");
      if(xp){ if(fscanf(xp,"%lld",&oldx)==1) hasx=1; fclose(xp); }
      long long newx = td<0 ? -1 : (long long)(now_ms()/1000 + td*86400.0);
      if(!(hasx&&oldx==-1) && !(hasx&&newx>=0&&oldx>=newx)){
        xp=fopen(xf,"w"); if(xp){ fprintf(xp,"%lld",newx); fclose(xp); }
      }
      pthread_mutex_lock(&G); st_blobs++; st_bytes_in+=len; pthread_mutex_unlock(&G);
      char resp[80]; snprintf(resp,sizeof resp,"{\"id\":\"%s\"}",id);
      http_json(fd,200,"OK",resp);
    } else http_json(fd,500,"Internal Server Error","{\"error\":\"disk\"}");
    free(body); close(fd); return NULL;
  }
  if(!strncmp(path,"/blob/",6)&&!strcmp(method,"GET")){
    if(!auth_ok(query,pub)){ http_json(fd,401,"Unauthorized","{\"error\":\"auth\"}"); close(fd); return NULL; }
    const char*id=path+6;
    if(!is_hex(id,32)){ http_json(fd,400,"Bad Request","{\"error\":\"bad_id\"}"); close(fd); return NULL; }
    char f[700]; snprintf(f,sizeof f,"%s/blobs/%s",DATADIR,id);
    FILE*fp=fopen(f,"rb");
    if(!fp){ http_json(fd,404,"Not Found","{\"error\":\"gone\"}"); close(fd); return NULL; }
    fseek(fp,0,SEEK_END); long sz=ftell(fp); fseek(fp,0,SEEK_SET);
    char head[300];
    int n=snprintf(head,sizeof head,"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %ld\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",sz);
    send(fd,head,n,MSG_NOSIGNAL);
    u8 buf[65536]; size_t r;
    while((r=fread(buf,1,sizeof buf,fp))>0){ if(send(fd,buf,r,MSG_NOSIGNAL)<0) break; }
    fclose(fp);
    pthread_mutex_lock(&G); st_bytes_out+=sz; pthread_mutex_unlock(&G);
    close(fd); return NULL;
  }
  if(!strcmp(path,"/journal")&&!strcmp(method,"POST")){
    /* append ONE encrypted history record to the account's journal */
    if(!auth_ok(query,pub)){ http_json(fd,401,"Unauthorized","{\"error\":\"auth\"}"); close(fd); return NULL; }
    char*cl=strcasestr(req,"Content-Length:");
    long long len=cl?atoll(cl+15):-1;
    if(len<=0||len>MAX_EVENT){ http_json(fd,413,"Payload Too Large","{\"error\":\"too_big\"}"); close(fd); return NULL; }
    long long quota=acct_quota_bytes(pub);
    if(quota>=0 && (long long)acct_used(pub)+len>quota){ http_json(fd,402,"Payment Required","{\"error\":\"quota\"}"); close(fd); return NULL; }
    u8*body=malloc(len);
    size_t have=got-((hdr_end+4)-req);
    if(have>(size_t)len) have=len;
    memcpy(body,hdr_end+4,have);
    if(have<(size_t)len&&read_n(fd,body+have,len-have)){ free(body); close(fd); return NULL; }
    int clean=1; for(long long i=0;i<len;i++) if(body[i]<0x20||body[i]>0x7e){ clean=0; break; }   /* records are base64 text */
    if(!clean){ free(body); http_json(fd,400,"Bad Request","{\"error\":\"binary\"}"); close(fd); return NULL; }
    pthread_mutex_lock(&G);
    u64 seq=next_seq(pub);
    char f[900]; acct_path(f,sizeof f,pub,NULL); snprintf(f+strlen(f),sizeof f-strlen(f),"/journal/%010llu",(unsigned long long)seq);
    FILE*fp=fopen(f,"wb"); int ok=0;
    if(fp){ ok=(fwrite(body,1,len,fp)==(size_t)len); fclose(fp); }
    st_bytes_in+=len;
    pthread_mutex_unlock(&G);
    free(body);
    if(ok){ char resp[64]; snprintf(resp,sizeof resp,"{\"seq\":%llu}",(unsigned long long)seq); http_json(fd,200,"OK",resp); }
    else http_json(fd,500,"Internal Server Error","{\"error\":\"disk\"}");
    close(fd); return NULL;
  }
  if(!strcmp(path,"/journal")&&!strcmp(method,"GET")){
    /* replay: ?since=<seq> → JSON array [{seq,d},...] oldest-first, max 200 records / ~2 MB */
    if(!auth_ok(query,pub)){ http_json(fd,401,"Unauthorized","{\"error\":\"auth\"}"); close(fd); return NULL; }
    char*sv=qparam(query,"since"); u64 since=sv?strtoull(sv,NULL,10):0; free(sv);
    char d[700]; acct_path(d,sizeof d,pub,"journal");
    u64*seqs=NULL; int n=0,cap=0;
    DIR*dir=opendir(d);
    if(dir){ struct dirent*e;
      while((e=readdir(dir))){ if(e->d_name[0]=='.') continue; u64 v=strtoull(e->d_name,NULL,10);
        if(v>since){ if(n==cap){ cap=cap?cap*2:64; seqs=realloc(seqs,cap*sizeof(u64)); } seqs[n++]=v; } }
      closedir(dir); }
    /* sort ascending (insertion — lists are small) */
    for(int i=1;i<n;i++){ u64 v=seqs[i]; int j=i-1; while(j>=0&&seqs[j]>v){ seqs[j+1]=seqs[j]; j--; } seqs[j+1]=v; }
    size_t bcap=65536, blen=0; char*out=malloc(bcap);
    out[blen++]='[';
    u64 total=0; int put=0;
    for(int i=0;i<n&&put<200&&total<2*1024*1024;i++){
      char f[900]; snprintf(f,sizeof f,"%s/%010llu",d,(unsigned long long)seqs[i]);
      FILE*fp=fopen(f,"rb"); if(!fp) continue;
      fseek(fp,0,SEEK_END); long sz=ftell(fp); fseek(fp,0,SEEK_SET);
      if(sz<0||sz>MAX_EVENT){ fclose(fp); continue; }
      char*data=malloc(sz+1); size_t r = fread(data,1,sz,fp); (void)r; data[sz]=0; fclose(fp);
      size_t need=blen+sz+64;
      if(need>bcap){ while(bcap<need) bcap*=2; out=realloc(out,bcap); }
      blen+=snprintf(out+blen,bcap-blen,"%s{\"seq\":%llu,\"d\":\"%s\"}",put?",":"",(unsigned long long)seqs[i],data);
      free(data); total+=sz; put++;
    }
    out[blen++]=']'; out[blen]=0;
    free(seqs);
    char head[300];
    int hn=snprintf(head,sizeof head,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",blen);
    send(fd,head,hn,MSG_NOSIGNAL); send(fd,out,blen,MSG_NOSIGNAL);
    pthread_mutex_lock(&G); st_bytes_out+=blen; pthread_mutex_unlock(&G);
    free(out); close(fd); return NULL;
  }
  if(!strcmp(path,"/usage")&&!strcmp(method,"GET")){
    if(!auth_ok(query,pub)){ http_json(fd,401,"Unauthorized","{\"error\":\"auth\"}"); close(fd); return NULL; }
    long long q=acct_quota_bytes(pub);
    char body[192]; snprintf(body,sizeof body,"{\"usedBytes\":%llu,\"quotaBytes\":%lld,\"ttlDays\":%g}",(unsigned long long)acct_used(pub),q,acct_ttl_days(pub));
    http_json(fd,200,"OK",body); close(fd); return NULL;
  }
  if(!strncmp(path,"/admin/",7)){
    /* admin key travels in the X-Admin-Key header — never in the URL, so it can't
       leak into reverse-proxy access logs or browser history */
    char akv[80]={0}; char*ah=strcasestr(req,"\r\nX-Admin-Key:");
    if(ah){ ah+=14; while(*ah==' '||*ah=='\t') ah++; size_t ai=0; while(ai<sizeof akv-1&&ah[ai]&&ah[ai]!='\r'&&ah[ai]!='\n'){ akv[ai]=ah[ai]; ai++; } akv[ai]=0; }
    int okk=(akv[0]&&ADMIN_KEY[0]&&!strcmp(akv,ADMIN_KEY));
    if(!okk){ http_json(fd,401,"Unauthorized","{\"error\":\"admin\"}"); close(fd); return NULL; }
    if(!strcmp(path,"/admin/accounts")){
      char ad[700]; snprintf(ad,sizeof ad,"%s/accounts",DATADIR);
      size_t bcap=8192, blen=0; char*out=malloc(bcap); out[blen++]='[';
      DIR*dir=opendir(ad); int put=0;
      if(dir){ struct dirent*e;
        while((e=readdir(dir))){ if(e->d_name[0]=='.'||strlen(e->d_name)!=64) continue;
          if(blen+320>bcap){ bcap*=2; out=realloc(out,bcap); }
          blen+=snprintf(out+blen,bcap-blen,"%s{\"pub\":\"%s\",\"usedBytes\":%llu,\"quotaBytes\":%lld,\"ttlDays\":%g}",put?",":"",e->d_name,(unsigned long long)acct_used(e->d_name),acct_quota_bytes(e->d_name),acct_ttl_days(e->d_name));
          put++; }
        closedir(dir); }
      out[blen++]=']'; out[blen]=0;
      http_json(fd,200,"OK",out); free(out); close(fd); return NULL;
    }
    if(!strcmp(path,"/admin/quota")){
      char*p2=qparam(query,"pub"); char*mb=qparam(query,"mb");
      if(p2&&mb&&is_hex(p2,64)){
        char d[700]; acct_path(d,sizeof d,p2,NULL); mkdirs(d);
        char f[700]; acct_path(f,sizeof f,p2,"quota");
        FILE*fp=fopen(f,"w");
        if(fp){ fprintf(fp,"%s",mb); fclose(fp); http_json(fd,200,"OK","{\"ok\":true}"); }
        else http_json(fd,500,"Internal Server Error","{\"error\":\"disk\"}");
      } else http_json(fd,400,"Bad Request","{\"error\":\"args\"}");
      free(p2); free(mb); close(fd); return NULL;
    }
    if(!strcmp(path,"/admin/ttl")){
      char*p2=qparam(query,"pub"); char*dd=qparam(query,"days");
      if(p2&&dd&&is_hex(p2,64)){
        char d[700]; acct_path(d,sizeof d,p2,NULL); mkdirs(d);
        char f[700]; acct_path(f,sizeof f,p2,"ttl");
        FILE*fp=fopen(f,"w");
        if(fp){ fprintf(fp,"%s",dd); fclose(fp); http_json(fd,200,"OK","{\"ok\":true}"); }
        else http_json(fd,500,"Internal Server Error","{\"error\":\"disk\"}");
      } else http_json(fd,400,"Bad Request","{\"error\":\"args\"}");
      free(p2); free(dd); close(fd); return NULL;
    }
    http_json(fd,404,"Not Found","{\"error\":\"not_found\"}"); close(fd); return NULL;
  }
  http_json(fd,404,"Not Found","{\"error\":\"not_found\"}");
  close(fd); return NULL;
}

/* ================= TTL sweeper ================= */
static void* sweeper(void*_){
  (void)_;
  for(;;){
    sleep(3600);
    u64 now=now_ms();
    char bd[600]; snprintf(bd,sizeof bd,"%s/blobs",DATADIR);
    DIR*d=opendir(bd);
    if(d){ struct dirent*e;
      while((e=readdir(d))){ if(e->d_name[0]=='.') continue;
        size_t nl=strlen(e->d_name);
        if(nl>4&&!strcmp(e->d_name+nl-4,".exp")) continue;
        char f[900]; snprintf(f,sizeof f,"%s/%s",bd,e->d_name);
        char xf[950]; snprintf(xf,sizeof xf,"%s.exp",f);
        long long exp=0; int hasx=0; FILE*xp=fopen(xf,"r");
        if(xp){ if(fscanf(xp,"%lld",&exp)==1) hasx=1; fclose(xp); }
        struct stat sb;
        if(hasx){ if(exp>=0&&(long long)(now/1000)>exp){ unlink(f); unlink(xf); } }
        else if(stat(f,&sb)==0&&now/1000-(u64)sb.st_mtime>BLOB_TTL_DAYS*86400){ unlink(f); unlink(xf); } }
      closedir(d); }
    char qd[600]; snprintf(qd,sizeof qd,"%s/queue",DATADIR);
    d=opendir(qd);
    if(d){ struct dirent*e;
      while((e=readdir(d))){ if(e->d_name[0]=='.') continue;
        char sub[900]; snprintf(sub,sizeof sub,"%s/%s",qd,e->d_name);
        DIR*d2=opendir(sub);
        if(d2){ struct dirent*e2;
          while((e2=readdir(d2))){ if(e2->d_name[0]=='.') continue;
            char f[1200]; snprintf(f,sizeof f,"%s/%s",sub,e2->d_name);
            struct stat sb;
            if(stat(f,&sb)==0&&now/1000-(u64)sb.st_mtime>QUEUE_TTL_DAYS*86400) unlink(f); }
          closedir(d2); }
        rmdir(sub); /* removes only if empty */ }
      closedir(d); }
  }
  return NULL;
}

/* ================= self-tests ================= */
static int self_test(void){
  /* SHA-512("abc") */
  static const char*want="ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
  u8 d[64]; char hex[129];
  sha512(d,(const u8*)"abc",3); tohex(hex,d,64);
  if(strcmp(hex,want)){ fprintf(stderr,"SELF-TEST FAILED: sha512\n"); return 0; }
  /* ed25519 vector (generated with the app's own tweetnacl) */
  u8 pk[32],sg[64];
  unhex(pk,"2abebd249ac4eb08c1cfe0bc2e184a04fedf3563552ad150a768f96dcfbae81e",32);
  unhex(sg,"65e59e24105683c5513dfef5e412994cf39afdd24d893f4cfaa6dab578356bf3c2487de52f23b42966bfc234fa1a034b14bc0c85ab986e5e8bcd15ab1bbb8006",64);
  const char*msg="R2R-AUTH|1700000000";
  if(!ed25519_verify((const u8*)msg,strlen(msg),sg,pk)){ fprintf(stderr,"SELF-TEST FAILED: ed25519 (valid sig rejected)\n"); return 0; }
  sg[0]^=1;
  if(ed25519_verify((const u8*)msg,strlen(msg),sg,pk)){ fprintf(stderr,"SELF-TEST FAILED: ed25519 (tampered sig accepted)\n"); return 0; }
  return 1;
}

/* ================= main ================= */
int main(int argc,char**argv){
  (void)argc;(void)argv;
  signal(SIGPIPE,SIG_IGN);
  T0=now_ms();
  if(getenv("PORT")) PORT=atoi(getenv("PORT"));
  if(getenv("DATA_DIR")) snprintf(DATADIR,sizeof DATADIR,"%s",getenv("DATA_DIR"));
  if(getenv("BLOB_TTL_DAYS")) BLOB_TTL_DAYS=atof(getenv("BLOB_TTL_DAYS"));
  if(getenv("QUEUE_TTL_DAYS")) QUEUE_TTL_DAYS=atof(getenv("QUEUE_TTL_DAYS"));
  if(getenv("DEFAULT_QUOTA_MB")) DEFAULT_QUOTA_MB=atof(getenv("DEFAULT_QUOTA_MB"));
  if(getenv("IP_REQS_PER_MIN")) IP_REQS_PER_MIN=atoi(getenv("IP_REQS_PER_MIN"));
  if(!self_test()) return 1;
  char sub[600];
  mkdirs(DATADIR);
  snprintf(sub,sizeof sub,"%s/queue",DATADIR); mkdirs(sub);
  snprintf(sub,sizeof sub,"%s/blobs",DATADIR); mkdirs(sub);
  snprintf(sub,sizeof sub,"%s/accounts",DATADIR); mkdirs(sub);
  /* admin key: generated at first run, printed every start. Delete the file to mint a new one. */
  { char akf[600]; snprintf(akf,sizeof akf,"%s/admin.key",DATADIR);
    FILE*fp=fopen(akf,"r");
    if(fp){ if(fscanf(fp,"%64s",ADMIN_KEY)!=1) ADMIN_KEY[0]=0; fclose(fp); }
    if(!ADMIN_KEY[0]){
      u8 rnd[32]; FILE*ur=fopen("/dev/urandom","rb");
      if(ur){ size_t r = fread(rnd,1,32,ur); (void)r; fclose(ur); } else { srand((unsigned)time(NULL)^getpid()); for(int i=0;i<32;i++) rnd[i]=(u8)rand(); }
      tohex(ADMIN_KEY,rnd,32);
      fp=fopen(akf,"w"); if(fp){ fprintf(fp,"%s\n",ADMIN_KEY); fclose(fp); chmod(akf,0600); }
    }
  }

  int srv=socket(AF_INET,SOCK_STREAM,0);
  int one=1; setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
  struct sockaddr_in addr={0};
  addr.sin_family=AF_INET; addr.sin_addr.s_addr=INADDR_ANY; addr.sin_port=htons(PORT);
  if(bind(srv,(struct sockaddr*)&addr,sizeof addr)<0){ perror("bind"); return 1; }
  if(listen(srv,64)<0){ perror("listen"); return 1; }

  printf("r2r-relay v1 (C) — self-tests passed. Data dir: %s\n",DATADIR);
  printf("ADMIN KEY — copy this into the wallet (Settings → Relay owner) to manage per-identity storage & file lifetimes:\n  %s\n",ADMIN_KEY);
  printf("  (kept in %s/admin.key — printed at every start; delete that file + restart for a new one. Default quota: %.1f MB/account)\n",DATADIR,DEFAULT_QUOTA_MB);
  printf("Paste ONE of these into the app (Settings → Relays):\n");
  struct ifaddrs*ifa=NULL;
  if(getifaddrs(&ifa)==0){
    for(struct ifaddrs*p=ifa;p;p=p->ifa_next){
      if(!p->ifa_addr||p->ifa_addr->sa_family!=AF_INET) continue;
      char ip[64];
      inet_ntop(AF_INET,&((struct sockaddr_in*)p->ifa_addr)->sin_addr,ip,sizeof ip);
      if(!strcmp(ip,"127.0.0.1")) continue;
      printf("  ws://%s:%d\n",ip,PORT);
    }
    freeifaddrs(ifa);
  }
  printf("  (from the internet: ws://<your-public-IP>:%d — forward TCP port %d on your router)\n",PORT,PORT);
  fflush(stdout);

  pthread_t swp; pthread_create(&swp,NULL,sweeper,NULL); pthread_detach(swp);
  for(;;){
    int fd=accept(srv,NULL,NULL);
    if(fd<0) continue;
    ThreadArg*a=malloc(sizeof *a); a->fd=fd;
    pthread_t t;
    if(pthread_create(&t,NULL,conn_thread,a)==0) pthread_detach(t);
    else { close(fd); free(a); }
  }
}
