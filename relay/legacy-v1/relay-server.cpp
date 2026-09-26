/* r2r-relay — single-file C++17 implementation of the R2R relay.
 * Build:   g++ -O2 -std=c++17 -o r2r r2r.cpp -pthread
 * Run:     ./r2r
 */
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <filesystem>
#include <regex>
#include <chrono>
#include <cstring>
#include <cstdarg>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <fcntl.h>

namespace fs = std::filesystem;

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64; typedef int64_t i64;

/* ================= CRYPTO (Kept raw for performance/compatibility) ================= */
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
    u64 S1=ROTR64(e,14)^ROTR64(e,18)^ROTR64(e,41); u64 ch=(e&f)^((~e)&g); t1=h+S1+ch+SHA512_K[i]+w[i];
    u64 S0=ROTR64(a,28)^ROTR64(a,34)^ROTR64(a,39); u64 mj=(a&b)^(a&cc)^(b&cc); t2=S0+mj;
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
  u64 bits=c->len*8; int i; u8 pad=0x80; sha512_update(c,&pad,1);
  u8 z=0; while(c->fill!=112) sha512_update(c,&z,1);
  u8 lenb[16]; memset(lenb,0,8); for(i=0;i<8;i++) lenb[8+i]=(u8)(bits>>(56-8*i));
  sha512_update(c,lenb,16);
  for(i=0;i<8;i++){ out[i*8]=(u8)(c->h[i]>>56); out[i*8+1]=(u8)(c->h[i]>>48); out[i*8+2]=(u8)(c->h[i]>>40); out[i*8+3]=(u8)(c->h[i]>>32); out[i*8+4]=(u8)(c->h[i]>>24); out[i*8+5]=(u8)(c->h[i]>>16); out[i*8+6]=(u8)(c->h[i]>>8); out[i*8+7]=(u8)c->h[i]; }
}
static void sha512(u8 out[64],const u8*d,size_t n){ sha512_ctx c; sha512_init(&c); sha512_update(&c,d,n); sha512_final(&c,out); }

static u32 ROTL32(u32 x,int n){ return (x<<n)|(x>>(32-n)); }
static void sha1(u8 out[20],const u8*data,size_t len){
  u32 h[5]={0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0};
  u64 ml=(u64)len*8; size_t total=((len+8)/64+1)*64;
  u8*m=(u8*)calloc(total,1); memcpy(m,data,len); m[len]=0x80;
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
  int i,j,b; gf m,t; for(i=0;i<16;i++) t[i]=n[i]; car25519(t); car25519(t); car25519(t);
  for(j=0;j<2;j++){ m[0]=t[0]-0xffed; for(i=1;i<15;i++){ m[i]=t[i]-0xffff-((m[i-1]>>16)&1); m[i-1]&=0xffff; }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1); b=(int)((m[15]>>16)&1); m[14]&=0xffff; sel25519(t,m,1-b); }
  for(i=0;i<16;i++){ o[2*i]=(u8)(t[i]&0xff); o[2*i+1]=(u8)(t[i]>>8); }
}
static void unpack25519(gf o,const u8*n){ for(int i=0;i<16;i++) o[i]=n[2*i]+((i64)n[2*i+1]<<8); o[15]&=0x7fff; }
static void Ag(gf o,const gf a,const gf b){ for(int i=0;i<16;i++) o[i]=a[i]+b[i]; }
static void Zg(gf o,const gf a,const gf b){ for(int i=0;i<16;i++) o[i]=a[i]-b[i]; }
static void Mg(gf o,const gf a,const gf b){
  i64 t[31]; int i,j; for(i=0;i<31;i++) t[i]=0;
  for(i=0;i<16;i++) for(j=0;j<16;j++) t[i+j]+=a[i]*b[j];
  for(i=0;i<15;i++) t[i]+=38*t[i+16]; for(i=0;i<16;i++) o[i]=t[i]; car25519(o); car25519(o);
}
static void Sg(gf o,const gf a){ Mg(o,a,a); }
static void inv25519(gf o,const gf i){ gf c; int a; set25519(c,i); for(a=253;a>=0;a--){ Sg(c,c); if(a!=2&&a!=4) Mg(c,c,i); } set25519(o,c); }
static void pow2523(gf o,const gf i){ gf c; int a; set25519(c,i); for(a=250;a>=0;a--){ Sg(c,c); if(a!=1) Mg(c,c,i); } set25519(o,c); }
static int vn(const u8*x,const u8*y,int n){ u32 d=0; for(int i=0;i<n;i++) d|=x[i]^y[i]; return (1&((d-1)>>8))-1; }
static int neq25519(const gf a,const gf b){ u8 c[32],d[32]; pack25519(c,a); pack25519(d,b); return vn(c,d,32); }
static u8 par25519(const gf a){ u8 d[32]; pack25519(d,a); return d[0]&1; }
static int unpackneg(gf r[4],const u8 p[32]){
  gf t,chk,num,den,den2,den4,den6; set25519(r[2],gf1); unpack25519(r[1],p);
  Sg(num,r[1]); Mg(den,num,D); Zg(num,num,r[2]); Ag(den,r[2],den); Sg(den2,den); Sg(den4,den2); Mg(den6,den4,den2);
  Mg(t,den6,num); Mg(t,t,den); pow2523(t,t); Mg(t,t,num); Mg(t,t,den); Mg(t,t,den); Mg(r[0],t,den);
  Sg(chk,r[0]); Mg(chk,chk,den); if(neq25519(chk,num)) Mg(r[0],r[0],Ico);
  Sg(chk,r[0]); Mg(chk,chk,den); if(neq25519(chk,num)) return -1;
  if(par25519(r[0])==(p[31]>>7)) Zg(r[0],gf0,r[0]); Mg(r[3],r[0],r[1]); return 0;
}
static void addp(gf p[4],gf q[4]){
  gf a,b,c,d,t,e,f,g,h; Zg(a,p[1],p[0]); Zg(t,q[1],q[0]); Mg(a,a,t); Ag(b,p[0],p[1]); Ag(t,q[0],q[1]); Mg(b,b,t);
  Mg(c,p[3],q[3]); Mg(c,c,D2); Mg(d,p[2],q[2]); Ag(d,d,d); Zg(e,b,a); Zg(f,d,c); Ag(g,d,c); Ag(h,b,a);
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
  for(i=63;i>=32;--i){ carry=0; for(j=i-32;j<i-12;++j){ x[j]+=carry-16*x[i]*L[j-(i-32)]; carry=(x[j]+128)>>8; x[j]-=carry<<8; } x[j]+=carry; x[i]=0; }
  carry=0; for(j=0;j<32;++j){ x[j]+=carry-(x[31]>>4)*L[j]; carry=x[j]>>8; x[j]&=255; }
  for(j=0;j<32;++j) x[j]-=carry*L[j]; for(i=0;i<32;++i){ x[i+1]+=x[i]>>8; r[i]=(u8)(x[i]&255); }
}
static void reduce64(u8 r[64]){ i64 x[64]; int i; for(i=0;i<64;i++){ x[i]=(u64)r[i]; r[i]=0; } modL(r,x); }
static int ed25519_verify(const u8*msg,size_t n,const u8 sig[64],const u8 pk[32]){
  u8 t[32],h[64]; gf p[4],q[4]; if(unpackneg(q,pk)) return 0;
  sha512_ctx c; sha512_init(&c); sha512_update(&c,sig,32); sha512_update(&c,pk,32); sha512_update(&c,msg,n);
  sha512_final(&c,h); reduce64(h); scalarmult(p,q,h); scalarbase(q,sig+32); addp(p,q); packp(t,p);
  return vn(sig,t,32)==0;
}

/* ================= STRING UTILS ================= */
static std::string b64enc(const u8* in, size_t len) {
    static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    for (; i + 2 < len; i += 3) {
        out += B64[in[i] >> 2];
        out += B64[((in[i] & 3) << 4) | (in[i+1] >> 4)];
        out += B64[((in[i+1] & 15) << 2) | (in[i+2] >> 6)];
        out += B64[in[i+2] & 63];
    }
    if (i < len) {
        out += B64[in[i] >> 2];
        if (i + 1 < len) {
            out += B64[((in[i] & 3) << 4) | (in[i+1] >> 4)];
            out += B64[(in[i+1] & 15) << 2];
            out += '=';
        } else {
            out += B64[(in[i] & 3) << 4];
            out += "==";
        }
    }
    return out;
}

static int hexval(char c) {
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return c-'a'+10;
    if(c>='A'&&c<='F')return c-'A'+10;
    return -1;
}

static bool is_hex(const std::string& s, size_t expected_len) {
    if (s.length() != expected_len) return false;
    for (char c : s) if (hexval(c) < 0) return false;
    return true;
}

static bool unhex(u8* out, const std::string& s, size_t bytes) {
    if(s.length() < bytes * 2) return false;
    for(size_t i=0; i<bytes; i++){
        int a = hexval(s[i*2]), b = hexval(s[i*2+1]);
        if(a<0 || b<0) return false;
        out[i] = (u8)((a<<4)|b);
    }
    return true;
}

static std::string tohex(const u8* in, size_t n) {
    std::string out(n * 2, '0');
    static const char* hex_chars = "0123456789abcdef";
    for(size_t i = 0; i < n; i++) {
        out[i * 2] = hex_chars[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex_chars[in[i] & 0x0F];
    }
    return out;
}

static std::string url_decode(const std::string& str) {
    std::string ret;
    for (size_t i = 0; i < str.length(); i++) {
        if (str[i] == '%' && i + 2 < str.length()) {
            int ii;
            if (sscanf(str.substr(i + 1, 2).c_str(), "%x", &ii) == 1) {
                ret += static_cast<char>(ii);
                i += 2;
            } else {
                ret += str[i];
            }
        } else if (str[i] == '+') {
            ret += ' ';
        } else {
            ret += str[i];
        }
    }
    return ret;
}

static std::string json_str(const std::string& json, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    size_t pos = json.find(pat);
    if (pos == std::string::npos) return "";
    pos += pat.length();
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    if (pos < json.length() && json[pos] != ':') return "";
    pos++;
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    if (pos < json.length() && json[pos] != '"') return "";
    pos++;
    size_t end = json.find('"', pos);
    if (end == std::string::npos) return "";
    std::string val = json.substr(pos, end - pos);
    if (val.find('\\') != std::string::npos) return ""; // Reject escaped paths for simplicity
    return val;
}

static u64 now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

/* ================= CONFIG / STATE ================= */
static int PORT = 8787;
static std::string DATADIR = "./r2r-relay-data";
static double BLOB_TTL_DAYS = 30, QUEUE_TTL_DAYS = 30;
static double DEFAULT_QUOTA_MB = 1;
static std::string ADMIN_KEY = "";
static int IP_REQS_PER_MIN = 240;

struct Client {
    int fd;
    bool alive;
    std::string pub;
    std::string pres;
    std::vector<std::string> watch;
    std::mutex wlock;
    u64 rate_t = 0;
    int rate_n = 0;
};

static std::vector<std::shared_ptr<Client>> CLIENTS;
static std::mutex G_MUTEX;
static u64 st_msgs_relayed=0, st_sigs=0, st_blobs=0, st_bytes_in=0, st_bytes_out=0;
static u64 T0 = now_ms();

std::shared_ptr<Client> find_client(const std::string& pub) {
    for (auto& c : CLIENTS) {
        if (c && c->alive && c->pub == pub) return c;
    }
    return nullptr;
}

/* ================= FILE OPS ================= */
void q_store(const std::string& to, const std::string& id, const std::string& from, u64 ts, const std::string& payload) {
    std::string d = DATADIR + "/queue/" + to;
    fs::create_directories(d);
    std::string path = d + "/" + id;
    if (fs::exists(path)) return;
    
    // Count items
    int n = 0;
    for (const auto& entry : fs::directory_iterator(d)) n++;
    if (n >= 500) return;

    FILE* fp = fopen(path.c_str(), "w");
    if (fp) {
        fprintf(fp, "%s\n%llu\n%s", from.c_str(), (unsigned long long)ts, payload.c_str());
        fclose(fp);
    }
}

/* ================= WS SEND ================= */
int ws_send_frame(std::shared_ptr<Client> c, const std::string& txt) {
    if (!c || !c->alive) return -1;
    std::vector<u8> head;
    head.push_back(0x81);
    size_t len = txt.length();
    if (len < 126) {
        head.push_back((u8)len);
    } else if (len < 65536) {
        head.push_back(126);
        head.push_back((u8)(len >> 8)); head.push_back((u8)len);
    } else {
        head.push_back(127);
        for (int i = 0; i < 8; i++) head.push_back((u8)(len >> (56 - 8 * i)));
    }
    
    std::lock_guard<std::mutex> lock(c->wlock);
    if (!c->alive) return -1;
    
    ssize_t r1 = send(c->fd, head.data(), head.size(), MSG_NOSIGNAL);
    ssize_t r2 = -1;
    if (r1 == (ssize_t)head.size()) {
        r2 = send(c->fd, txt.data(), len, MSG_NOSIGNAL);
    }
    
    if (r2 == (ssize_t)len) {
        std::lock_guard<std::mutex> glock(G_MUTEX);
        st_bytes_out += len;
        return 0;
    }
    return -1;
}

/* ================= CONN THREAD ================= */
static int read_n(int fd, u8* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    return 0;
}

void conn_thread(int fd) {
    std::string req;
    char buf[1024];
    while (req.find("\r\n\r\n") == std::string::npos) {
        ssize_t r = recv(fd, buf, sizeof(buf) - 1, 0);
        if (r <= 0) { close(fd); return; }
        buf[r] = 0;
        req += buf;
        if (req.length() > 8192) { close(fd); return; }
    }

    std::regex ws_upg_reg(R"(Upgrade:\s*websocket)", std::regex_constants::icase);
    if (std::regex_search(req, ws_upg_reg)) {
        // Extract Pub & Sig
        std::regex pub_reg(R"(pub=([a-fA-F0-9]+))", std::regex_constants::icase);
        std::regex ts_reg(R"(ts=([0-9]+))");
        std::regex sig_reg(R"(sig=([a-zA-Z0-9%\+]+))"); // Sig might be URL encoded
        
        std::smatch m;
        if (std::regex_search(req, m, pub_reg) && std::regex_search(req, m, ts_reg) && std::regex_search(req, m, sig_reg)) {
            std::string pub_match = req.substr(m.position(1), m.length(1));
            std::string ts_match = req.substr(m.position(1), m.length(1));
            
            // Re-run matches on req specifically
            std::smatch m_ts, m_sig, m_pub;
            std::regex_search(req, m_pub, pub_reg);
            std::regex_search(req, m_ts, ts_reg);
            std::regex_search(req, m_sig, sig_reg);
            
            std::string pub = m_pub.str(1);
            std::string ts = m_ts.str(1);
            std::string raw_sig = m_sig.str(1);
            
            // Decoded signature solves the silent 401 bug if app appends spaces or URL encodings
            std::string sig = url_decode(raw_sig); 
            
            if (is_hex(pub, 64) && is_hex(sig, 128)) {
                long long t = std::stoll(ts);
                long long now = (long long)(now_ms() / 1000);
                if (std::abs(now - t) <= 600) {
                    u8 pk[32], sg[64];
                    if (unhex(pk, pub, 32) && unhex(sg, sig, 64)) {
                        std::string msg = "R2R-AUTH|" + ts;
                        if (ed25519_verify((const u8*)msg.c_str(), msg.length(), sg, pk)) {
                            
                            // Get WS Key robustly (trimming whitespace solves the bad hash bug)
                            std::regex key_reg(R"(Sec-WebSocket-Key:\s*([^\r\n ]+))", std::regex_constants::icase);
                            std::smatch key_m;
                            if (std::regex_search(req, key_m, key_reg)) {
                                std::string wskey = key_m.str(1);
                                std::string cat = wskey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                                u8 dig[20];
                                sha1(dig, (const u8*)cat.c_str(), cat.length());
                                std::string acc = b64enc(dig, 20);
                                
                                std::string resp = "HTTP/1.1 101 Switching Protocols\r\n"
                                                   "Upgrade: websocket\r\n"
                                                   "Connection: Upgrade\r\n"
                                                   "Sec-WebSocket-Accept: " + acc + "\r\n\r\n";
                                send(fd, resp.c_str(), resp.length(), MSG_NOSIGNAL);
                                
                                int one = 1;
                                setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                                
                                auto c = std::make_shared<Client>();
                                c->fd = fd;
                                c->alive = true;
                                c->pub = pub;
                                c->pres = "online";
                                
                                {
                                    std::lock_guard<std::mutex> lock(G_MUTEX);
                                    CLIENTS.push_back(c);
                                }
                                
                                // WS Frame loop (simplistic)
                                while (c->alive) {
                                    u8 h2[2];
                                    if (read_n(fd, h2, 2)) break;
                                    int op = h2[0] & 0x0f, masked = h2[1] & 0x80;
                                    u64 len = h2[1] & 0x7f;
                                    if (len == 126) { u8 x[2]; if (read_n(fd, x, 2)) break; len = ((u64)x[0]<<8) | x[1]; }
                                    else if (len == 127) { u8 x[8]; if (read_n(fd, x, 8)) break; len = 0; for (int i = 0; i < 8; i++) len = (len << 8) | x[i]; }
                                    
                                    if (len > 1024 * 1024) break;
                                    
                                    u8 mask[4] = {0};
                                    if (masked && read_n(fd, mask, 4)) break;
                                    
                                    std::vector<u8> data(len);
                                    if (len && read_n(fd, data.data(), len)) break;
                                    
                                    if (masked) for (u64 i = 0; i < len; i++) data[i] ^= mask[i & 3];
                                    
                                    if (op == 8) break; // close
                                    if (op == 9) { // ping
                                        std::vector<u8> ph = {0x8A, (u8)len};
                                        std::lock_guard<std::mutex> wlock(c->wlock);
                                        send(fd, ph.data(), 2, MSG_NOSIGNAL);
                                        if (len) send(fd, data.data(), len, MSG_NOSIGNAL);
                                        continue;
                                    }
                                    if (op == 1) {
                                        std::string msg((char*)data.data(), len);
                                        std::string type = json_str(msg, "type");
                                        if (type == "ping") ws_send_frame(c, "{\"type\":\"pong\"}");
                                    }
                                }
                                
                                {
                                    std::lock_guard<std::mutex> lock(G_MUTEX);
                                    c->alive = false;
                                    for(auto it = CLIENTS.begin(); it != CLIENTS.end(); ++it) {
                                        if (*it == c) { CLIENTS.erase(it); break; }
                                    }
                                }
                                close(fd);
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
    
    // HTTP 401 fallback
    const char* r401 = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    send(fd, r401, strlen(r401), MSG_NOSIGNAL);
    close(fd);
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    
    fs::create_directories(DATADIR + "/queue");
    fs::create_directories(DATADIR + "/blobs");
    fs::create_directories(DATADIR + "/accounts");

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    
    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(srv, 64) < 0) {
        perror("listen");
        return 1;
    }
    
    std::cout << "R2R Relay C++17 port running on port " << PORT << std::endl;
    
    while (true) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) continue;
        std::thread(conn_thread, fd).detach();
    }
    return 0;
}