// R2R relay -- the embedded /admin console (generated from admin.html +
// the wallet project's nacl.js; regenerate rather than editing the strings).
#include "admin_ui.hpp"

namespace r2r::admin_ui {

const char* html() {
    return R"R2RADM(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>R2R relay admin</title>
<style>
:root{color-scheme:dark;--bg:#0e1013;--fg:#e8e9ec;--mut:#9aa1ab;--line:#23262d;--card:#15181d;--acc:#0EADB5;--warn:#f26430;--err:#f88}
*{box-sizing:border-box}
body{margin:0;padding:1.5rem;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,system-ui,sans-serif}
main{max-width:72rem;margin:0 auto}
h1{font-size:1.3rem;margin:0 0 .2rem}
p.sub{color:var(--mut);margin:0 0 1.2rem;font-size:.9rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:1rem;margin-bottom:1rem}
input,select,button{font:inherit;color:inherit;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:.45rem .6rem}
input:focus,select:focus{outline:1px solid var(--acc)}
button{cursor:pointer;background:var(--acc);border:0;color:#fff}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--fg)}
button.danger{background:var(--warn)}
button:disabled{opacity:.4;cursor:default}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{color:var(--mut);text-transform:uppercase;font-size:.7rem;letter-spacing:.06em;text-align:left}
th,td{padding:.4rem .5rem;border-top:1px solid var(--line);vertical-align:middle}
tr:first-child th{border-top:0}
code{font-family:ui-monospace,Menlo,monospace;font-size:.82rem}
.mut{color:var(--mut)}.err{color:var(--err)}
.tabs{display:flex;gap:.5rem;margin-bottom:1rem}
.tabs button{background:transparent;border:1px solid var(--line);color:var(--mut)}
.tabs button.on{border-color:var(--acc);color:var(--fg)}
#banner{position:sticky;top:0;background:var(--warn);color:#fff;padding:.5rem .8rem;border-radius:6px;margin-bottom:1rem;display:none}
.row-actions{display:flex;gap:.35rem;flex-wrap:wrap}
.row-actions input{width:4.5rem;padding:.25rem .4rem}
.pillstate{padding:.1rem .5rem;border-radius:99px;font-size:.72rem;border:1px solid var(--line)}
.pillstate.open{color:#79d0a3}.pillstate.burned{color:var(--mut)}.pillstate.revoked{color:var(--err)}
.newcodes code{display:block;padding:.3rem .5rem;background:var(--bg);border-radius:6px;margin:.25rem 0;user-select:all}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
@media(max-width:800px){.grid2{grid-template-columns:1fr}}
.tblwrap{overflow-x:auto}
</style>
</head>
<body>
<main>
<h1>R2R relay admin</h1>
<p class="sub">Owner console — signs every action with your identity key; the key never leaves this page.</p>
<div id="banner"></div>

<div class="card" id="login-card">
  <label class="mut" for="seed">Identity seed (64 hex characters — from your wallet, or the key file used with <code>--owner-add</code>)</label><br>
  <input id="seed" type="password" size="70" autocomplete="off" placeholder="identity seed">
  <button id="login-btn">Unlock</button>
  <div id="login-msg" class="mut" style="margin-top:.5rem"></div>
</div>

<div id="console" style="display:none">
  <div class="card" id="whoami"></div>
  <div class="tabs">
    <button data-tab="accounts" class="on">Accounts</button>
    <button data-tab="invites">Invites</button>
    <button data-tab="market">Market</button>
    <button data-tab="relay">Relay</button>
  </div>

  <div class="card tab" id="tab-accounts">
    <div style="display:flex;gap:.5rem;margin-bottom:.7rem">
      <input id="acct-q" placeholder="fingerprint prefix or relay text" size="34">
      <button id="acct-search">Search</button>
      <button class="ghost" id="acct-reload">All accounts</button>
    </div>
    <div class="tblwrap"><table id="acct-table"></table></div>
  </div>

  <div class="card tab" id="tab-invites" style="display:none">
    <div style="display:flex;gap:.5rem;margin-bottom:.7rem;align-items:center">
      <select id="inv-state"><option value="all">all</option><option value="open">open</option><option value="burned">burned</option><option value="revoked">revoked</option></select>
      <button id="inv-reload">Refresh</button>
      <span style="flex:1"></span>
      <input id="inv-count" type="number" min="1" max="50" value="3" style="width:4rem">
      <button id="inv-mint">Mint codes</button>
    </div>
    <div class="newcodes" id="inv-new"></div>
    <div class="tblwrap"><table id="inv-table"></table></div>
  </div>

  <div class="card tab" id="tab-market" style="display:none">
    <div id="mkt-summary" class="mut" style="margin-bottom:.7rem"></div>
    <h3 style="margin:.2rem 0 .5rem">Rentals</h3>
    <div class="tblwrap"><table id="mkt-rentals"></table></div>
    <h3 style="margin:1rem 0 .5rem">Settlement vouchers</h3>
    <p class="mut">Newest signed voucher per payer — redeem them against the vault from your own
    browser wallet (the relay holds no chain keys). The export contains everything
    <code>redeemBatch()</code> needs.</p>
    <div style="display:flex;gap:.5rem;margin-bottom:.7rem">
      <button id="mkt-reload" class="ghost">Refresh</button>
      <button id="mkt-export">Download settlement JSON</button>
    </div>
    <div class="tblwrap"><table id="mkt-vouchers"></table></div>
  </div>

  <div class="card tab" id="tab-relay" style="display:none">
    <div class="grid2">
      <div>
        <h3 style="margin-top:0">Advertised address</h3>
        <p class="mut">What peers dial and what the doorway shows as this relay's host. Changing it re-renders the site immediately and survives restarts.</p>
        <input id="adv-host" placeholder="host:port" size="28">
        <button id="adv-set">Change</button>
      </div>
      <div>
        <h3 style="margin-top:0">This session</h3>
        <div id="relay-info" class="mut"></div>
      </div>
    </div>
  </div>
</div>
</main>

<script src="{{BASE}}/admin/nacl.js"></script>
<script>
'use strict';
var BASE = "{{BASE}}";

/* ---- crypto core (mirrored by the node-side test) ---- */
function hexToBytes(h){var o=new Uint8Array(h.length/2);for(var i=0;i<o.length;i++)o[i]=parseInt(h.substr(2*i,2),16);return o}
function bytesToHex(b){var s="";for(var i=0;i<b.length;i++)s+=(b[i]<16?"0":"")+b[i].toString(16);return s}
function bytesToB64(b){var s="";for(var i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s)}
function utf8(s){return new TextEncoder().encode(s)}
async function fingerprintOf(pub){
  var dom=utf8("r2r-id-v1"),buf=new Uint8Array(dom.length+pub.length);
  buf.set(dom,0);buf.set(pub,dom.length);
  var d=await crypto.subtle.digest("SHA-256",buf);
  return bytesToHex(new Uint8Array(d));
}
function authSig(kp,fp,ts,nonce){
  return bytesToB64(nacl.sign.detached(utf8("r2r-client-v1\n"+fp+"\n"+ts+"\n"+nonce),kp.secretKey));
}
function signedIdentity(kp,fp){
  var ts=Math.floor(Date.now()/1000),nonce=bytesToHex(nacl.randomBytes(12));
  return {id:fp,pubkey:bytesToB64(kp.publicKey),ts:ts,nonce:nonce,sig:authSig(kp,fp,ts,nonce)};
}
/* ---- end crypto core ---- */

var kp=null,fp=null,ws=null,welcome=null,waiters={};
var $=function(id){return document.getElementById(id)};

function banner(msg,ok){var b=$("banner");if(!msg){b.style.display="none";return}b.style.display="block";b.style.background=ok?"#2f6f4f":"#a33";b.textContent=msg}

function request(frame,replyTypes){
  return new Promise(function(res,rej){
    if(!ws||ws.readyState!==1)return rej(new Error("not connected"));
    var types=replyTypes||[frame.t,"admin_ok"];
    types.forEach(function(t){waiters[t]=waiters[t]||[];waiters[t].push({res:res,rej:rej})});
    waiters["err"]=waiters["err"]||[];waiters["err"].push({res:null,rej:rej});
    ws.send(JSON.stringify(frame));
  });
}
function dispatch(m){
  var t=m.t;
  if(t==="err"){
    (waiters["err"]||[]).splice(0).forEach(function(w){w.rej(new Error(m.code+(m.msg?": "+m.msg:"")))});
    Object.keys(waiters).forEach(function(k){if(k!=="err")waiters[k]=[]});
    return;
  }
  var q=waiters[t];
  if(q&&q.length){q.splice(0).forEach(function(w){if(w.res)w.res(m)});waiters["err"]=[]}
}

async function login(){
  var seed=$("seed").value.trim().toLowerCase();
  if(!/^[0-9a-f]{64}$/.test(seed)){$("login-msg").textContent="the seed is 64 hex characters";return}
  if(!window.crypto||!crypto.subtle){$("login-msg").innerHTML="this page needs a secure context (https:// or localhost) for SHA-256";return}
  kp=nacl.sign.keyPair.fromSeed(hexToBytes(seed));
  fp=await fingerprintOf(kp.publicKey);
  $("login-msg").textContent="identity "+fp.slice(0,16)+"… — connecting…";
  connect();
}
function connect(){
  var url=(location.protocol==="https:"?"wss":"ws")+"://"+location.host+BASE+"/ws";
  ws=new WebSocket(url);
  ws.onopen=function(){
    var hello=signedIdentity(kp,fp);hello.t="hello";
    ws.send(JSON.stringify(hello));
  };
  ws.onmessage=function(ev){
    var m;try{m=JSON.parse(ev.data)}catch(e){return}
    if(m.t==="welcome"){
      welcome=m;
      if(!m.owner){$("login-msg").innerHTML="<span class=err>Connected, but this identity is not an owner of this relay. Add it with:</span> <code>r2r-relay --owner-add "+fp+"</code>";ws.close();return}
      $("login-card").style.display="none";$("console").style.display="block";
      $("whoami").innerHTML="Owner <code>"+fp.slice(0,16)+"…</code> on <code>"+location.host+"</code>"+
        " · storage "+fmtBytes(m.used_bytes||0)+" / "+fmtBytes(m.quota_bytes||0)+
        " · "+(m.peers||0)+" verified peers · retention "+(m.ttl_days||"?")+" days";
      $("relay-info").innerHTML="proto "+m.proto+" · node <code>"+(m.node_id||"").slice(0,16)+"…</code>";
      loadAccounts();loadInvites();
      return;
    }
    dispatch(m);
  };
  ws.onclose=function(){if(welcome&&welcome.owner)banner("connection lost — reload to reconnect")};
}

function fmtBytes(n){if(n>=1048576)return (n/1048576).toFixed(1)+" MB";if(n>=1024)return (n/1024).toFixed(0)+" KB";return n+" B"}
function fmtWhen(ts){return ts?new Date(ts*1000).toISOString().slice(0,16).replace("T"," "):"—"}
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c]})}

/* ---- accounts ---- */
function renderAccounts(rows){
  var h="<tr><th>identity</th><th>home relay</th><th>used / quota</th><th>pending</th><th>seen</th><th></th></tr>";
  rows.forEach(function(a){
    h+="<tr><td><code title=\""+esc(a.id)+"\">"+esc(a.id.slice(0,12))+"…</code>"+(a.online?" <span class=pillstate style='color:#79d0a3'>online</span>":"")+"</td>"+
      "<td class=mut>"+esc(a.home_relay||"—")+"</td>"+
      "<td>"+fmtBytes(a.used_bytes)+" / "+fmtBytes(a.quota_bytes)+(a.custom_quota?" *":"")+"</td>"+
      "<td>"+a.pending+"</td><td class=mut>"+fmtWhen(a.last_seen)+"</td>"+
      "<td><div class=row-actions>"+
      "<input placeholder=MB data-quota=\""+esc(a.id)+"\"><button class=ghost data-setquota=\""+esc(a.id)+"\">quota</button>"+
      "<input placeholder=days data-ttl=\""+esc(a.id)+"\"><button class=ghost data-setttl=\""+esc(a.id)+"\">ttl</button>"+
      "<button class=danger data-del=\""+esc(a.id)+"\">delete</button>"+
      "</div></td></tr>";
  });
  $("acct-table").innerHTML=h;
}
function loadAccounts(){request({t:"admin_accounts",max:200}).then(function(m){renderAccounts(m.accounts)}).catch(function(e){banner(e.message)})}
$("acct-reload").onclick=loadAccounts;
$("acct-search").onclick=function(){
  var q=$("acct-q").value.trim();if(!q)return loadAccounts();
  request({t:"admin_search_accounts",q:q}).then(function(m){renderAccounts(m.accounts)}).catch(function(e){banner(e.message)});
};
$("acct-table").onclick=function(ev){
  var b=ev.target;
  if(b.dataset.setquota){
    var mb=document.querySelector("input[data-quota=\""+b.dataset.setquota+"\"]").value.trim();
    var frame={t:"admin_set_quota",id:b.dataset.setquota,mb:mb===""?null:parseInt(mb,10)};
    request(frame).then(function(){banner("quota updated",true);loadAccounts()}).catch(function(e){banner(e.message)});
  }
  if(b.dataset.setttl){
    var d=document.querySelector("input[data-ttl=\""+b.dataset.setttl+"\"]").value.trim();
    var f={t:"admin_set_ttl",id:b.dataset.setttl,days:d===""?null:parseInt(d,10)};
    request(f).then(function(){banner("retention updated",true);loadAccounts()}).catch(function(e){banner(e.message)});
  }
  if(b.dataset.del){
    if(!confirm("Delete "+b.dataset.del.slice(0,16)+"…?\n\nEverything it stores — waiting messages, history, recordings — is removed permanently."))return;
    request({t:"admin_delete_account",id:b.dataset.del}).then(function(){banner("account deleted",true);loadAccounts()}).catch(function(e){banner(e.message)});
  }
};

/* ---- invites ---- */
function loadInvites(){
  request({t:"admin_list_invites",state:$("inv-state").value,max:200}).then(function(m){
    var h="<tr><th>code</th><th>state</th><th>minted</th><th>by</th><th>parent</th><th></th></tr>";
    m.invites.forEach(function(r){
      h+="<tr><td><code>"+esc(r.code)+"</code></td>"+
        "<td><span class=\"pillstate "+r.state+"\">"+r.state+"</span></td>"+
        "<td class=mut>"+fmtWhen(r.created_at)+"</td>"+
        "<td class=mut><code>"+esc((r.issued_by||"").slice(0,10))+"</code></td>"+
        "<td class=mut><code>"+esc((r.parent_code||"").slice(0,14))+"</code></td>"+
        "<td>"+(r.state==="open"?"<button class=danger data-revoke=\""+esc(r.code)+"\">revoke tree</button>":"")+"</td></tr>";
    });
    $("inv-table").innerHTML=h;
  }).catch(function(e){banner(e.message)});
}
$("inv-reload").onclick=loadInvites;
$("inv-state").onchange=loadInvites;
$("inv-mint").onclick=function(){
  request({t:"admin_invites",count:parseInt($("inv-count").value,10)||3}).then(function(m){
    var h="<p>New codes — each is single use; share as <code>https://"+esc(location.host)+esc(BASE)+"/&lt;code&gt;</code>:</p>";
    (m.invites||[]).forEach(function(c){h+="<code>"+esc(c)+"</code>"});
    $("inv-new").innerHTML=h;loadInvites();
  }).catch(function(e){banner(e.message)});
};
$("inv-table").onclick=function(ev){
  var b=ev.target;
  if(b.dataset.revoke){
    if(!confirm("Revoke "+b.dataset.revoke+" and every unused code descended from it?"))return;
    request({t:"admin_revoke_invite",code:b.dataset.revoke,cascade:true}).then(function(m){
      banner("revoked "+(m.revoked+m.cascaded)+" code(s)",true);loadInvites();
    }).catch(function(e){banner(e.message)});
  }
};

/* ---- market ---- */
var mktLast=null;
function fmtMicro(n){return (n/1e6).toLocaleString(undefined,{maximumFractionDigits:6})+" USDC"}
function loadMarket(){
  request({t:"admin_list_rentals"}).then(function(m){
    var off=!m.pool_bytes;
    $("mkt-summary").innerHTML=off
      ?"Market is off — set <code>--pool-market-mb</code> and <code>--payout-address</code> to sell storage."
      :"Pool "+fmtBytes(m.pool_bytes)+" · committed "+fmtBytes(m.committed_bytes)+
       " · free "+fmtBytes(Math.max(0,m.pool_bytes-m.committed_bytes));
    var h="<tr><th>rental</th><th>renter</th><th>size</th><th>price/epoch</th><th>paid until</th><th>state</th></tr>";
    (m.rentals||[]).forEach(function(r){
      h+="<tr><td><code>"+esc(r.id.slice(0,8))+"…</code></td>"+
        "<td><code title=\""+esc(r.fingerprint)+"\">"+esc(r.fingerprint.slice(0,12))+"…</code></td>"+
        "<td>"+fmtBytes(r.bytes)+"</td><td>"+fmtMicro(r.price_epoch_micro)+"</td>"+
        "<td class=mut>"+fmtWhen(r.paid_until)+"</td>"+
        "<td><span class=\"pillstate "+(r.state==="active"?"open":"revoked")+"\">"+esc(r.state)+"</span></td></tr>";
    });
    $("mkt-rentals").innerHTML=h;
  }).catch(function(e){banner(e.message)});
  request({t:"admin_list_vouchers"}).then(function(m){
    mktLast=m;
    var h="<tr><th>payer</th><th>cumulative</th><th>signed</th></tr>";
    (m.vouchers||[]).forEach(function(v){
      h+="<tr><td><code>"+esc(v.payment_key)+"</code></td>"+
        "<td>"+fmtMicro(v.cumulative_micro)+"</td>"+
        "<td class=mut>"+fmtWhen(v.created_at)+"</td></tr>";
    });
    $("mkt-vouchers").innerHTML=h+
      "<tr><td class=mut>total</td><td>"+fmtMicro(m.cumulative_total_micro||0)+"</td><td></td></tr>";
  }).catch(function(e){banner(e.message)});
}
$("mkt-reload").onclick=loadMarket;
$("mkt-export").onclick=function(){
  if(!mktLast)return;
  var blob=new Blob([JSON.stringify(mktLast,null,1)],{type:"application/json"});
  var a=document.createElement("a");
  a.href=URL.createObjectURL(blob);
  a.download="r2r-settlement-"+location.hostname+"-"+new Date().toISOString().slice(0,10)+".json";
  a.click();URL.revokeObjectURL(a.href);
};

/* ---- relay ---- */
$("adv-set").onclick=function(){
  var host=$("adv-host").value.trim();if(!host)return;
  if(!confirm("Advertise this relay as "+host+"?\nPeers and the doorway switch to it immediately."))return;
  request({t:"admin_set_advertise",host:host}).then(function(m){
    banner("now advertising as "+m.advertise,true);
  }).catch(function(e){banner(e.message)});
};

/* ---- tabs & login ---- */
document.querySelectorAll(".tabs button").forEach(function(b){
  b.onclick=function(){
    document.querySelectorAll(".tabs button").forEach(function(x){x.classList.remove("on")});
    b.classList.add("on");
    document.querySelectorAll(".tab").forEach(function(x){x.style.display="none"});
    $("tab-"+b.dataset.tab).style.display="block";
    if(b.dataset.tab==="market")loadMarket();
  };
});
$("login-btn").onclick=login;
$("seed").addEventListener("keydown",function(e){if(e.key==="Enter")login()});
</script>
</body>
</html>
)R2RADM";
}

const char* nacl_js() {
    return R"R2RNACL(
!function(i){"use strict";var m=function(r,n){this.hi=0|r,this.lo=0|n},v=function(r){var n,e=new Float64Array(16);if(r)for(n=0;n<r.length;n++)e[n]=r[n];return e},a=function(){throw new Error("no PRNG")},o=new Uint8Array(16),e=new Uint8Array(32);e[0]=9;var c=v(),w=v([1]),g=v([56129,1]),y=v([30883,4953,19914,30187,55467,16705,2637,112,59544,30585,16505,36039,65139,11119,27886,20995]),l=v([61785,9906,39828,60374,45398,33411,5274,224,53552,61171,33010,6542,64743,22239,55772,9222]),t=v([54554,36645,11616,51542,42930,38181,51040,26924,56412,64982,57905,49316,21502,52590,14035,8553]),f=v([26200,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214]),s=v([41136,18958,6951,50414,58488,44335,6150,12099,55207,15867,153,11085,57099,20417,9344,11139]);function h(r,n){return r<<n|r>>>32-n}function b(r,n){var e=255&r[n+3];return(e=(e=e<<8|255&r[n+2])<<8|255&r[n+1])<<8|255&r[n+0]}function B(r,n){var e=r[n]<<24|r[n+1]<<16|r[n+2]<<8|r[n+3],t=r[n+4]<<24|r[n+5]<<16|r[n+6]<<8|r[n+7];return new m(e,t)}function p(r,n,e){var t;for(t=0;t<4;t++)r[n+t]=255&e,e>>>=8}function S(r,n,e){r[n]=e.hi>>24&255,r[n+1]=e.hi>>16&255,r[n+2]=e.hi>>8&255,r[n+3]=255&e.hi,r[n+4]=e.lo>>24&255,r[n+5]=e.lo>>16&255,r[n+6]=e.lo>>8&255,r[n+7]=255&e.lo}function u(r,n,e,t,o){var i,a=0;for(i=0;i<o;i++)a|=r[n+i]^e[t+i];return(1&a-1>>>8)-1}function A(r,n,e,t){return u(r,n,e,t,16)}function _(r,n,e,t){return u(r,n,e,t,32)}function U(r,n,e,t,o){var i,a,f,u=new Uint32Array(16),c=new Uint32Array(16),w=new Uint32Array(16),y=new Uint32Array(4);for(i=0;i<4;i++)c[5*i]=b(t,4*i),c[1+i]=b(e,4*i),c[6+i]=b(n,4*i),c[11+i]=b(e,16+4*i);for(i=0;i<16;i++)w[i]=c[i];for(i=0;i<20;i++){for(a=0;a<4;a++){for(f=0;f<4;f++)y[f]=c[(5*a+4*f)%16];for(y[1]^=h(y[0]+y[3]|0,7),y[2]^=h(y[1]+y[0]|0,9),y[3]^=h(y[2]+y[1]|0,13),y[0]^=h(y[3]+y[2]|0,18),f=0;f<4;f++)u[4*a+(a+f)%4]=y[f]}for(f=0;f<16;f++)c[f]=u[f]}if(o){for(i=0;i<16;i++)c[i]=c[i]+w[i]|0;for(i=0;i<4;i++)c[5*i]=c[5*i]-b(t,4*i)|0,c[6+i]=c[6+i]-b(n,4*i)|0;for(i=0;i<4;i++)p(r,4*i,c[5*i]),p(r,16+4*i,c[6+i])}else for(i=0;i<16;i++)p(r,4*i,c[i]+w[i]|0)}function E(r,n,e,t){U(r,n,e,t,!1)}function x(r,n,e,t){return U(r,n,e,t,!0),0}var d=new Uint8Array([101,120,112,97,110,100,32,51,50,45,98,121,116,101,32,107]);function K(r,n,e,t,o,i,a){var f,u,c=new Uint8Array(16),w=new Uint8Array(64);if(!o)return 0;for(u=0;u<16;u++)c[u]=0;for(u=0;u<8;u++)c[u]=i[u];for(;64<=o;){for(E(w,c,a,d),u=0;u<64;u++)r[n+u]=(e?e[t+u]:0)^w[u];for(f=1,u=8;u<16;u++)f=f+(255&c[u])|0,c[u]=255&f,f>>>=8;o-=64,n+=64,e&&(t+=64)}if(0<o)for(E(w,c,a,d),u=0;u<o;u++)r[n+u]=(e?e[t+u]:0)^w[u];return 0}function Y(r,n,e,t,o){return K(r,n,null,0,e,t,o)}function L(r,n,e,t,o){var i=new Uint8Array(32);return x(i,t,o,d),Y(r,n,e,t.subarray(16),i)}function T(r,n,e,t,o,i,a){var f=new Uint8Array(32);return x(f,i,a,d),K(r,n,e,t,o,i.subarray(16),f)}function k(r,n){var e,t=0;for(e=0;e<17;e++)t=t+(r[e]+n[e]|0)|0,r[e]=255&t,t>>>=8}var z=new Uint32Array([5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,252]);function R(r,n,e,t,o,i){var a,f,u,c,w=new Uint32Array(17),y=new Uint32Array(17),l=new Uint32Array(17),s=new Uint32Array(17),h=new Uint32Array(17);for(u=0;u<17;u++)y[u]=l[u]=0;for(u=0;u<16;u++)y[u]=i[u];for(y[3]&=15,y[4]&=252,y[7]&=15,y[8]&=252,y[11]&=15,y[12]&=252,y[15]&=15;0<o;){for(u=0;u<17;u++)s[u]=0;for(u=0;u<16&&u<o;++u)s[u]=e[t+u];for(s[u]=1,t+=u,o-=u,k(l,s),f=0;f<17;f++)for(u=w[f]=0;u<17;u++)w[f]=w[f]+l[u]*(u<=f?y[f-u]:320*y[f+17-u]|0)|0;for(f=0;f<17;f++)l[f]=w[f];for(u=c=0;u<16;u++)c=c+l[u]|0,l[u]=255&c,c>>>=8;for(c=c+l[16]|0,l[16]=3&c,c=5*(c>>>2)|0,u=0;u<16;u++)c=c+l[u]|0,l[u]=255&c,c>>>=8;c=c+l[16]|0,l[16]=c}for(u=0;u<17;u++)h[u]=l[u];for(k(l,z),a=0|-(l[16]>>>7),u=0;u<17;u++)l[u]^=a&(h[u]^l[u]);for(u=0;u<16;u++)s[u]=i[u+16];for(s[16]=0,k(l,s),u=0;u<16;u++)r[n+u]=l[u];return 0}function P(r,n,e,t,o,i){var a=new Uint8Array(16);return R(a,0,e,t,o,i),A(r,n,a,0)}function M(r,n,e,t,o){var i;if(e<32)return-1;for(T(r,0,n,0,e,t,o),R(r,16,r,32,e-32,r),i=0;i<16;i++)r[i]=0;return 0}function N(r,n,e,t,o){var i,a=new Uint8Array(32);if(e<32)return-1;if(L(a,0,32,t,o),0!==P(n,16,n,32,e-32,a))return-1;for(T(r,0,n,0,e,t,o),i=0;i<32;i++)r[i]=0;return 0}function O(r,n){var e;for(e=0;e<16;e++)r[e]=0|n[e]}function C(r){var n,e;for(e=0;e<16;e++)r[e]+=65536,n=Math.floor(r[e]/65536),r[(e+1)*(e<15?1:0)]+=n-1+37*(n-1)*(15===e?1:0),r[e]-=65536*n}function F(r,n,e){for(var t,o=~(e-1),i=0;i<16;i++)t=o&(r[i]^n[i]),r[i]^=t,n[i]^=t}function Z(r,n){var e,t,o,i=v(),a=v();for(e=0;e<16;e++)a[e]=n[e];for(C(a),C(a),C(a),t=0;t<2;t++){for(i[0]=a[0]-65517,e=1;e<15;e++)i[e]=a[e]-65535-(i[e-1]>>16&1),i[e-1]&=65535;i[15]=a[15]-32767-(i[14]>>16&1),o=i[15]>>16&1,i[14]&=65535,F(a,i,1-o)}for(e=0;e<16;e++)r[2*e]=255&a[e],r[2*e+1]=a[e]>>8}function G(r,n){var e=new Uint8Array(32),t=new Uint8Array(32);return Z(e,r),Z(t,n),_(e,0,t,0)}function q(r){var n=new Uint8Array(32);return Z(n,r),1&n[0]}function D(r,n){var e;for(e=0;e<16;e++)r[e]=n[2*e]+(n[2*e+1]<<8);r[15]&=32767}function I(r,n,e){var t;for(t=0;t<16;t++)r[t]=n[t]+e[t]|0}function V(r,n,e){var t;for(t=0;t<16;t++)r[t]=n[t]-e[t]|0}function X(r,n,e){var t,o,i=new Float64Array(31);for(t=0;t<31;t++)i[t]=0;for(t=0;t<16;t++)for(o=0;o<16;o++)i[t+o]+=n[t]*e[o];for(t=0;t<15;t++)i[t]+=38*i[t+16];for(t=0;t<16;t++)r[t]=i[t];C(r),C(r)}function j(r,n){X(r,n,n)}function H(r,n){var e,t=v();for(e=0;e<16;e++)t[e]=n[e];for(e=253;0<=e;e--)j(t,t),2!==e&&4!==e&&X(t,t,n);for(e=0;e<16;e++)r[e]=t[e]}function J(r,n){var e,t=v();for(e=0;e<16;e++)t[e]=n[e];for(e=250;0<=e;e--)j(t,t),1!==e&&X(t,t,n);for(e=0;e<16;e++)r[e]=t[e]}function Q(r,n,e){var t,o,i=new Uint8Array(32),a=new Float64Array(80),f=v(),u=v(),c=v(),w=v(),y=v(),l=v();for(o=0;o<31;o++)i[o]=n[o];for(i[31]=127&n[31]|64,i[0]&=248,D(a,e),o=0;o<16;o++)u[o]=a[o],w[o]=f[o]=c[o]=0;for(f[0]=w[0]=1,o=254;0<=o;--o)F(f,u,t=i[o>>>3]>>>(7&o)&1),F(c,w,t),I(y,f,c),V(f,f,c),I(c,u,w),V(u,u,w),j(w,y),j(l,f),X(f,c,f),X(c,u,y),I(y,f,c),V(f,f,c),j(u,f),V(c,w,l),X(f,c,g),I(f,f,w),X(c,c,f),X(f,w,l),X(w,u,a),j(u,y),F(f,u,t),F(c,w,t);for(o=0;o<16;o++)a[o+16]=f[o],a[o+32]=c[o],a[o+48]=u[o],a[o+64]=w[o];var s=a.subarray(32),h=a.subarray(16);return H(s,s),X(h,h,s),Z(r,h),0}function W(r,n){return Q(r,n,e)}function $(r,n){return a(n,32),W(r,n)}function rr(r,n,e){var t=new Uint8Array(32);return Q(t,e,n),x(r,o,t,d)}var nr=M,er=N;function tr(){var r,n,e,t=0,o=0,i=0,a=0,f=65535;for(e=0;e<arguments.length;e++)t+=(r=arguments[e].lo)&f,o+=r>>>16,i+=(n=arguments[e].hi)&f,a+=n>>>16;return new m((i+=(o+=t>>>16)>>>16)&f|(a+=i>>>16)<<16,t&f|o<<16)}function or(r,n){return new m(r.hi>>>n,r.lo>>>n|r.hi<<32-n)}function ir(){var r,n=0,e=0;for(r=0;r<arguments.length;r++)n^=arguments[r].lo,e^=arguments[r].hi;return new m(e,n)}function ar(r,n){var e,t,o=32-n;return n<32?(e=r.hi>>>n|r.lo<<o,t=r.lo>>>n|r.hi<<o):n<64&&(e=r.lo>>>n|r.hi<<o,t=r.hi>>>n|r.lo<<o),new m(e,t)}var fr=[new m(1116352408,3609767458),new m(1899447441,602891725),new m(3049323471,3964484399),new m(3921009573,2173295548),new m(961987163,4081628472),new m(1508970993,3053834265),new m(2453635748,2937671579),new m(2870763221,3664609560),new m(3624381080,2734883394),new m(310598401,1164996542),new m(607225278,1323610764),new m(1426881987,3590304994),new m(1925078388,4068182383),new m(2162078206,991336113),new m(2614888103,633803317),new m(3248222580,3479774868),new m(3835390401,2666613458),new m(4022224774,944711139),new m(264347078,2341262773),new m(604807628,2007800933),new m(770255983,1495990901),new m(1249150122,1856431235),new m(1555081692,3175218132),new m(1996064986,2198950837),new m(2554220882,3999719339),new m(2821834349,766784016),new m(2952996808,2566594879),new m(3210313671,3203337956),new m(3336571891,1034457026),new m(3584528711,2466948901),new m(113926993,3758326383),new m(338241895,168717936),new m(666307205,1188179964),new m(773529912,1546045734),new m(1294757372,1522805485),new m(1396182291,2643833823),new m(1695183700,2343527390),new m(1986661051,1014477480),new m(2177026350,1206759142),new m(2456956037,344077627),new m(2730485921,1290863460),new m(2820302411,3158454273),new m(3259730800,3505952657),new m(3345764771,106217008),new m(3516065817,3606008344),new m(3600352804,1432725776),new m(4094571909,1467031594),new m(275423344,851169720),new m(430227734,3100823752),new m(506948616,1363258195),new m(659060556,3750685593),new m(883997877,3785050280),new m(958139571,3318307427),new m(1322822218,3812723403),new m(1537002063,2003034995),new m(1747873779,3602036899),new m(1955562222,1575990012),new m(2024104815,1125592928),new m(2227730452,2716904306),new m(2361852424,442776044),new m(2428436474,593698344),new m(2756734187,3733110249),new m(3204031479,2999351573),new m(3329325298,3815920427),new m(3391569614,3928383900),new m(3515267271,566280711),new m(3940187606,3454069534),new m(4118630271,4000239992),new m(116418474,1914138554),new m(174292421,2731055270),new m(289380356,3203993006),new m(460393269,320620315),new m(685471733,587496836),new m(852142971,1086792851),new m(1017036298,365543100),new m(1126000580,2618297676),new m(1288033470,3409855158),new m(1501505948,4234509866),new m(1607167915,987167468),new m(1816402316,1246189591)];function ur(r,n,e){var t,o,i,a=[],f=[],u=[],c=[];for(o=0;o<8;o++)a[o]=u[o]=B(r,8*o);for(var w,y,l,s,h,v,g,b,p,A,_,U,E,x,d=0;128<=e;){for(o=0;o<16;o++)c[o]=B(n,8*o+d);for(o=0;o<80;o++){for(i=0;i<8;i++)f[i]=u[i];for(t=tr(u[7],ir(ar(x=u[4],14),ar(x,18),ar(x,41)),(p=u[4],A=u[5],_=u[6],0,U=p.hi&A.hi^~p.hi&_.hi,E=p.lo&A.lo^~p.lo&_.lo,new m(U,E)),fr[o],c[o%16]),f[7]=tr(t,ir(ar(b=u[0],28),ar(b,34),ar(b,39)),(l=u[0],s=u[1],h=u[2],0,v=l.hi&s.hi^l.hi&h.hi^s.hi&h.hi,g=l.lo&s.lo^l.lo&h.lo^s.lo&h.lo,new m(v,g))),f[3]=tr(f[3],t),i=0;i<8;i++)u[(i+1)%8]=f[i];if(o%16==15)for(i=0;i<16;i++)c[i]=tr(c[i],c[(i+9)%16],ir(ar(y=c[(i+1)%16],1),ar(y,8),or(y,7)),ir(ar(w=c[(i+14)%16],19),ar(w,61),or(w,6)))}for(o=0;o<8;o++)u[o]=tr(u[o],a[o]),a[o]=u[o];d+=128,e-=128}for(o=0;o<8;o++)S(r,8*o,a[o]);return e}var cr=new Uint8Array([106,9,230,103,243,188,201,8,187,103,174,133,132,202,167,59,60,110,243,114,254,148,248,43,165,79,245,58,95,29,54,241,81,14,82,127,173,230,130,209,155,5,104,140,43,62,108,31,31,131,217,171,251,65,189,107,91,224,205,25,19,126,33,121]);function wr(r,n,e){var t,o=new Uint8Array(64),i=new Uint8Array(256),a=e;for(t=0;t<64;t++)o[t]=cr[t];for(ur(o,n,e),e%=128,t=0;t<256;t++)i[t]=0;for(t=0;t<e;t++)i[t]=n[a-e+t];for(i[e]=128,i[(e=256-128*(e<112?1:0))-9]=0,S(i,e-8,new m(a/536870912|0,a<<3)),ur(o,i,e),t=0;t<64;t++)r[t]=o[t];return 0}function yr(r,n){var e=v(),t=v(),o=v(),i=v(),a=v(),f=v(),u=v(),c=v(),w=v();V(e,r[1],r[0]),V(w,n[1],n[0]),X(e,e,w),I(t,r[0],r[1]),I(w,n[0],n[1]),X(t,t,w),X(o,r[3],n[3]),X(o,o,l),X(i,r[2],n[2]),I(i,i,i),V(a,t,e),V(f,i,o),I(u,i,o),I(c,t,e),X(r[0],a,f),X(r[1],c,u),X(r[2],u,f),X(r[3],a,c)}function lr(r,n,e){var t;for(t=0;t<4;t++)F(r[t],n[t],e)}function sr(r,n){var e=v(),t=v(),o=v();H(o,n[2]),X(e,n[0],o),X(t,n[1],o),Z(r,t),r[31]^=q(e)<<7}function hr(r,n,e){var t,o;for(O(r[0],c),O(r[1],w),O(r[2],w),O(r[3],c),o=255;0<=o;--o)lr(r,n,t=e[o/8|0]>>(7&o)&1),yr(n,r),yr(r,r),lr(r,n,t)}function vr(r,n){var e=[v(),v(),v(),v()];O(e[0],t),O(e[1],f),O(e[2],w),X(e[3],t,f),hr(r,e,n)}function gr(r,n,e){var t,o=new Uint8Array(64),i=[v(),v(),v(),v()];for(e||a(n,32),wr(o,n,32),o[0]&=248,o[31]&=127,o[31]|=64,vr(i,o),sr(r,i),t=0;t<32;t++)n[t+32]=r[t];return 0}var br=new Float64Array([237,211,245,92,26,99,18,88,214,156,247,162,222,249,222,20,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,16]);function pr(r,n){var e,t,o,i;for(t=63;32<=t;--t){for(e=0,o=t-32,i=t-12;o<i;++o)n[o]+=e-16*n[t]*br[o-(t-32)],e=Math.floor((n[o]+128)/256),n[o]-=256*e;n[o]+=e,n[t]=0}for(o=e=0;o<32;o++)n[o]+=e-(n[31]>>4)*br[o],e=n[o]>>8,n[o]&=255;for(o=0;o<32;o++)n[o]-=e*br[o];for(t=0;t<32;t++)n[t+1]+=n[t]>>8,r[t]=255&n[t]}function Ar(r){var n,e=new Float64Array(64);for(n=0;n<64;n++)e[n]=r[n];for(n=0;n<64;n++)r[n]=0;pr(r,e)}function _r(r,n,e,t){var o,i,a=new Uint8Array(64),f=new Uint8Array(64),u=new Uint8Array(64),c=new Float64Array(64),w=[v(),v(),v(),v()];wr(a,t,32),a[0]&=248,a[31]&=127,a[31]|=64;var y=e+64;for(o=0;o<e;o++)r[64+o]=n[o];for(o=0;o<32;o++)r[32+o]=a[32+o];for(wr(u,r.subarray(32),e+32),Ar(u),vr(w,u),sr(r,w),o=32;o<64;o++)r[o]=t[o];for(wr(f,r,e+64),Ar(f),o=0;o<64;o++)c[o]=0;for(o=0;o<32;o++)c[o]=u[o];for(o=0;o<32;o++)for(i=0;i<32;i++)c[o+i]+=f[o]*a[i];return pr(r.subarray(32),c),y}function Ur(r,n,e,t){var o,i=new Uint8Array(32),a=new Uint8Array(64),f=[v(),v(),v(),v()],u=[v(),v(),v(),v()];if(e<64)return-1;if(function(r,n){var e=v(),t=v(),o=v(),i=v(),a=v(),f=v(),u=v();if(O(r[2],w),D(r[1],n),j(o,r[1]),X(i,o,y),V(o,o,r[2]),I(i,r[2],i),j(a,i),j(f,a),X(u,f,a),X(e,u,o),X(e,e,i),J(e,e),X(e,e,o),X(e,e,i),X(e,e,i),X(r[0],e,i),j(t,r[0]),X(t,t,i),G(t,o)&&X(r[0],r[0],s),j(t,r[0]),X(t,t,i),G(t,o))return 1;q(r[0])===n[31]>>7&&V(r[0],c,r[0]),X(r[3],r[0],r[1])}(u,t))return-1;for(o=0;o<e;o++)r[o]=n[o];for(o=0;o<32;o++)r[o+32]=t[o];if(wr(a,r,e),Ar(a),hr(f,u,a),vr(u,n.subarray(32)),yr(f,u),sr(i,f),e-=64,_(n,0,i,0)){for(o=0;o<e;o++)r[o]=0;return-1}for(o=0;o<e;o++)r[o]=n[o+64];return e}function Er(r,n){if(32!==r.length)throw new Error("bad key size");if(24!==n.length)throw new Error("bad nonce size")}function xr(){for(var r=0;r<arguments.length;r++)if(!(arguments[r]instanceof Uint8Array))throw new TypeError("unexpected type, use Uint8Array")}function dr(r){for(var n=0;n<r.length;n++)r[n]=0}i.lowlevel={crypto_core_hsalsa20:x,crypto_stream_xor:T,crypto_stream:L,crypto_stream_salsa20_xor:K,crypto_stream_salsa20:Y,crypto_onetimeauth:R,crypto_onetimeauth_verify:P,crypto_verify_16:A,crypto_verify_32:_,crypto_secretbox:M,crypto_secretbox_open:N,crypto_scalarmult:Q,crypto_scalarmult_base:W,crypto_box_beforenm:rr,crypto_box_afternm:nr,crypto_box:function(r,n,e,t,o,i){var a=new Uint8Array(32);return rr(a,o,i),nr(r,n,e,t,a)},crypto_box_open:function(r,n,e,t,o,i){var a=new Uint8Array(32);return rr(a,o,i),er(r,n,e,t,a)},crypto_box_keypair:$,crypto_hash:wr,crypto_sign:_r,crypto_sign_keypair:gr,crypto_sign_open:Ur,crypto_secretbox_KEYBYTES:32,crypto_secretbox_NONCEBYTES:24,crypto_secretbox_ZEROBYTES:32,crypto_secretbox_BOXZEROBYTES:16,crypto_scalarmult_BYTES:32,crypto_scalarmult_SCALARBYTES:32,crypto_box_PUBLICKEYBYTES:32,crypto_box_SECRETKEYBYTES:32,crypto_box_BEFORENMBYTES:32,crypto_box_NONCEBYTES:24,crypto_box_ZEROBYTES:32,crypto_box_BOXZEROBYTES:16,crypto_sign_BYTES:64,crypto_sign_PUBLICKEYBYTES:32,crypto_sign_SECRETKEYBYTES:64,crypto_sign_SEEDBYTES:32,crypto_hash_BYTES:64,gf:v,D:y,L:br,pack25519:Z,unpack25519:D,M:X,A:I,S:j,Z:V,pow2523:J,add:yr,set25519:O,modL:pr,scalarmult:hr,scalarbase:vr},i.randomBytes=function(r){var n=new Uint8Array(r);return a(n,r),n},i.secretbox=function(r,n,e){xr(r,n,e),Er(e,n);for(var t=new Uint8Array(32+r.length),o=new Uint8Array(t.length),i=0;i<r.length;i++)t[i+32]=r[i];return M(o,t,t.length,n,e),o.subarray(16)},i.secretbox.open=function(r,n,e){xr(r,n,e),Er(e,n);for(var t=new Uint8Array(16+r.length),o=new Uint8Array(t.length),i=0;i<r.length;i++)t[i+16]=r[i];return t.length<32||0!==N(o,t,t.length,n,e)?null:o.subarray(32)},i.secretbox.keyLength=32,i.secretbox.nonceLength=24,i.secretbox.overheadLength=16,i.scalarMult=function(r,n){if(xr(r,n),32!==r.length)throw new Error("bad n size");if(32!==n.length)throw new Error("bad p size");var e=new Uint8Array(32);return Q(e,r,n),e},i.scalarMult.base=function(r){if(xr(r),32!==r.length)throw new Error("bad n size");var n=new Uint8Array(32);return W(n,r),n},i.scalarMult.scalarLength=32,i.scalarMult.groupElementLength=32,i.box=function(r,n,e,t){var o=i.box.before(e,t);return i.secretbox(r,n,o)},i.box.before=function(r,n){xr(r,n),function(r,n){if(32!==r.length)throw new Error("bad public key size");if(32!==n.length)throw new Error("bad secret key size")}(r,n);var e=new Uint8Array(32);return rr(e,r,n),e},i.box.after=i.secretbox,i.box.open=function(r,n,e,t){var o=i.box.before(e,t);return i.secretbox.open(r,n,o)},i.box.open.after=i.secretbox.open,i.box.keyPair=function(){var r=new Uint8Array(32),n=new Uint8Array(32);return $(r,n),{publicKey:r,secretKey:n}},i.box.keyPair.fromSecretKey=function(r){if(xr(r),32!==r.length)throw new Error("bad secret key size");var n=new Uint8Array(32);return W(n,r),{publicKey:n,secretKey:new Uint8Array(r)}},i.box.publicKeyLength=32,i.box.secretKeyLength=32,i.box.sharedKeyLength=32,i.box.nonceLength=24,i.box.overheadLength=i.secretbox.overheadLength,i.sign=function(r,n){if(xr(r,n),64!==n.length)throw new Error("bad secret key size");var e=new Uint8Array(64+r.length);return _r(e,r,r.length,n),e},i.sign.open=function(r,n){if(xr(r,n),32!==n.length)throw new Error("bad public key size");var e=new Uint8Array(r.length),t=Ur(e,r,r.length,n);if(t<0)return null;for(var o=new Uint8Array(t),i=0;i<o.length;i++)o[i]=e[i];return o},i.sign.detached=function(r,n){for(var e=i.sign(r,n),t=new Uint8Array(64),o=0;o<t.length;o++)t[o]=e[o];return t},i.sign.detached.verify=function(r,n,e){if(xr(r,n,e),64!==n.length)throw new Error("bad signature size");if(32!==e.length)throw new Error("bad public key size");var t,o=new Uint8Array(64+r.length),i=new Uint8Array(64+r.length);for(t=0;t<64;t++)o[t]=n[t];for(t=0;t<r.length;t++)o[t+64]=r[t];return 0<=Ur(i,o,o.length,e)},i.sign.keyPair=function(){var r=new Uint8Array(32),n=new Uint8Array(64);return gr(r,n),{publicKey:r,secretKey:n}},i.sign.keyPair.fromSecretKey=function(r){if(xr(r),64!==r.length)throw new Error("bad secret key size");for(var n=new Uint8Array(32),e=0;e<n.length;e++)n[e]=r[32+e];return{publicKey:n,secretKey:new Uint8Array(r)}},i.sign.keyPair.fromSeed=function(r){if(xr(r),32!==r.length)throw new Error("bad seed size");for(var n=new Uint8Array(32),e=new Uint8Array(64),t=0;t<32;t++)e[t]=r[t];return gr(n,e,!0),{publicKey:n,secretKey:e}},i.sign.publicKeyLength=32,i.sign.secretKeyLength=64,i.sign.seedLength=32,i.sign.signatureLength=64,i.hash=function(r){xr(r);var n=new Uint8Array(64);return wr(n,r,r.length),n},i.hash.hashLength=64,i.verify=function(r,n){return xr(r,n),0!==r.length&&0!==n.length&&(r.length===n.length&&0===u(r,0,n,0,r.length))},i.setPRNG=function(r){a=r},function(){var o="undefined"!=typeof self?self.crypto||self.msCrypto:null;if(o&&o.getRandomValues){i.setPRNG(function(r,n){var e,t=new Uint8Array(n);for(e=0;e<n;e+=65536)o.getRandomValues(t.subarray(e,e+Math.min(n-e,65536)));for(e=0;e<n;e++)r[e]=t[e];dr(t)})}else"undefined"!=typeof require&&(o=require("crypto"))&&o.randomBytes&&i.setPRNG(function(r,n){var e,t=o.randomBytes(n);for(e=0;e<n;e++)r[e]=t[e];dr(t)})}()}("undefined"!=typeof module&&module.exports?module.exports:self.nacl=self.nacl||{});
)R2RNACL";
}

}  // namespace r2r::admin_ui
