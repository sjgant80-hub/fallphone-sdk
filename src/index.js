// fallphone SDK · sovereign single-file library · MIT · AI-Native Solutions
// Extracted from fallphone/index.html · 15787 bytes of source logic
// Public-safe: no primes/glyphs/dyad references

// ============ Step navigation ============
function goStep(n){
    const s=parseInt(t.dataset.step);
    t.classList.toggle('on', s===n);
    if(s<n) t.classList.add('done');
  });
  localStorage.setItem('fp_step', n);
}
const savedStep = parseInt(localStorage.getItem('fp_step')||'1');
if(savedStep>1) goStep(savedStep);
// ============ FallID load ============
async function loadFallID(){
  s.textContent='Attempting FallID load from IndexedDB...';
  try{
    const req = indexedDB.open('fallid',1);
    const db = await new Promise((res,rej)=>{req.onsuccess=()=>res(req.result);req.onerror=()=>rej(req.error);req.onupgradeneeded=()=>req.result.createObjectStore('keys');});
    const tx = db.transaction('keys','readonly');
    const store = tx.objectStore('keys');
    const getReq = store.get('primary');
    const val = await new Promise(res=>{getReq.onsuccess=()=>res(getReq.result);getReq.onerror=()=>res(null);});
    if(val){s.textContent='FallID loaded · DID ready to encode.'; window._fallidKey = val;}
    else s.textContent='No FallID keypair found in this browser. Visit fallid first, or Generate will create a demo payload.';
  }catch(e){ s.textContent='FallID load error: '+e.message; }
}
// ============ AES-GCM encryption ============
async function deriveKey(pass, salt){
  const enc=new TextEncoder();
  const mat=await crypto.subtle.importKey('raw',enc.encode(pass),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:200000,hash:'SHA-256'},mat,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function encryptPayload(pass, secret){
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await deriveKey(pass,salt);
  const enc=new TextEncoder();
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(JSON.stringify(secret)));
  const combined=new Uint8Array(salt.length+iv.length+ct.byteLength);
  combined.set(salt,0);combined.set(iv,16);combined.set(new Uint8Array(ct),28);
  return btoa(String.fromCharCode(...combined));
}
// ============ QR code encoder (byte-mode, version-auto, ECC-M) ============
// Minimal QR encoder — supports byte mode, versions 1-40, error correction level M.
const QR = (()=>{
  const GP={M:[0x537,0xd5c,0x1f25,0x1eda,0x2e73,0x2dac,0x3d05,0x3cfa,0x4c31,0x4d0e,0x5d67,0x5c98,0x6c4b,0x6db4,0x7ded]}; // unused runtime, kept as marker
  // Reed-Solomon over GF(256)
  const EXP=new Uint8Array(512),LOG=new Uint8Array(256);
  (function(){let x=1;for(let i=0;i<255;i++){EXP[i]=x;LOG[x]=i;x<<=1;if(x&0x100)x^=0x11d;}for(let i=255;i<512;i++)EXP[i]=EXP[i-255];})();
  function mul(a,b){return (a===0||b===0)?0:EXP[LOG[a]+LOG[b]];}
  function rsGen(deg){let g=[1];for(let i=0;i<deg;i++){const n=[...g,0];for(let j=0;j<g.length;j++)n[j+1]^=mul(g[j],EXP[i]);g=n;}return g;}
  function rsEncode(data,ecLen){const g=rsGen(ecLen);const res=new Array(ecLen).fill(0);const buf=[...data,...res];for(let i=0;i<data.length;i++){const c=buf[i];if(c!==0)for(let j=0;j<g.length;j++)buf[i+j]^=mul(g[j],c);}return buf.slice(data.length);}
  // ECC-M capacity table (data codewords, ec per block, num blocks group1, cw per block g1, num g2, cw g2)
  const CAP_M=[
    [16,10,1,16,0,0],[28,16,1,28,0,0],[44,26,1,44,0,0],[64,18,2,32,0,0],[86,24,2,43,0,0],
    [108,16,4,27,0,0],[124,18,4,31,0,0],[154,22,2,38,2,39],[182,22,3,36,2,37],[216,26,4,43,1,44],
    [254,30,1,50,4,51],[290,22,6,36,2,37],[334,22,8,37,1,38],[365,24,4,40,5,41],[415,24,5,41,5,42],
    [453,28,7,45,3,46],[507,28,10,46,1,47],[563,26,9,43,4,44],[627,26,3,44,11,45],[669,26,3,41,13,42],
    [714,26,17,42,0,0],[782,28,17,46,0,0],[860,28,4,47,14,48],[914,28,6,45,14,46],[1000,28,8,47,13,48],
    [1062,28,19,46,4,47],[1128,28,22,45,3,46],[1193,28,3,45,23,46],[1267,28,21,45,7,46],[1373,28,19,47,10,48],
    [1455,28,2,46,29,47],[1541,28,10,46,23,47],[1631,28,14,46,21,47],[1725,28,14,46,23,47],[1812,28,12,47,26,48],
    [1914,28,6,47,34,48],[1992,28,29,46,14,47],[2102,28,13,46,32,47],[2216,28,40,47,7,48],[2334,28,18,47,31,48]
  ];
  function chooseVersion(len){for(let v=1;v<=40;v++){const c=CAP_M[v-1][0];const bitCap=c*8;const cci=v<10?8:16;const need=4+cci+len*8;if(need<=bitCap)return v;}return null;}
  function encodeData(str,v){
    const bytes=new TextEncoder().encode(str);
    const cci=v<10?8:16;
    let bits='';
    bits+='0100'; // byte mode
    bits+=bytes.length.toString(2).padStart(cci,'0');
    for(const b of bytes) bits+=b.toString(2).padStart(8,'0');
    const cap=CAP_M[v-1][0]*8;
    if(bits.length+4<=cap) bits+='0000'; else bits+='0'.repeat(cap-bits.length);
    while(bits.length%8) bits+='0';
    const pad=['11101100','00010001'];let i=0;
    while(bits.length<cap){bits+=pad[i%2];i++;}
    const arr=[];for(let j=0;j<bits.length;j+=8) arr.push(parseInt(bits.substr(j,8),2));
    return arr;
  }
  function interleave(data,v){
    const [_,ec,g1n,g1cw,g2n,g2cw]=CAP_M[v-1];
    const blocks=[];let off=0;
    for(let i=0;i<g1n;i++){const b=data.slice(off,off+g1cw);off+=g1cw;blocks.push({d:b,e:rsEncode(b,ec)});}
    for(let i=0;i<g2n;i++){const b=data.slice(off,off+g2cw);off+=g2cw;blocks.push({d:b,e:rsEncode(b,ec)});}
    const out=[];const maxD=Math.max(...blocks.map(b=>b.d.length));
    for(let i=0;i<maxD;i++)for(const b of blocks) if(i<b.d.length) out.push(b.d[i]);
    const maxE=Math.max(...blocks.map(b=>b.e.length));
    for(let i=0;i<maxE;i++)for(const b of blocks) if(i<b.e.length) out.push(b.e[i]);
    return out;
  }
  // matrix build
  function size(v){return 21+4*(v-1);}
  function buildMatrix(v,codewords){
    const n=size(v);
    const m=Array.from({length:n},()=>new Int8Array(n).fill(-1));
    const rsv=Array.from({length:n},()=>new Int8Array(n).fill(0));
    function finder(x,y){for(let dy=0;dy<7;dy++)for(let dx=0;dx<7;dx++){const v=(dx===0||dx===6||dy===0||dy===6||(dx>=2&&dx<=4&&dy>=2&&dy<=4))?1:0;m[y+dy][x+dx]=v;rsv[y+dy][x+dx]=1;}}
    finder(0,0);finder(n-7,0);finder(0,n-7);
    // separators
    for(let i=0;i<8;i++){if(i<n){[[7,i],[i,7],[n-8,i],[i,n-8],[n-1-i,7],[7,n-1-i]].forEach(([x,y])=>{if(x<n&&y<n&&m[y][x]===-1){m[y][x]=0;rsv[y][x]=1;}});}}
    // timing
    for(let i=8;i<n-8;i++){if(m[6][i]===-1){m[6][i]=(i%2===0)?1:0;rsv[6][i]=1;}if(m[i][6]===-1){m[i][6]=(i%2===0)?1:0;rsv[i][6]=1;}}
    // alignment
    const alignPos={1:[],2:[6,18],3:[6,22],4:[6,26],5:[6,30],6:[6,34],7:[6,22,38],8:[6,24,42],9:[6,26,46],10:[6,28,50]};
    const ap=alignPos[v]||[6,26,50,74,98,122,146].slice(0,Math.min(7,Math.floor(v/7)+2));
    for(const cx of ap)for(const cy of ap){if((cx===6&&cy===6)||(cx===6&&cy===n-7)||(cx===n-7&&cy===6))continue;for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++){const x=cx+dx,y=cy+dy;if(x>=0&&x<n&&y>=0&&y<n){const val=(Math.abs(dx)===2||Math.abs(dy)===2||(dx===0&&dy===0))?1:0;m[y][x]=val;rsv[y][x]=1;}}}
    // reserve format
    for(let i=0;i<9;i++){if(rsv[8][i]===0){rsv[8][i]=1;m[8][i]=0;}if(rsv[i][8]===0){rsv[i][8]=1;m[i][8]=0;}}
    for(let i=0;i<8;i++){if(rsv[8][n-1-i]===0){rsv[8][n-1-i]=1;m[8][n-1-i]=0;}if(rsv[n-1-i][8]===0){rsv[n-1-i][8]=1;m[n-1-i][8]=0;}}
    m[n-8][8]=1;rsv[n-8][8]=1;
    // version info for v>=7
    if(v>=7){
      const versionEC=(v)=>{let d=v<<12;const gp=0x1f25;for(let i=17;i>=12;i--){if(d&(1<<i))d^=gp<<(i-12);}return (v<<12)|d;};
      const bits=versionEC(v);
      for(let i=0;i<18;i++){const b=(bits>>i)&1;const y=Math.floor(i/3),x=n-11+(i%3);m[y][x]=b;rsv[y][x]=1;m[x][y]=b;rsv[x][y]=1;}
    }
    // data placement
    const bitStream=[];for(const c of codewords) for(let i=7;i>=0;i--) bitStream.push((c>>i)&1);
    let idx=0,upward=true;
    for(let col=n-1;col>0;col-=2){if(col===6)col--;for(let i=0;i<n;i++){const y=upward?n-1-i:i;for(let c=0;c<2;c++){const x=col-c;if(rsv[y][x]===0){m[y][x]=idx<bitStream.length?bitStream[idx]:0;idx++;}}}upward=!upward;}
    // mask 0 (row+col)%2===0
    for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(rsv[y][x]===0&&m[y][x]!==-1){if((x+y)%2===0)m[y][x]^=1;}
    // format info: EC-M=0, mask=0 → data bits 00 000
    const fmtData=0b00000;
    let fmtEC=fmtData<<10;const genFmt=0b10100110111;
    let tmp=fmtEC;for(let i=14;i>=10;i--){if(tmp&(1<<i))tmp^=genFmt<<(i-10);}
    let fmt=((fmtData<<10)|tmp)^0b101010000010010;
    const fmtBits=[];for(let i=14;i>=0;i--)fmtBits.push((fmt>>i)&1);
    // place format
    const fpos=[[0,8],[1,8],[2,8],[3,8],[4,8],[5,8],[7,8],[8,8],[8,7],[8,5],[8,4],[8,3],[8,2],[8,1],[8,0]];
    for(let i=0;i<15;i++){const [x,y]=fpos[i];m[y][x]=fmtBits[i];}
    const fpos2=[[8,n-1],[8,n-2],[8,n-3],[8,n-4],[8,n-5],[8,n-6],[8,n-7],[n-8,8],[n-7,8],[n-6,8],[n-5,8],[n-4,8],[n-3,8],[n-2,8],[n-1,8]];
    for(let i=0;i<15;i++){const [x,y]=fpos2[i];m[y][x]=fmtBits[i];}
    return m;
  }
  function encode(str){
    const v=chooseVersion(str.length);
    if(!v) throw new Error('Payload too large for QR (max ~2000 bytes)');
    const data=encodeData(str,v);
    const cw=interleave(data,v);
    return {matrix:buildMatrix(v,cw), size:size(v), version:v};
  }
  function svg(str,px=10){
    const {matrix,size:n}=encode(str);
    const total=(n+8)*px;
    let s=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" width="${Math.min(total,320)}" height="${Math.min(total,320)}"><rect width="${total}" height="${total}" fill="#fff"/>`;
    for(let y=0;y<n;y++)for(let x=0;x<n;x++){if(matrix[y][x]===1)s+=`<rect x="${(x+4)*px}" y="${(y+4)*px}" width="${px}" height="${px}" fill="#1a1a1e"/>`;}
    s+='</svg>';
    return s;
  }
  return {svg,encode};
})();
// ============ Generate QR ============
async function generateQR(){
  if(pass.length<12){status.textContent='Passphrase must be at least 12 characters.';status.style.color='var(--coral)';return;}
  status.style.color='var(--muted)';
  status.textContent='Encrypting keypair...';
  const secret = window._fallidKey || {demo:true, seed:crypto.getRandomValues(new Uint8Array(32)).join('-'), created:Date.now()};
  try{
    const encB64 = await encryptPayload(pass, secret);
    const payload = `fallid-transfer://v1?ed25519_encrypted=${encodeURIComponent(encB64)}&passphrase_hint=${encodeURIComponent(peer)}&sync_peer=${encodeURIComponent(peer)}`;
    status.textContent = `Encoded ${encB64.length} bytes · QR ready.`;
    try{
      const svg = QR.svg(payload, 5);
      box.className='qr-box';
      box.innerHTML = svg;
      pl.textContent = payload.slice(0,80)+'...';
    }catch(e){
      // fallback: shorter test payload
      const fallback = `fallid-transfer://v1?ed25519_encrypted=${encodeURIComponent(encB64.slice(0,200))}&sync_peer=${encodeURIComponent(peer)}&truncated=1`;
      const svg = QR.svg(fallback, 5);
      box.className='qr-box';
      box.innerHTML = svg;
      pl.textContent = 'Payload too long for on-screen QR — showing truncated demo. Use file-transfer fallback for full keypair.';
      status.textContent = 'QR generated (demo mode · payload > 2KB). Real transfer uses chunked QR sequence.';
      status.style.color='var(--amber)';
    }
  }catch(e){
    status.textContent='Encryption failed: '+e.message;
    status.style.color='var(--coral)';
  }
}
// ============ FallHarbor manifest → PWA list ============
const FALLBACK_PWAS = [
  {slug:'fallid',name:'FallID',desc:'Your sovereign identity',url:'https://sjgant80-hub.github.io/fallid/',glyph:'◈'},
  {slug:'fallsync',name:'FallSync',desc:'Multi-device state sync',url:'https://sjgant80-hub.github.io/fallsync/',glyph:'◇'},
  {slug:'fallbrief',name:'FallBrief',desc:'Sovereign legal research',url:'https://sjgant80-hub.github.io/fallbrief/',glyph:'§'},
  {slug:'fallmirror',name:'FallMirror',desc:'Private reflection tool',url:'https://sjgant80-hub.github.io/fallmirror/',glyph:'◎'},
  {slug:'fallrouter',name:'FallRouter',desc:'BYOK LLM orchestrator',url:'https://sjgant80-hub.github.io/fallrouter/',glyph:'⟐'},
  {slug:'fallcolony',name:'FallColony',desc:'Agent-native settlement',url:'https://sjgant80-hub.github.io/fallcolony/',glyph:'⌘'},
  {slug:'fallhub',name:'FallHub',desc:'Sovereign SMB OS',url:'https://sjgant80-hub.github.io/fallhub/',glyph:'◉'}
];
async function loadHarbor(){
  let tools = FALLBACK_PWAS;
  try{
    const r = await fetch('https://sjgant80-hub.github.io/fallharbor/manifest.json',{cache:'no-store'});
    if(r.ok){
      const j = await r.json();
    }
  }catch(e){/* fallback list already set */}
  const done = JSON.parse(localStorage.getItem('fp_pwas')||'{}');
  list.innerHTML='';
  tools.forEach(t=>{
    const row=document.createElement('div');
    row.className='pwa-row'+(done[t.slug]?' done':'');
    list.appendChild(row);
  });
  list.querySelectorAll('.action').forEach(b=>{
    b.addEventListener('click',(e)=>{
      const slug=b.dataset.slug;const url=b.dataset.url;
      const d=JSON.parse(localStorage.getItem('fp_pwas')||'{}');
      d[slug]=true;localStorage.setItem('fp_pwas',JSON.stringify(d));
      b.closest('.pwa-row').classList.add('done');
      b.textContent='Installed';
      updatePwaProgress(tools);
    });
  });
  updatePwaProgress(tools);
}
function updatePwaProgress(tools){
  const done=JSON.parse(localStorage.getItem('fp_pwas')||'{}');
  const n=Object.keys(done).filter(k=>done[k]).length;
  const pct=Math.round((n/tools.length)*100);
}
loadHarbor();
// ============ Posture checklist ============
const savedChecks = JSON.parse(localStorage.getItem('fp_checks')||'{}');
  const k=row.dataset.k;
  if(savedChecks[k]) row.classList.add('on');
  row.addEventListener('click',()=>{
    row.classList.toggle('on');
    savedChecks[k]=row.classList.contains('on');
    localStorage.setItem('fp_checks',JSON.stringify(savedChecks));
    updatePosture();
  });
});
function updatePosture(){
  val.textContent=`${on} / ${rows.length}`;
  val.classList.toggle('dim', on===0);
}
updatePosture();
// ============ Service worker ============
if('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(()=>{});

// Named exports for the primary API surface
export { goStep };
export { loadFallID };
export { deriveKey };
export { encryptPayload };
export { mul };
export { rsGen };
export { rsEncode };
export { chooseVersion };
export { encodeData };
export { interleave };

export { QR };
export { GP };
export { EXP };
export { CAP_M };
export { FALLBACK_PWAS };
