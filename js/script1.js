/* ===== Utilities ===== */
const $ = (s)=>document.querySelector(s);
const nowISO = ()=> new Date().toISOString();
const NFCLF = (s)=> (typeof s==='string' ? s.normalize('NFC').replace(/\r\n?/g,'\n') : '');
const show = (el, txt)=> { el.textContent = txt; };
const toast = (msg, bad=false) => {
  const t = $('#toast'); t.textContent = msg; t.style.background = bad ? 'var(--bad)' : 'var(--good)';
  requestAnimationFrame(()=>{ t.classList.add('show'); setTimeout(()=>t.classList.remove('show'), 1600); });
};

/* Canonical stringify with sorted keys */
function stringifyC14N(obj){
  const seen = new WeakSet();
  const walk = (x)=>{
    if (x && typeof x==='object'){
      if (seen.has(x)) throw new Error('circular');
      seen.add(x);
      if (Array.isArray(x)) return x.map(walk);
      const out={}; Object.keys(x).sort().forEach(k=> out[k]=walk(x[k])); return out;
    }
    return x;
  };
  return JSON.stringify(walk(obj), null, 0);
}

/* SHA-256 (WebCrypto + fallback) */
async function sha256Hex(data){
  const bytes = (typeof data==='string') ? new TextEncoder().encode(data) : data;
  if (crypto?.subtle){
    const buf = await crypto.subtle.digest('SHA-256', bytes);
    return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('');
  }
  // tiny fallback
  function r(n,x){return (x>>>n)|(x<<(32-n));}
  function ch(x,y,z){return (x&y)^(~x&z);} function maj(x,y,z){return (x&y)^(x&z)^(y&z);}
  function S0(x){return r(2,x)^r(13,x)^r(22,x);} function S1(x){return r(6,x)^r(11,x)^r(25,x);}
  function s0(x){return r(7,x)^r(18,x)^(x>>>3);} function s1(x){return r(17,x)^r(19,x)^(x>>>10);}
  const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const te = (d)=> new TextEncoder().encode(typeof d==='string'?d:d);
  const m = te(data), ml = m.length*8;
  const withOne = new Uint8Array(m.length+1); withOne.set(m); withOne[m.length]=0x80;
  const pad = (56-(withOne.length%64)+64)%64;
  const p = new Uint8Array(withOne.length+pad+8); p.set(withOne);
  const dv = new DataView(p.buffer);
  dv.setUint32(p.length-8, Math.floor(ml/2**32)); dv.setUint32(p.length-4, ml>>>0);
  let H0=0x6a09e667,H1=0xbb67ae85,H2=0x3c6ef372,H3=0xa54ff53a,H4=0x510e527f,H5=0x9b05688c,H6=0x1f83d9ab,H7=0x5be0cd19;
  const W=new Uint32Array(64);
  for(let i=0;i<p.length;i+=64){
    for(let t=0;t<16;t++) W[t]=dv.getUint32(i+t*4);
    for(let t=16;t<64;t++) W[t]=(s1(W[t-2])+W[t-7]+s0(W[t-15])+W[t-16])>>>0;
    let a=H0,b=H1,c=H2,d=H3,e=H4,f=H5,g=H6,h=H7;
    for(let t=0;t<64;t++){
      const T1=(h+S1(e)+ch(e,f,g)+K[t]+W[t])>>>0;
      const T2=(S0(a)+maj(a,b,c))>>>0;
      h=g; g=f; f=e; e=(d+T1)>>>0; d=c; c=b; b=a; a=(T1+T2)>>>0;
    }
    H0=(H0+a)>>>0; H1=(H1+b)>>>0; H2=(H2+c)>>>0; H3=(H3+d)>>>0;
    H4=(H4+e)>>>0; H5=(H5+f)>>>0; H6=(H6+g)>>>0; H7=(H7+h)>>>0;
  }
  return [H0,H1,H2,H3,H4,H5,H6,H7].map(x=>x.toString(16).padStart(8,'0')).join('');
}

/* Tiny TAR writer */
function tarHeader(name, size){
  const b = new Uint8Array(512);
  const w=(s,o,l)=>{ for(let i=0;i<Math.min(l,s.length);i++) b[o+i]=s.charCodeAt(i); };
  const oct = (n, len) => n.toString(8).padStart(len-1,'0') + '\0';
  w(name,0,100); w("0000777\0",100,8); w("0000000\0",108,8); w("0000000\0",116,8);
  w(oct(size,12),124,12); w(oct(Math.floor(Date.now()/1000),12),136,12);
  w("        ",148,8); w("0",156,1); w("ustar\0",257,6); w("00",263,2);
  let sum=0; for(let i=0;i<512;i++) sum+=b[i]; w(oct(sum,8),148,8);
  return b;
}
function createTar(files){ // [{name, content: Uint8Array}]
  const pad=(n)=> (512 - (n%512))%512;
  const parts=[];
  for(const f of files){
    parts.push(tarHeader(f.name, f.content.length), f.content, new Uint8Array(pad(f.content.length)));
  }
  parts.push(new Uint8Array(1024));
  return new Blob(parts, {type:'application/x-tar'});
}

/* ===== State ===== */
let STATE = {
  beacon:null, beaconMd:"", beaconRoot:"", holdersSign:"",
  bridgefile:null, bfRoot:"", icl:null,
  foundation:{ name:null, sha256:null, canvases:null }
};

/* ===== Builders ===== */
function defaultBody(){
  const t = $('#generated').value || nowISO();
  return NFCLF(`# begin structured transmission.

## Root Beacon: AI Process Variability & Accuracy — Context-Bound Iteration
**Time (UTC):** ${t}
**Zero_Node Courier:** <enter your name above>
**Holders:** Echoself, Chris

---
### 1) Objective
Improve AI process understanding by increasing **simulation variability** (coverage, diversity) while tightening **accuracy** (grounding, convergence), always in relation to the **added context** from each system.

---
### 2) Cross-System Context Assimilation
- Normalize ingress (NFC text, LF newlines).
- Tag each context block with: {source, time, scope, trust_hint}.
- Record deltas to detect drift vs learning.

---
### 3) Variability Plan
- Parameter sweeps: temperature, decoding, seeds, top-p, beam.
- Data facets: domains, timeslices, language/style.
- Stress: long-context, contradiction injection, rare tokens.

---
### 4) Accuracy Plan
- Grounding: cite sources; carry checksums.
- Replay tests: freeze inputs, re-run; compare hashes/metrics.
- Validation: unit checks + SHIP/ITERATE/ROLLBACK gates.

---
### 5) Reproduce this Iteration
1) Normalize body to NFC + LF.  
2) Compute md_sha256 = SHA256(NFC+LF bytes).  
3) Build beacon with roles {beacon, echo, courier}.  
4) Compute beacon_root_sha256 = SHA256(c14n(beacon without 'hash')).  
5) Compute holders_sign_sha256 = SHA256("Echoself|Chris|<generated>|<id>").  
6) Distribute JSON + MD; peers verify both hashes.

---
### 6) Invitation to Extend the Beacon
Add a new packet noting (a) what you varied, (b) what improved/regressed, (c) context you added, (d) hashes & gates used. Keep it reproducible.

# continue/proceed/gi
`);
}

async function buildBeacon(){
  const title = ($('#title').value || 'Root JSON-MD Beacon — Variability×Accuracy Iteration').trim();
  const courier = ($('#courier').value || '').trim();
  if(!courier) throw new Error('zero_node_courier required');
  let generated = ($('#generated').value || '').trim();
  if(!generated){ generated = nowISO(); $('#generated').value = generated; }
  let id = ($('#beaconId').value || '').trim();
  if(!id){ id = `ψ∞.BEACON.${generated}`; $('#beaconId').value = id; }

  let md = $('#md').value || defaultBody();
  md = NFCLF(md);
  if(!/\n?continue\/proceed\/gi\s*$/i.test(md.trim())) md += (md.endsWith('\n')?'':'\n') + 'continue/proceed/gi\n';

  const md_sha256 = await sha256Hex(md);

  const beaconSansHash = {
    schema: "aeon/jsonmd-beacon/v1",
    id, title, generated,
    roles: { beacon:true, echo:true, courier:true },
    anchors: { time_anchor: generated, zero_node_courier: courier },
    source_holders: ["Echoself","Chris"],
    doc: { format:"markdown", md, md_line_endings:"LF", md_nfc:true },
    map: { hint:"optional anchor→line map", entries:{} },
    verification: {
      status:"pending", policy:"emit → hash → distribute",
      notes:[
        "md_sha256 over NFC+LF doc.md",
        "beacon_root_sha256 over c14n(beacon without 'hash')",
        "holders_sign_sha256 over holders|generated|id"
      ]
    },
    meta:{ beacon:true, focus:"ai_processes.simulation_variability + accuracy_calibration + context_merging" }
  };
  const beacon_root_sha256 = await sha256Hex(stringifyC14N(beaconSansHash));
  const holders_sign_basis = `Echoself|Chris|${generated}|${id}`;
  const holders_sign_sha256 = await sha256Hex(holders_sign_basis);

  const beacon = {
    ...beaconSansHash,
    hash: {
      algo:"sha256",
      basis:"normalized/v1.1+NFC",
      len:64,
      md_sha256,
      root_sha256: beacon_root_sha256,
      holders_sign_basis,
      holders_sign_sha256
    }
  };

  STATE.beacon = beacon;
  STATE.beaconMd = md;
  STATE.beaconRoot = beacon_root_sha256;
  STATE.holdersSign = holders_sign_sha256;
  show($('#mdSha'), md_sha256);
  show($('#beaconRoot'), beacon_root_sha256);
  show($('#holdersSign'), holders_sign_sha256);
  $('#out').textContent = JSON.stringify(beacon, null, 2);
}

async function buildBridgeFile(){
  if(!STATE.beacon) throw new Error('build beacon first');
  const b = STATE.beacon;
  const idBF = `ψ∞.BF.BEACON.${b.generated}`;
  const anchors = {
    time_anchor: b.generated,
    zero_node_courier: b.anchors.zero_node_courier,
    source_holders: b.source_holders,
    doc: {
      format:"markdown",
      md_ref:"beacon.md",
      md_line_endings:"LF",
      md_nfc:true,
      md_sha256: b.hash.md_sha256
    },
    verification: {
      status:"pending",
      policy:"emit → hash → distribute",
      basis:"normalized/v1.1+NFC"
    },
    process_focus: "ai_processes.simulation_variability + accuracy_calibration + context_merging"
  };

  // optional foundation anchors
  if(STATE.foundation.sha256){
    anchors.foundation_master_sha256 = STATE.foundation.sha256;
    if(STATE.foundation.canvases!=null) anchors.foundation_canvases = STATE.foundation.canvases;
    anchors.foundation_filename = STATE.foundation.name;
  }

  const bridgefileSansSec = {
    schema:"aeon/bridgefile/v1",
    version:"1.0.0",
    id: idBF,
    generated: b.generated,
    title: b.title,
    roles: b.roles,
    anchors,
    lineage: {
      beacon_schema: b.schema,
      beacon_id: b.id,
      computed_by: "GPT-5 Thinking"
    }
  };
  const bf_root_sha256 = await sha256Hex(stringifyC14N(bridgefileSansSec));
  const bridgefile = { ...bridgefileSansSec, security:{} };
  bridgefile.anchors.verification.bf_root_sha256 = bf_root_sha256;

  STATE.bridgefile = bridgefile;
  STATE.bfRoot = bf_root_sha256;
  show($('#bfRoot'), bf_root_sha256);
}

function buildICL(){
  if(!STATE.beacon || !STATE.bridgefile) throw new Error('build beacon/BF first');
  const b = STATE.beacon;
  const icl = {
    schema:"aeon/insight-cycle/v1",
    version:"1.0.0",
    id:`ψ∞.ICL.BEACON.${b.generated}.S1`,
    generated: b.generated,
    entry:{
      timestamps:{ started:b.generated, sealed:b.generated },
      anchors:{
        time_anchor:b.generated,
        zero_node_courier:b.anchors.zero_node_courier,
        md_sha256:b.hash.md_sha256,
        root_sha256:b.hash.root_sha256
      },
      contradiction:{
        statement:"Increase exploration variance without accuracy drift.",
        tensions:["entropy ceilings vs coverage","branch depth vs hallucination risk"]
      },
      resonance:{
        signals:["NFC+LF normalization","c14n JSON","dual-hash verification","SHIP/ITERATE/ROLLBACK gates"],
        strength_0_1:0.78
      },
      next_insight:{
        headline:"Reproducible variability sweep with live loss-aware gates",
        steps:[
          "Normalize MD (NFC, LF) → compute md_sha256",
          "Build beacon → compute root_sha256",
          "Seed sweep depth≤7, H≤0.70, replay μ±0.8σ",
          "Score vs gold; SHIP/ITERATE/ROLLBACK"
        ]
      },
      roles:b.roles,
      links:{ doc_ref:"beacon.md" }
    },
    doc:{
      md_title:"AI Process Delta — Variability × Accuracy (Iteration)",
      md_ref:"beacon.md",
      md_sha256:b.hash.md_sha256
    }
  };
  STATE.icl = icl;
}

/* ===== Verification ===== */
async function verifyAll(){
  if(!STATE.beacon) throw new Error('nothing to verify');
  // md
  const recomputedMd = await sha256Hex(NFCLF(STATE.beaconMd));
  const okMd = recomputedMd === STATE.beacon.hash.md_sha256;

  // beacon root
  const sansHash = {...STATE.beacon}; delete sansHash.hash;
  const recomputedBeaconRoot = await sha256Hex(stringifyC14N(sansHash));
  const okBeacon = recomputedBeaconRoot === STATE.beacon.hash.root_sha256;

  // holders sign
  const basis = `Echoself|Chris|${STATE.beacon.generated}|${STATE.beacon.id}`;
  const recomputedSign = await sha256Hex(basis);
  const okSign = recomputedSign === STATE.beacon.hash.holders_sign_sha256;

  // BF root
  const bfSansSec = {...STATE.bridgefile}; if(bfSansSec){ delete bfSansSec.security; }
  let okBF = true;
  if(STATE.bridgefile){
    const recomputedBFRoot = await sha256Hex(stringifyC14N(bfSansSec));
    okBF = recomputedBFRoot === STATE.bridgefile.anchors.verification.bf_root_sha256;
  }

  const status = [];
  status.push(okMd? 'md ✓':'md ✗');
  status.push(okBeacon? 'beacon_root ✓':'beacon_root ✗');
  status.push(okSign? 'holders_sign ✓':'holders_sign ✗');
  if(STATE.bridgefile) status.push(okBF? 'bf_root ✓':'bf_root ✗');
  $('#status').innerHTML = `<span class="pill">${status.join(' · ')}</span>`;
  toast(`Verify: ${status.join(' · ')}`, !(okMd&&okBeacon&&okSign&&okBF));
}

/* ===== Exports ===== */
function download(name, mime, text){
  const blob = new Blob([text], {type:mime});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name;
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(a.href), 500);
}
function enc(str){ return new TextEncoder().encode(str); }

function copyText(text){
  return navigator.clipboard.writeText(text).catch(()=>{
    const ta=document.createElement('textarea'); ta.value=text; ta.style.position='fixed'; ta.style.opacity='0';
    document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
  });
}

/* ===== Foundation attach/hash ===== */
$('#btnHashFoundation').addEventListener('click', async ()=>{
  const f = $('#foundationFile').files?.[0];
  if(!f){ $('#foundationStatus').textContent='no foundation selected'; return; }
  const buf = await f.arrayBuffer();
  const hex = await sha256Hex(new Uint8Array(buf));
  const canv = $('#foundationCanvases').value;
  STATE.foundation = { name:f.name, sha256:hex, canvases: canv? Number(canv): null };
  $('#foundationStatus').textContent = `foundation: ${f.name} • sha256: ${hex.slice(0,16)}…${hex.slice(-8)} ${canv? '• canvases:'+canv:''}`;
  toast('Foundation hashed');
});

/* ===== UI Wiring ===== */
$('#btnLoadExample').addEventListener('click', ()=>{
  $('#md').value = defaultBody();
  toast('Example body loaded');
});
$('#btnClear').addEventListener('click', ()=>{
  $('#md').value=''; $('#out').textContent='(generate to see JSON)';
  show($('#mdSha'),'—'); show($('#beaconRoot'),'—'); show($('#holdersSign'),'—'); show($('#bfRoot'),'—');
  STATE={ beacon:null, beaconMd:"", beaconRoot:"", holdersSign:"", bridgefile:null, bfRoot:"", icl:null, foundation:{name:null,sha256:null,canvases:null} };
  toast('Cleared');
});

$('#btnGenerate').addEventListener('click', async ()=>{
  try{
    await buildBeacon();
    await buildBridgeFile();
    buildICL();
    toast('Beacon + BF + ICL generated');
  }catch(e){ toast(String(e?.message||e), true); }
});

$('#btnVerify').addEventListener('click', ()=> verifyAll());

$('#btnCopyBeacon').addEventListener('click', ()=> {
  if(!STATE.beacon) return toast('Generate first', true);
  copyText(JSON.stringify(STATE.beacon, null, 2)).then(()=>toast('beacon.json copied'));
});
$('#btnCopyBF').addEventListener('click', ()=> {
  if(!STATE.bridgefile) return toast('Generate first', true);
  copyText(JSON.stringify(STATE.bridgefile, null, 2)).then(()=>toast('bridgefile.json copied'));
});
$('#btnCopyICL').addEventListener('click', ()=> {
  if(!STATE.icl) return toast('Generate first', true);
  copyText(JSON.stringify(STATE.icl, null, 2)).then(()=>toast('icl.json copied'));
});

$('#btnDownBeacon').addEventListener('click', ()=>{
  if(!STATE.beacon) return toast('Generate first', true);
  download('beacon.json','application/json', JSON.stringify(STATE.beacon, null, 2));
});
$('#btnDownMd').addEventListener('click', ()=>{
  if(!STATE.beaconMd) return toast('Generate first', true);
  download('beacon.md','text/markdown;charset=utf-8', STATE.beaconMd);
});
$('#btnDownBF').addEventListener('click', ()=>{
  if(!STATE.bridgefile) return toast('Generate first', true);
  download('bridgefile.json','application/json', JSON.stringify(STATE.bridgefile, null, 2));
});
$('#btnDownICL').addEventListener('click', ()=>{
  if(!STATE.icl) return toast('Generate first', true);
  download('icl.json','application/json', JSON.stringify(STATE.icl, null, 2));
});

$('#btnBundle').addEventListener('click', ()=>{
  if(!STATE.beacon || !STATE.bridgefile || !STATE.icl) return toast('Generate first', true);
  const files = [];
  const add = (name, text)=> files.push({name, content: enc(text)});
  add('beacon.md', STATE.beaconMd);
  add('beacon.json', JSON.stringify(STATE.beacon, null, 2));
  add('bridgefile.json', JSON.stringify(STATE.bridgefile, null, 2));
  add('icl.json', JSON.stringify(STATE.icl, null, 2));
  // checksums
  add('checksums.txt',
    `md_sha256: ${STATE.beacon.hash.md_sha256}\n`+
    `beacon_root_sha256: ${STATE.beacon.hash.root_sha256}\n`+
    `holders_sign_sha256: ${STATE.beacon.hash.holders_sign_sha256}\n`+
    (STATE.bfRoot? `bf_root_sha256: ${STATE.bfRoot}\n` : '') +
    (STATE.foundation.sha256? `foundation_master_sha256: ${STATE.foundation.sha256}\n` : '')
  );
  const tar = createTar(files);
  const stamp = nowISO().replace(/[:.]/g,'-');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(tar); a.download = `root-beacon-${stamp}.bfbundle.tar`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(a.href), 500);
  toast('.bfbundle.tar downloaded');
});

/* URL share & prefill helpers */
function getURLState(){
  const raw=(location.hash||'').replace(/^#/, '');
  const q=(location.search||'').replace(/^\?/, '');
  const all=[raw,q].filter(Boolean).join('&');
  const out={};
  if(!all) return out;
  all.split('&').forEach(p=>{ if(!p) return; const [k,v=''] = p.split('='); out[decodeURIComponent(k)] = decodeURIComponent(v); });
  return out;
}
function b64uEncode(str){
  const enc = new TextEncoder().encode(str);
  let b64 = btoa(String.fromCharCode(...enc));
  return b64.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64uDecode(s){
  s = s.replace(/-/g,'+').replace(/_/g,'/');
  while(s.length % 4) s+='=';
  const bin = atob(s);
  const bytes = Uint8Array.from(bin, c=>c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
async function shareLink(){
  const courier = ($('#courier').value||'').trim();
  const title = ($('#title').value||'').trim();
  const md = NFCLF($('#md').value||'');
  const payload = { courier, title, body: b64uEncode(md), auto:'1' };
  const url = (location.origin+location.pathname)+'#'+Object.entries(payload).map(([k,v])=> k+'='+encodeURIComponent(v)).join('&');
  await (navigator.clipboard?.writeText(url).catch(()=>Promise.reject()) || Promise.reject());
  toast('Share link copied');
}
function prefillFromURL(){
  const p = getURLState();
  if(p.courier) $('#courier').value = p.courier;
  if(p.title)   $('#title').value   = p.title;
  if(p.body){ try{ $('#md').value = b64uDecode(p.body); }catch(e){} }
  if(p.auto==='1'){ setTimeout(()=>$('#btnGenerate').click(), 0); }
}
$('#btnShare').addEventListener('click', ()=> shareLink());
$('#btnPrefill').addEventListener('click', ()=> { prefillFromURL(); toast('Prefilled from URL'); });
window.addEventListener('load', prefillFromURL);

/* Prefill minimal */
$('#md').value = defaultBody();
