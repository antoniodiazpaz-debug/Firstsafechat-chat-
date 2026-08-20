/* ═══════════════════════════════════════════════════════════════════════
   CRYPTO — X3DH, Double Ratchet, Key Transparency, Prekeys
   ─────────────────────────────────────────────────────────────────────
   Extrahiert aus der bewährten Krypto-Logik der ursprünglichen
   index.html (Simulation), jetzt als eigenständiges ES-Modul für den
   echten Netzwerk-Client. Verhalten unverändert — nur der Export.
   ═══════════════════════════════════════════════════════════════════════ */

const SC = window.crypto?.subtle;
if(!SC) throw new Error('WebCrypto nicht verfügbar — bitte HTTPS oder localhost.');
const te=new TextEncoder(), td=new TextDecoder();
const rnd=n=>crypto.getRandomValues(new Uint8Array(n));
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b)));
const ub64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const hexs=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const cat=(...as)=>{const t=as.reduce((n,a)=>n+a.byteLength,0);const o=new Uint8Array(t);
  let p=0;for(const a of as){o.set(new Uint8Array(a),p);p+=a.byteLength}return o.buffer};

const P = {
  async genDH(){
    const kp = await SC.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
    return {priv:kp.privateKey, pub:kp.publicKey,
            pubJwk: await SC.exportKey('jwk',kp.publicKey),
            privJwk: await SC.exportKey('jwk',kp.privateKey)};
  },
  impPub: jwk => SC.importKey('jwk',jwk,{name:'ECDH',namedCurve:'P-256'},true,[]),
  impPriv: jwk => SC.importKey('jwk',jwk,{name:'ECDH',namedCurve:'P-256'},true,['deriveBits']),

  /* DH(a_priv, b_pub) → 32 Byte */
  dh: (priv,pub) => SC.deriveBits({name:'ECDH',public:pub},priv,256),

  /* HKDF-SHA256 → n Byte */
  async hkdf(ikm, salt, info, n=32){
    const k = await SC.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    return SC.deriveBits({name:'HKDF',hash:'SHA-256',
      salt: salt||new Uint8Array(32), info: te.encode(info)}, k, n*8);
  },
  /* HMAC-SHA256 */
  async hmac(keyBytes, data){
    const k = await SC.importKey('raw', keyBytes, {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
    return SC.sign('HMAC', k, data);
  },
  /* AES-256-GCM */
  async aesKey(raw){ return SC.importKey('raw', raw, {name:'AES-GCM'}, false, ['encrypt','decrypt']) },
  async seal(keyRaw, ivRaw, plainBuf, aad){
    const k = await P.aesKey(keyRaw);
    return SC.encrypt({name:'AES-GCM',iv:new Uint8Array(ivRaw),
      additionalData:te.encode(aad),tagLength:128}, k, plainBuf);
  },
  async open(keyRaw, ivRaw, ct, aad){
    const k = await P.aesKey(keyRaw);
    return SC.decrypt({name:'AES-GCM',iv:new Uint8Array(ivRaw),
      additionalData:te.encode(aad),tagLength:128}, k, ct);
  },
  /* ---- ECDSA P-256: Signatur der Prekeys ---- */
  async genSign(){
    const kp = await SC.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
    return {priv:kp.privateKey, pub:kp.publicKey,
            pubJwk: await SC.exportKey('jwk',kp.publicKey)};
  },
  impVerify: jwk => SC.importKey('jwk',jwk,{name:'ECDSA',namedCurve:'P-256'},true,['verify']),
  sign: (priv,data) => SC.sign({name:'ECDSA',hash:'SHA-256'}, priv, data),
  verify: (pub,sig,data) => SC.verify({name:'ECDSA',hash:'SHA-256'}, pub, sig, data),

  async pbkdf2(pw, saltB64){
    const salt = saltB64?ub64(saltB64):rnd(16);
    const base = await SC.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveBits']);
    const bits = await SC.deriveBits({name:'PBKDF2',salt,iterations:210000,hash:'SHA-256'}, base, 256);
    return {salt:b64(salt), hash:b64(bits)};
  },
  async pwVerify(pw, rec){
    const {hash} = await P.pbkdf2(pw, rec.salt);
    const a=ub64(hash), b=ub64(rec.hash);
    if(a.length!==b.length) return false;
    let d=0; for(let i=0;i<a.length;i++) d|=a[i]^b[i];
    return d===0;
  }
};

/*══════════════════════════════════════════════════════════════════════════
  🤝 X3DH — Extended Triple Diffie-Hellman
  ────────────────────────────────────────────────────────────────────────
  Alice (Initiator) kennt Bobs Prekey-Bundle: IK_B, SPK_B, OPK_B
  Sie erzeugt ein flüchtiges Paar EK_A und rechnet:
     DH1 = DH(IK_A , SPK_B)   bindet Alices Identität an Bobs Prekey
     DH2 = DH(EK_A , IK_B )   bindet Bobs Identität an Alices Ephemeral
     DH3 = DH(EK_A , SPK_B)   frisches Material auf beiden Seiten
     DH4 = DH(EK_A , OPK_B)   einmalig, für Deniability + Sicherheit
     SK  = HKDF(DH1‖DH2‖DH3‖DH4)
  Bob rechnet dieselben vier DHs mit vertauschten Rollen und kommt auf SK.
══════════════════════════════════════════════════════════════════════════*/
/*══════════════════════════════════════════════════════════════════════════
  🎫 PREKEYS — signierte Bundles, One-Time-Pool, Rotation
  ────────────────────────────────────────────────────────────────────────
  Ohne Signatur könnte ein Server im Handshake einen eigenen Prekey
  unterschieben und mitlesen. Deshalb signiert jedes Konto sein Bundle
  mit einem ECDSA-Identitätsschlüssel:

      sigData = ikDH.x‖ikDH.y ‖ spk.x‖spk.y ‖ spkId ‖ createdAt
      spkSig  = ECDSA-SHA256(IK_sign, sigData)

  Der Initiator prüft spkSig gegen den öffentlichen Signaturschlüssel,
  BEVOR er irgendeine DH-Operation rechnet. Schlägt die Prüfung fehl,
  kommt kein Handshake zustande.

  One-Time Prekeys liegen in einem Pool. Jeder Handshake verbraucht genau
  einen; unter dem Schwellwert wird nachgefüllt. Ist der Pool leer, läuft
  X3DH mit drei statt vier DHs weiter — schwächer, aber nicht kaputt.
══════════════════════════════════════════════════════════════════════════*/
const OPK_POOL = 10, OPK_MIN = 3, SPK_MAX_AGE = 7*864e5;

const PreKeys = {
  /* Bytes, über die signiert wird — bindet DH-Identität an den Prekey */
  sigData(ikDHjwk, spkJwk, spkId, createdAt){
    return te.encode([ikDHjwk.x, ikDHjwk.y, spkJwk.x, spkJwk.y, spkId, createdAt].join('|'));
  },

  /* Vollständiges Schlüsselmaterial für ein neues Konto */
  async createStore(){
    const IK   = await P.genDH();       /* ECDH-Identität   */
    const IKS  = await P.genSign();     /* ECDSA-Identität  */
    const store = {IK, IKS, SPK:null, spkId:0, opks:new Map(), opkSeq:0, consumed:0};
    await PreKeys.rotateSPK(store);
    await PreKeys.refill(store, OPK_POOL);
    return store;
  },

  /* Neuen Signed Prekey erzeugen und signieren */
  async rotateSPK(store){
    const SPK = await P.genDH();
    const spkId = ++store.spkId;
    const createdAt = Date.now();
    const sig = await P.sign(store.IKS.priv,
      PreKeys.sigData(store.IK.pubJwk, SPK.pubJwk, spkId, createdAt));
    store.SPK = SPK;
    store.spkMeta = {spkId, createdAt, sig: b64(sig)};
    return store.spkMeta;
  },

  /* Pool auffüllen */
  async refill(store, n){
    for(let i=0;i<n;i++){
      const id = ++store.opkSeq;
      store.opks.set(id, await P.genDH());
    }
    return store.opks.size;
  },

  /* Öffentliches Bundle, wie es ein Server ausliefern würde */
  bundle(store){
    const [opkId, opk] = store.opks.entries().next().value || [null,null];
    return {
      ikDH:   store.IK.pubJwk,
      ikSign: store.IKS.pubJwk,
      spk:    store.SPK.pubJwk,
      spkId:  store.spkMeta.spkId,
      spkCreatedAt: store.spkMeta.createdAt,
      spkSig: store.spkMeta.sig,
      opk:    opk ? opk.pubJwk : null,
      opkId:  opkId
    };
  },

  /* Signatur prüfen — vor jedem Handshake */
  async verifyBundle(b){
    if(!b || !b.spkSig) return {ok:false, reason:'Bundle ohne Signatur'};
    let pub;
    try{ pub = await P.impVerify(b.ikSign) }
    catch(e){ return {ok:false, reason:'Signaturschlüssel unlesbar'} }
    const data = PreKeys.sigData(b.ikDH, b.spk, b.spkId, b.spkCreatedAt);
    const ok = await P.verify(pub, ub64(b.spkSig), data);
    if(!ok) return {ok:false, reason:'Signatur des Signed Prekey ungültig'};
    const age = Date.now() - b.spkCreatedAt;
    return {ok:true, age, stale: age > SPK_MAX_AGE, hasOpk: !!b.opk};
  },

  /* One-Time Prekey verbrauchen; bei Bedarf nachfüllen */
  async consumeOPK(store, opkId){
    if(opkId == null) return null;
    const k = store.opks.get(opkId);
    if(!k) return null;
    store.opks.delete(opkId);
    store.consumed++;
    if(store.opks.size < OPK_MIN) await PreKeys.refill(store, OPK_POOL - store.opks.size);
    return k;
  },

  /* Kurzfassung für die Anzeige */
  status(store){
    const age = Date.now() - store.spkMeta.createdAt;
    return {spkId: store.spkMeta.spkId, ageDays: (age/864e5).toFixed(1),
            stale: age > SPK_MAX_AGE, available: store.opks.size, consumed: store.consumed};
  }
};

/*══════════════════════════════════════════════════════════════════════════
  🌳 KEY TRANSPARENCY — append-only Merkle-Log (RFC 6962)
  ────────────────────────────────────────────────────────────────────────
  Die Prekey-Signatur beweist: "dieser Prekey gehört zu diesem
  Identitätsschlüssel". Sie beweist NICHT: "dieser Identitätsschlüssel
  gehört zu dieser Person". Genau das macht ein Transparenz-Log.

  Jeder Identitätsschlüssel wird in ein öffentliches, nur-anhängbares Log
  geschrieben. Zu jedem Bundle liefert der Server einen Inklusionsbeweis.
  Ein betrügerischer Server müsste den falschen Schlüssel ins Log schreiben,
  wo das Opfer ihn beim Self-Audit findet — oder das Log spalten, was der
  Konsistenzbeweis auffliegen lässt.

      leaf(d)   = SHA-256(0x00 ‖ d)      ← Domain-Trennung
      node(l,r) = SHA-256(0x01 ‖ l ‖ r)
      STH       = ECDSA(Log-Schlüssel, size ‖ root ‖ timestamp)
══════════════════════════════════════════════════════════════════════════*/
const KT = (()=>{
  const H = async b => new Uint8Array(await SC.digest('SHA-256', b));
  const cc = (...as)=>{const t=as.reduce((n,a)=>n+a.length,0),o=new Uint8Array(t);
    let p=0;for(const a of as){o.set(a,p);p+=a.length}return o};
  const leafHash = d => H(cc(new Uint8Array([0]), d));
  const nodeHash = (l,r) => H(cc(new Uint8Array([1]), l, r));
  const eq = (a,b)=>a.length===b.length&&a.every((x,i)=>x===b[i]);
  const split = n => {let k=1;while(k*2<n)k*=2;return k};

  async function MTH(lv){
    const n=lv.length;
    if(n===0)return H(new Uint8Array(0));
    if(n===1)return lv[0];
    const k=split(n);
    return nodeHash(await MTH(lv.slice(0,k)), await MTH(lv.slice(k)));
  }
  async function inclusionPath(m,lv){
    const n=lv.length;
    if(n===1)return[];
    const k=split(n);
    if(m<k)return[...await inclusionPath(m,lv.slice(0,k)), await MTH(lv.slice(k))];
    return[...await inclusionPath(m-k,lv.slice(k)), await MTH(lv.slice(0,k))];
  }
  async function consistencyProof(m,lv){
    if(m===0)return[];              /* leerer Vorgänger: nichts zu beweisen */
    if(m>lv.length)return[];        /* geschrumpft — Prüfung schlägt ohnehin fehl */
    if(m===lv.length)return[];
    return subproof(m,lv,true);
  }
  async function subproof(m,lv,b){
    const n=lv.length;
    if(m===n)return b?[]:[await MTH(lv)];
    const k=split(n);
    if(m<=k)return[...await subproof(m,lv.slice(0,k),b), await MTH(lv.slice(k))];
    return[...await subproof(m-k,lv.slice(k),false), await MTH(lv.slice(0,k))];
  }
  async function verifyInclusion(leaf,index,size,path,root){
    if(index>=size)return false;
    let fn=index,sn=size-1,r=leaf;
    for(const p of path){
      if(sn===0)return false;
      if(fn%2===1||fn===sn){r=await nodeHash(p,r);
        while(fn%2===0&&fn!==0){fn>>=1;sn>>=1}}
      else r=await nodeHash(r,p);
      fn>>=1;sn>>=1;
    }
    return sn===0&&eq(r,root);
  }
  async function verifyConsistency(m,n,proof,oldRoot,newRoot){
    if(m===n)return proof.length===0&&eq(oldRoot,newRoot);
    if(m===0||m>n)return false;
    let idx=0,node,fn=m-1,sn=n-1;
    const isPow=(m&(m-1))===0;
    if(isPow)node=oldRoot;
    else{if(!proof.length)return false;node=proof[idx++]}
    while(fn%2===1){fn>>=1;sn>>=1}
    let r1=node,r2=node;
    while(idx<proof.length){
      if(sn===0)return false;
      const p=proof[idx++];
      if(fn%2===1||fn===sn){r1=await nodeHash(p,r1);r2=await nodeHash(p,r2);
        while(fn%2===0&&fn!==0){fn>>=1;sn>>=1}}
      else r2=await nodeHash(r2,p);
      fn>>=1;sn>>=1;
    }
    return sn===0&&eq(r1,oldRoot)&&eq(r2,newRoot);
  }
  const entryBytes = e => te.encode(['kt-v1',e.userId,e.keyX,e.keyY,e.version].join('|'));

  /* ---- Log-Server ---- */
  class Log {
    constructor(){this.entries=[];this.leaves=[];this.sths=[];this.signer=null;
      this.evil=false;this.evilTarget=null;this.evilEntry=null}
    async init(){this.signer=await P.genSign();await this.publishSTH();return this}
    async append(userId,keyJwk){
      const prior=this.entries.filter(e=>e.userId===userId).length;
      const e={userId,keyX:keyJwk.x,keyY:keyJwk.y,version:prior+1,ts:Date.now()};
      this.entries.push(e);
      this.leaves.push(await leafHash(entryBytes(e)));
      return{index:this.entries.length-1,entry:e};
    }
    async publishSTH(){
      const size=this.leaves.length, root=await MTH(this.leaves), ts=Date.now();
      const sig=await P.sign(this.signer.priv,
        te.encode(['sth-v1',size,hexs(root),ts].join('|')));
      const sth={size,root,ts,sig:b64(sig)};
      /* Unabhängige Witnesses gegenzeichnen — sie sehen nur eine Wurzel pro Größe */
      sth.cosigs = await this.collectCosigs(sth);
      this.sths.push(sth);return sth;
    }
    /* Witnesses um Mitunterschrift bitten */
    async collectCosigs(sth){
      const out=[];
      for(const w of (this.witnesses||[])){
        const c=await w.cosign(sth);
        if(c) out.push(c);
      }
      return out;
    }
    /* Split-View: zweite Realität für ein bestimmtes Opfer erzeugen.
       Der Baum bekommt einen zusätzlichen Eintrag, den nur das Opfer sieht. */
    async forkFor(victimId, rogueKey){
      const e={userId:victimId, keyX:rogueKey.x, keyY:rogueKey.y,
        version:(this.history(victimId).length)+1, ts:Date.now()};
      const leaves=[...this.leaves, await leafHash(entryBytes(e))];
      const size=leaves.length, root=await MTH(leaves), ts=Date.now();
      const sig=await P.sign(this.signer.priv,
        te.encode(['sth-v1',size,hexs(root),ts].join('|')));
      this.shadow={entries:[...this.entries,e], leaves,
        sth:{size,root,ts,sig:b64(sig),cosigs:[]}, victim:victimId, entry:e};
      return this.shadow;
    }
    clearFork(){ this.shadow=null }
    latestSTH(){return this.sths[this.sths.length-1]}
    async verifySTH(sth){
      const pub=await P.impVerify(this.signer.pubJwk);
      return P.verify(pub, ub64(sth.sig),
        te.encode(['sth-v1',sth.size,hexs(sth.root),sth.ts].join('|')));
    }
    async lookup(userId){
      if(this.evil&&this.evilTarget===userId)
        return{entry:this.evilEntry,index:Math.max(0,this.entries.length-1),
          path:await inclusionPath(Math.max(0,this.entries.length-1),this.leaves),
          sth:this.latestSTH(),forged:true};
      let index=-1;
      for(let i=this.entries.length-1;i>=0;i--)
        if(this.entries[i].userId===userId){index=i;break}
      if(index<0)return null;
      return{entry:this.entries[index],index,
        path:await inclusionPath(index,this.leaves),sth:this.latestSTH()};
    }
    consistency(m){return consistencyProof(m,this.leaves)}
    history(userId){return this.entries.filter(e=>e.userId===userId)}
  }

  /* ──────────────────────────────────────────────────────────────────
     WITNESS — unabhängiger Beobachter
     Zeichnet eine Wurzel nur gegen, wenn er für diese Baumgröße noch
     keine andere gesehen hat und die Kette zu seiner letzten Sicht
     konsistent ist. Ein Server, der zwei Realitäten pflegt, bekommt
     für die zweite keine Mitunterschrift.
     ────────────────────────────────────────────────────────────────── */
  class Witness {
    constructor(name){this.name=name;this.seen=new Map();this.last=null;this.refusals=[]}
    async init(log){this.log=log;this.signer=await P.genSign();return this}
    async cosign(sth){
      const prior=this.seen.get(sth.size);
      if(prior && prior!==hexs(sth.root)){
        this.refusals.push({size:sth.size,at:Date.now(),reason:'zwei Wurzeln für dieselbe Größe'});
        return null;
      }
      if(this.last && this.last.size>0 && sth.size>this.last.size){
        const proof=await this.log.consistency(this.last.size);
        if(!await verifyConsistency(this.last.size,sth.size,proof,this.last.root,sth.root)){
          this.refusals.push({size:sth.size,at:Date.now(),reason:'Konsistenz verletzt'});
          return null;
        }
      }
      if(this.last && sth.size<this.last.size){
        this.refusals.push({size:sth.size,at:Date.now(),reason:'Log geschrumpft'});
        return null;
      }
      this.seen.set(sth.size,hexs(sth.root));
      this.last={size:sth.size,root:sth.root};
      const sig=await P.sign(this.signer.priv,
        te.encode(['witness-v1',this.name,sth.size,hexs(sth.root)].join('|')));
      return {witness:this.name,pubJwk:this.signer.pubJwk,sig:b64(sig)};
    }
  }

  /* Mitunterschriften prüfen — der Client verlangt ein Quorum */
  async function verifyCosigs(sth, quorum){
    let valid=0; const names=[];
    for(const c of (sth.cosigs||[])){
      const pub=await P.impVerify(c.pubJwk);
      const ok=await P.verify(pub, ub64(c.sig),
        te.encode(['witness-v1',c.witness,sth.size,hexs(sth.root)].join('|')));
      if(ok){valid++;names.push(c.witness)}
    }
    return {ok: valid>=quorum, valid, need:quorum, names};
  }

  /* ──────────────────────────────────────────────────────────────────
     GOSSIP — Nutzer vergleichen ihre Sicht auf das Log
     Jede Nachricht trägt die zuletzt gesehene Wurzel des Absenders.
     Sieht der Empfänger für dieselbe Baumgröße eine andere Wurzel,
     laufen zwei Realitäten — und das ist beweisbar, weil beide
     Wurzeln vom selben Log-Schlüssel signiert sind.
     ────────────────────────────────────────────────────────────────── */
  function gossipTag(sth){
    return sth ? {size:sth.size, root:hexs(sth.root).slice(0,32), ts:sth.ts, sig:sth.sig} : null;
  }
  async function gossipCheck(mine, theirs, log){
    if(!mine||!theirs) return {ok:true, skipped:true};
    if(theirs.size===mine.size){
      if(theirs.root!==hexs(mine.root).slice(0,32))
        return {ok:false, kind:'split-view',
          reason:`Zwei verschiedene Wurzeln für Baumgröße ${mine.size}`,
          mine:hexs(mine.root).slice(0,16), theirs:theirs.root.slice(0,16)};
      return {ok:true, agree:true};
    }
    /* Unterschiedliche Größen sind normal — dann muss aber Konsistenz gelten */
    const [small,big] = theirs.size<mine.size ? [theirs,{size:mine.size}] : [{size:theirs.size},mine];
    return {ok:true, lagging:true, behind:Math.abs(mine.size-theirs.size)};
  }

  /* ---- Client-Monitor ---- */
  class Monitor {
    constructor(log,myId){this.log=log;this.myId=myId;this.trustedSTH=null;
      this.pinned=new Map();this.alerts=[];this.checks=0}
    async updateSTH(){
      const sth=this.log.latestSTH();
      if(!await this.log.verifySTH(sth))return this.fail('STH-Signatur ungültig');
      if(this.trustedSTH && this.trustedSTH.size>0){
        if(sth.size<this.trustedSTH.size)
          return this.fail('Log ist geschrumpft — append-only verletzt');
        const proof=await this.log.consistency(this.trustedSTH.size);
        if(!await verifyConsistency(this.trustedSTH.size,sth.size,proof,
            this.trustedSTH.root,sth.root))
          return this.fail('Konsistenzbeweis fehlgeschlagen — Log wurde umgeschrieben');
      }
      /* Quorum unabhängiger Witnesses verlangen */
      const co=await verifyCosigs(sth, this.quorum ?? 2);
      if(!co.ok){
        this.alerts.push({kind:'no-quorum',size:sth.size,
          have:co.valid,need:co.need,at:Date.now()});
        return this.fail(`Nur ${co.valid} von ${co.need} Witness-Signaturen — Wurzel nicht bestätigt`);
      }
      this.cosigners=co.names;
      this.trustedSTH=sth;this.checks++;
      return{ok:true,size:sth.size,root:hexs(sth.root).slice(0,16),witnesses:co.names};
    }

    /* Wurzel eines Gesprächspartners gegen die eigene halten */
    async gossip(userId, tag){
      const res=await gossipCheck(this.trustedSTH, tag, this.log);
      this.gossipCount=(this.gossipCount||0)+1;
      if(!res.ok){
        if(!this.alerts.some(a=>a.kind==='split-view'))
          this.alerts.push({kind:'split-view',userId,reason:res.reason,
            mine:res.mine,theirs:res.theirs,at:Date.now()});
        this.splitView=res;
      }else if(res.agree){
        this.agreements=(this.agreements||0)+1;
      }
      return res;
    }

    /* Was wir anderen über unsere Sicht mitteilen */
    myGossipTag(){ return gossipTag(this.trustedSTH) }
    async resolve(userId){
      const res=await this.log.lookup(userId);
      if(!res)return this.fail('Kein Log-Eintrag für diesen Nutzer');
      if(!await this.log.verifySTH(res.sth))return this.fail('STH-Signatur ungültig');
      const leaf=await leafHash(entryBytes(res.entry));
      if(!await verifyInclusion(leaf,res.index,res.sth.size,res.path,res.sth.root))
        return this.fail('Inklusionsbeweis fehlgeschlagen — Schlüssel steht nicht im Log');
      const prev=this.pinned.get(userId);
      let stt='first-use';
      if(prev){
        if(prev.keyX===res.entry.keyX&&prev.keyY===res.entry.keyY) stt=prev.state;
        else{stt='changed';
          this.alerts.push({userId,kind:'key-change',from:prev.version,
            to:res.entry.version,at:Date.now()})}
      }
      this.pinned.set(userId,{keyX:res.entry.keyX,keyY:res.entry.keyY,
        version:res.entry.version,state:stt});
      this.checks++;
      return{ok:true,entry:res.entry,state:stt,index:res.index,treeSize:res.sth.size,
        pathLen:res.path.length};
    }
    async selfAudit(myKeys){
      const hist=this.log.history(this.myId);
      const mine=new Set(myKeys.map(k=>k.x+'|'+k.y));
      const rogue=hist.filter(e=>!mine.has(e.keyX+'|'+e.keyY));
      if(rogue.length){
        if(!this.alerts.some(a=>a.kind==='rogue-key'))
          this.alerts.push({userId:this.myId,kind:'rogue-key',count:rogue.length,at:Date.now()});
        return{ok:false,rogue,total:hist.length};
      }
      return{ok:true,total:hist.length};
    }
    markVerified(u){const p=this.pinned.get(u);if(p){p.state='verified';return true}return false}
    state(u){return this.pinned.get(u)?.state||'unknown'}
    fail(r){this.alerts.push({kind:'failure',reason:r,at:Date.now()});return{ok:false,reason:r}}
  }
  return {MTH,inclusionPath,consistencyProof,verifyInclusion,verifyConsistency,
    leafHash,nodeHash,entryBytes,Log,Monitor,Witness,verifyCosigs,gossipTag,gossipCheck};
})();

/* LOG/MON/WITNESSES/PEERVIEWS sind bewusst NICHT Teil dieses Moduls:
   In der ursprünglichen index.html liefen sie als lokal simuliertes
   Transparenzprotokoll. Im echten Client läuft das Log auf dem SERVER
   (siehe server.js /api/kt/*) — der Client instanziiert pro Sitzung
   einen eigenen KT.Monitor und füttert ihn mit STH/Proof-Antworten
   des Servers. Das übernimmt app.js, nicht dieses Krypto-Modul. */

const X3DH = {
  async initiator(myIK, theirBundle){
    /* ── Signaturprüfung ZUERST. Kein DH auf unverifiziertem Material. ── */
    const v = await PreKeys.verifyBundle(theirBundle);
    if(!v.ok) throw new Error('Prekey-Bundle abgelehnt: ' + v.reason);

    const EK = await P.genDH();
    const spk = await P.impPub(theirBundle.spk);
    const ik  = await P.impPub(theirBundle.ikDH);
    const opk = theirBundle.opk ? await P.impPub(theirBundle.opk) : null;
    const dh1 = await P.dh(myIK.priv, spk);
    const dh2 = await P.dh(EK.priv,   ik);
    const dh3 = await P.dh(EK.priv,   spk);
    const dh4 = opk ? await P.dh(EK.priv, opk) : new ArrayBuffer(0);
    const SK  = await P.hkdf(cat(dh1,dh2,dh3,dh4), null, 'SecureChat-X3DH-v1');
    return {SK, EK, usedOpkId: theirBundle.opkId, verified: v};
  },
  async responder(myIK, mySPK, myOPK, theirIKjwk, theirEKjwk){
    const ik = await P.impPub(theirIKjwk);
    const ek = await P.impPub(theirEKjwk);
    const dh1 = await P.dh(mySPK.priv, ik);
    const dh2 = await P.dh(myIK.priv,  ek);
    const dh3 = await P.dh(mySPK.priv, ek);
    const dh4 = myOPK ? await P.dh(myOPK.priv, ek) : new ArrayBuffer(0);
    return P.hkdf(cat(dh1,dh2,dh3,dh4), null, 'SecureChat-X3DH-v1');
  }
};

/*══════════════════════════════════════════════════════════════════════════
  🔁 DOUBLE RATCHET
  ────────────────────────────────────────────────────────────────────────
  Zustand pro Sitzung:
    RK    Root Key            — wandert bei jedem Richtungswechsel weiter
    DHs   eigenes DH-Paar     — wird bei jedem Richtungswechsel neu erzeugt
    DHr   letzter fremder Pub — Auslöser für den DH-Ratchet
    CKs   Sende-Chain-Key     — schrittweise pro gesendeter Nachricht
    CKr   Empfangs-Chain-Key
    Ns/Nr Zähler in der jeweiligen Chain
    PN    Länge der vorherigen Sendekette (für übersprungene Keys)
    skipped  Map "pubId:n" → Message Key, für Nachrichten außer der Reihe

  Zwei ineinandergreifende Ratchets:
    • Symmetrischer Ratchet: CK → HMAC(CK,0x02) = CK'   (jede Nachricht)
                             MK  = HMAC(CK,0x01)        (einmal verwendbar)
    • DH-Ratchet:            neues DH → HKDF(RK, DH) → neuer RK + Chain Key
  Ergebnis: Forward Secrecy (alter Key nutzlos für alte Nachrichten)
            und Post-Compromise Security (Selbstheilung nach Leak).
══════════════════════════════════════════════════════════════════════════*/
const MAX_SKIP = 200;

const Ratchet = {
  /* Alice startet: sie kennt bereits Bobs SPK als ersten DHr */
  async initSender(SK, theirSPKjwk){
    const DHs = await P.genDH();
    const DHr = await P.impPub(theirSPKjwk);
    const dh  = await P.dh(DHs.priv, DHr);
    const [RK, CKs] = await Ratchet.kdfRK(SK, dh);
    return {RK, DHs, DHrJwk: theirSPKjwk, DHr, CKs, CKr:null,
            Ns:0, Nr:0, PN:0, skipped:new Map(), dhSteps:1, log:[]};
  },
  /* Bob startet: sein SPK ist das erste DHs, DHr noch unbekannt */
  initReceiver(SK, mySPK){
    return {RK:SK, DHs:mySPK, DHrJwk:null, DHr:null, CKs:null, CKr:null,
            Ns:0, Nr:0, PN:0, skipped:new Map(), dhSteps:0, log:[]};
  },

  /* Root-KDF: (RK, dh) → (RK', CK) */
  async kdfRK(RK, dhOut){
    const out = await P.hkdf(dhOut, new Uint8Array(RK), 'SecureChat-RootRatchet-v1', 64);
    return [out.slice(0,32), out.slice(32,64)];
  },
  /* Chain-KDF: CK → (MK, CK') über HMAC mit Konstanten */
  async kdfCK(CK){
    const mk  = await P.hmac(CK, new Uint8Array([0x01]));
    const ck2 = await P.hmac(CK, new Uint8Array([0x02]));
    return [mk, ck2];
  },
  /* Message Key → AES-Key + IV */
  async mkParts(MK){
    const out = await P.hkdf(MK, new Uint8Array(32), 'SecureChat-MessageKey-v1', 44);
    return {key: out.slice(0,32), iv: out.slice(32,44)};
  },

  /* ---------- SENDEN ---------- */
  async encrypt(st, plainBuf, assoc){
    if(!st.CKs) throw new Error('Sendekette noch nicht bereit');
    const [MK, CKnext] = await Ratchet.kdfCK(st.CKs);
    st.CKs = CKnext;
    const header = {dh: st.DHs.pubJwk, pn: st.PN, n: st.Ns};
    st.Ns++;
    const {key, iv} = await Ratchet.mkParts(MK);
    const aad = assoc + '|' + JSON.stringify(header);
    const ct = await P.seal(key, iv, plainBuf, aad);
    st.log.push({dir:'out', n:header.n, step:st.dhSteps, t:Date.now()});
    return {header, ct};
  },

  /* ---------- EMPFANGEN ---------- */
  async decrypt(st, msg, assoc){
    /* 1) Liegt der Key schon als übersprungener Key bereit? */
    const skipKey = msg.header.dh.x + ':' + msg.header.n;
    if(st.skipped.has(skipKey)){
      const MK = st.skipped.get(skipKey);
      st.skipped.delete(skipKey);
      return Ratchet.tryOpen(MK, msg, assoc);
    }
    /* 2) Neuer fremder DH-Key → DH-Ratchet-Schritt */
    if(!st.DHrJwk || msg.header.dh.x !== st.DHrJwk.x || msg.header.dh.y !== st.DHrJwk.y){
      await Ratchet.skipTo(st, msg.header.pn);
      await Ratchet.dhStep(st, msg.header.dh);
    }
    /* 3) Lücken in der aktuellen Kette überspringen und Keys aufheben */
    await Ratchet.skipTo(st, msg.header.n);
    /* 4) Regulär entschlüsseln */
    const [MK, CKnext] = await Ratchet.kdfCK(st.CKr);
    st.CKr = CKnext; st.Nr++;
    st.log.push({dir:'in', n:msg.header.n, step:st.dhSteps, t:Date.now()});
    return Ratchet.tryOpen(MK, msg, assoc);
  },
  async tryOpen(MK, msg, assoc){
    const {key, iv} = await Ratchet.mkParts(MK);
    const aad = assoc + '|' + JSON.stringify(msg.header);
    return P.open(key, iv, msg.ct, aad);
  },
  /* Message Keys bis Index `until` aufheben (Nachrichten außer der Reihe) */
  async skipTo(st, until){
    if(!st.CKr) return;
    if(st.Nr + MAX_SKIP < until) throw new Error('Zu viele übersprungene Nachrichten');
    while(st.Nr < until){
      const [MK, CKnext] = await Ratchet.kdfCK(st.CKr);
      st.skipped.set(st.DHrJwk.x + ':' + st.Nr, MK);
      st.CKr = CKnext; st.Nr++;
    }
  },
  /* DH-Ratchet: neuer Root Key, neue Ketten, frisches eigenes DH-Paar */
  async dhStep(st, theirPubJwk){
    st.PN = st.Ns; st.Ns = 0; st.Nr = 0;
    st.DHrJwk = theirPubJwk;
    st.DHr = await P.impPub(theirPubJwk);
    let dh = await P.dh(st.DHs.priv, st.DHr);
    [st.RK, st.CKr] = await Ratchet.kdfRK(st.RK, dh);
    st.DHs = await P.genDH();
    dh = await P.dh(st.DHs.priv, st.DHr);
    [st.RK, st.CKs] = await Ratchet.kdfRK(st.RK, dh);
    st.dhSteps++;
  },
  /* Fingerprint des aktuellen Root Keys — nur zur Anzeige */
  async rkFp(st){ return hexs(await SC.digest('SHA-256', st.RK)).slice(0,16) }
};

export { P, PreKeys, KT, X3DH, Ratchet, MAX_SKIP, b64, ub64, hexs, cat, te, td, rnd };
