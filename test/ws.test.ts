import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import {createServer,type Server} from 'node:http';
import {once} from 'node:events';
import {mkdtempSync,rmSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import WebSocket from 'ws';
import {Store} from '../server/store.js';
import {createApp} from '../server/app.js';
import {allowedProxy} from '../server/proxy.js';
import {attachWebSocket} from '../server/ws.js';
async function listen(s:Server){await new Promise<void>(r=>s.listen(0,'127.0.0.1',r));return 'http://127.0.0.1:'+(s.address() as any).port;}
async function close(s:Server){s.closeAllConnections();await new Promise<void>(r=>s.close(()=>r()));}
class Peer{
 ws:WebSocket;messages:any[]=[];wake?:()=>void;
 constructor(url:string,options:any={}){this.ws=new WebSocket(url.replace('http','ws')+'/transport','agyp.v1',options);this.ws.on('message',b=>{this.messages.push(JSON.parse(b.toString()));this.wake?.();});this.ws.on('error',()=>{});}
 async next(){if(this.messages.length)return this.messages.shift();await Promise.race([new Promise<void>(r=>this.wake=r),new Promise<void>((_,reject)=>{const timer=setTimeout(()=>reject(new Error('frame timeout')),3000);timer.unref();})]);this.wake=undefined;return this.messages.shift();}
 send(o:any){this.ws.send(JSON.stringify(o));}
 async auth(token:string){const c=await this.next();assert.equal(c.type,'challenge');this.send({type:'auth',keyId:token.slice(5,21),proof:createHmac('sha256',token).update('agyp-ws-v1\n'+c.salt+'\n'+c.nonce).digest('hex')});assert.equal((await this.next()).type,'ready');}
 async stop(){if(this.ws.readyState===WebSocket.CLOSED)return;const p=once(this.ws,'close');this.ws.terminate();await p;}
}
const rid=(n:number)=>n.toString(16).padStart(32,'0');
function start(p:Peer,n:number,body:string,path='/v1internal:generateContent'){const id=rid(n);p.send({type:'start',id,method:'POST',path,headers:{'content-type':'application/json','user-agent':'unchanged-client'},deadline:Date.now()+10000});if(body)p.send({type:'data',id,data:Buffer.from(body).toString('base64')});p.send({type:'end',id});}
async function result(p:Peer){const h=await p.next();assert.equal(h.type,'headers');let body='';for(;;){const f=await p.next();assert.equal(f.id,h.id);if(f.type==='end')return {status:h.status,body,headers:h.headers};assert.equal(f.type,'data');body+=Buffer.from(f.data,'base64').toString();}}
test('websocket proof, exact proxy pipeline, allowance, usage, per-request revocation and failclosed paths',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-ws-')),store=new Store(dir);let calls=0,rawSeen='',ua='';
 const upstream=createServer(async(req,res)=>{calls++;let b='';for await(const c of req)b+=c;rawSeen=b;ua=String(req.headers['user-agent']);res.setHeader('content-type','text/event-stream');res.end('data: {"response":{"text":"OK","usageMetadata":{"promptTokenCount":2,"candidatesTokenCount":1,"totalTokenCount":3}}}\n\n');});
 const config={origin:'',upstream:await listen(upstream),clientId:'',clientSecret:'',secure:false};
 const {app,pool}=createApp(store,config),server=createServer(app);const transport=attachWebSocket(server,store,pool);config.origin=await listen(server);
 store.putAccount({id:'a',email:'fake@example.invalid',refresh_token:'fake',access_token:'fake',token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets:[{family:'gemini',label:'Gemini',remaining:1,reset:0}],cooldowns:{},denied:{},updated:Date.now()});
 const peers:Peer[]=[];const make=()=>{const p=new Peer(config.origin);peers.push(p);return p;};
 try{
  const key=store.createKey({name:'ws'}),p=make();await p.auth(key.token);
  const raw='{ "model":"gemini-flash", "request":{"contents":[{"parts":[{"text":"雪"}]}]}, "n":1e+05 }';
  start(p,1,raw);let r=await result(p);assert.equal(r.status,200);assert(r.body.includes('OK'));assert.equal(rawSeen,raw);assert.equal(ua,'unchanged-client');assert.equal(store.used(key.key).total,3);assert.equal(calls,1);
  start(p,90,'{}');r=await result(p);assert.equal(r.status,400);assert.deepEqual(JSON.parse(r.body),{error:{message:'Request rejected'}});assert.equal(calls,1);assert.equal(store.used(key.key).total,3);
  const bounded=store.createKey({name:'bounded',allowance:10000}),q=make();await q.auth(bounded.token);
  start(q,1,raw);r=await result(q);assert.equal(r.status,422);assert.equal(calls,1);assert.equal(store.used(bounded.key).total,0);
  start(q,2,JSON.stringify({model:'gemini-flash',request:{generationConfig:{maxOutputTokens:10}}}));r=await result(q);assert.equal(r.status,200);assert.equal(store.used(bounded.key).total,3);assert.equal(calls,2);
  const before=calls;const closed=once(p.ws,'close');start(p,2,raw,'//example.invalid/v1internal:generateContent');await closed;assert.equal(calls,before);
  const v=make();await v.auth(key.token);store.revoke(key.key.id);const revoked=once(v.ws,'close');start(v,1,raw);await revoked;assert.equal(calls,before);
  const bad=make();const c=await bad.next();bad.send({type:'auth',keyId:bounded.key.id,proof:createHmac('sha256',bounded.token).update(c.nonce).digest('hex')});await once(bad.ws,'close');assert.equal(calls,before);
  assert.equal((store.db.prepare('SELECT COUNT(*) n FROM reservations').get() as any).n,0);
 }finally{await Promise.all(peers.map(p=>p.stop()));await transport.close();await close(server);await close(upstream);store.close();rmSync(dir,{recursive:true,force:true});}
});
test('duplicate IDs and disallowed browser origin fail closed',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-ws-')),store=new Store(dir);const config={origin:'',upstream:'http://127.0.0.1:1',clientId:'',clientSecret:'',secure:false};const {app,pool}=createApp(store,config),server=createServer(app);const transport=attachWebSocket(server,store,pool);config.origin=await listen(server);
 let p:Peer|undefined;
 try{
  const browser=new WebSocket(config.origin.replace('http','ws')+'/transport','agyp.v1',{origin:config.origin});browser.on('error',()=>{});await once(browser,'unexpected-response').then(([,r]:any)=>{assert.equal(r.statusCode,403);r.resume();browser.terminate();});
  p=new Peer(config.origin);await p.auth(store.createKey({name:'ws'}).token);const f={type:'start',id:rid(1),method:'GET',path:'/v1/models',headers:{},deadline:Date.now()+10000};p.send(f);p.send(f);await once(p.ws,'close');
 }finally{await p?.stop();await transport.close();await close(server);store.close();rmSync(dir,{recursive:true,force:true});}
});
test('transport bounds empty chunks, chunk count, frame size, request slots and expired proofs',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-ws-limits-')),store=new Store(dir);const config={origin:'',upstream:'http://127.0.0.1:1',clientId:'',clientSecret:'',secure:false};const {app,pool}=createApp(store,config),server=createServer(app);const transport=attachWebSocket(server,store,pool);config.origin=await listen(server);
 const key=store.createKey({name:'limits'});const peers:Peer[]=[];
 const make=async()=>{const p=new Peer(config.origin);peers.push(p);await p.auth(key.token);return p;};
 const f={type:'start',id:rid(1),method:'POST',path:'/v1internal:generateContent',headers:{},deadline:Date.now()+10000};
 try{
  let p=await make();p.send(f);let closed=once(p.ws,'close');p.send({type:'data',id:f.id,data:''});await closed;
  p=await make();p.send(f);closed=once(p.ws,'close');for(let i=0;i<4097;i++)p.send({type:'data',id:f.id,data:'eA=='});await closed;
  p=await make();closed=once(p.ws,'close');p.ws.send('x'.repeat(65537));await closed;
  p=await make();closed=once(p.ws,'close');for(let i=0;i<9;i++)p.send({...f,id:rid(i+1)});await closed;
  p=await make();closed=once(p.ws,'close');p.send({...f,headers:{'x-bad':'a\r\nb'}});await closed;
  p=new Peer(config.origin);peers.push(p);const c=await p.next(),now=Date.now;
  try{Date.now=()=>c.expires+1;closed=once(p.ws,'close');p.send({type:'auth',keyId:key.key.id,proof:createHmac('sha256',key.token).update('agyp-ws-v1\n'+c.salt+'\n'+c.nonce).digest('hex')});await closed;}finally{Date.now=now;}
  assert.equal((store.db.prepare('SELECT COUNT(*) n FROM reservations').get() as any).n,0);
 }finally{await Promise.all(peers.map(p=>p.stop()));await transport.close();await close(server);store.close();rmSync(dir,{recursive:true,force:true});}
});
test('upgrade throttling uses TCP peer rather than forged forwarding headers',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-ws-rate-')),store=new Store(dir),config={origin:'',upstream:'http://127.0.0.1:1',clientId:'',clientSecret:'',secure:false};const {app,pool}=createApp(store,config),server=createServer(app);const transport=attachWebSocket(server,store,pool);config.origin=await listen(server);
 try{
  for(let i=0;i<61;i++){
   const ws=new WebSocket(config.origin.replace('http','ws')+'/transport','agyp.v1',{origin:'https://forbidden.invalid',headers:{'x-forwarded-for':'192.0.2.'+i}});ws.on('error',()=>{});
   const [,response]=await once(ws,'unexpected-response') as any;assert.equal(response.statusCode,i<60?403:429);response.resume();ws.terminate();
  }
 }finally{await transport.close();await close(server);store.close();rmSync(dir,{recursive:true,force:true});}
});
test('transport shutdown settles dispatched usage before the database can close',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-ws-drain-')),store=new Store(dir);let dispatched!:()=>void;const began=new Promise<void>(r=>dispatched=r);
 const upstream=createServer(async(req,res)=>{for await(const _ of req){}res.setHeader('content-type','text/event-stream');res.write('data: {"response":{"usageMetadata":{"promptTokenCount":2,"candidatesTokenCount":1,"totalTokenCount":3}}}\n\n');dispatched();});
 const config={origin:'',upstream:await listen(upstream),clientId:'',clientSecret:'',secure:false};const {app,pool}=createApp(store,config),server=createServer(app);const transport=attachWebSocket(server,store,pool);config.origin=await listen(server);
 store.putAccount({id:'a',email:'fake@example.invalid',refresh_token:'fake',access_token:'fake',token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets:[{family:'gemini',label:'Gemini',remaining:1,reset:0}],cooldowns:{},denied:{},updated:Date.now()});
 const key=store.createKey({name:'drain',allowance:10000}),p=new Peer(config.origin);
 try{await p.auth(key.token);start(p,1,JSON.stringify({model:'gemini-flash',request:{generationConfig:{maxOutputTokens:10}}}));await began;assert.equal((await p.next()).type,'headers');assert.equal((await p.next()).type,'data');assert.equal((store.db.prepare('SELECT COUNT(*) n FROM reservations').get() as any).n,1);await transport.close();assert.equal((store.db.prepare('SELECT COUNT(*) n FROM reservations').get() as any).n,0);assert.equal(store.used(key.key).total,3);}
 finally{await p.stop();await transport.close();await close(server);await close(upstream);store.close();rmSync(dir,{recursive:true,force:true});}
});

test('full Cloud Code namespace matrix over authenticated WS preserves service fidelity and bounded admission',async()=>{
 const matrix=JSON.parse(readFileSync(new URL('./fixtures/cloudcode-paths.json',import.meta.url),'utf8')) as {method:string;path:string;allowed:boolean;bounded:boolean}[];
 const dir=mkdtempSync(join(tmpdir(),'agyp-ws-compat-')),store=new Store(dir);let calls=0,seen:any;
 const reply='{ "cloudaicompanionProject":"fixture-project", "operation":{"name":"fixture-op"}, "unknownField":true }';
 const upstream=createServer(async(req,res)=>{calls++;let body='';for await(const c of req)body+=c;seen={method:req.method,path:req.url,body};assert.equal(req.headers.authorization,'Bearer fixture-access');res.setHeader('content-type','application/json');res.end(reply);});
 const config={origin:'',upstream:await listen(upstream),clientId:'',clientSecret:'',secure:false}, {app,pool}=createApp(store,config),server=createServer(app);const transport=attachWebSocket(server,store,pool);config.origin=await listen(server);
 store.putAccount({id:'a',email:'fixture@example.invalid',refresh_token:'fake',access_token:'fixture-access',token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets:[],cooldowns:{},denied:{},updated:Date.now()});
 const key=store.createKey({name:'unlimited'}),bounded=store.createKey({name:'bounded',allowance:100000}),p=new Peer(config.origin),q=new Peer(config.origin);const peers=[p,q];let id=0;
 const payload=(path:string)=>path.startsWith('/v1internal')?'{ "metadata":{"ideType":"ANTIGRAVITY"}, "model":"gemini-flash", "request":{"contents":[],"generationConfig":{"maxOutputTokens":10}}, "n":1e+05 }':'{ "contents":[],"generationConfig":{"maxOutputTokens":10},"n":1e+05 }';
 const invoke=async(peer:Peer,c:typeof matrix[number])=>{const n=rid(++id),body=['GET','HEAD'].includes(c.method)?'':payload(c.path);peer.send({type:'start',id:n,method:c.method,path:c.path,headers:{'content-type':'application/json'},deadline:Date.now()+10000});if(body)peer.send({type:'data',id:n,data:Buffer.from(body).toString('base64')});peer.send({type:'end',id:n});return result(peer);};
 try{
  await p.auth(key.token);await q.auth(bounded.token);
  const expectedCharge=(c:typeof matrix[number])=>c.method==='POST'&&/:(?:generateContent|streamGenerateContent)$/.test(c.path)?{input:Buffer.byteLength(payload(c.path))+1024,output:10}:{input:0,output:0};
  const checkCharge=(key:any,before:any,c:typeof matrix[number])=>{const charge=expectedCharge(c),after=store.used(key);assert.deepEqual({...after},{input:before.input+charge.input,output:before.output+charge.output,total:before.total+charge.input+charge.output},c.method+' '+c.path+' exact accounting');};
  for(const c of matrix.filter(c=>c.allowed)){
   const unBefore=store.used(key.key),boundedBefore=store.used(bounded.key);
   let before=calls,r=await invoke(p,c);assert.equal(r.status,200,c.method+' '+c.path);assert.equal(r.body,c.method==='HEAD'?'':reply);assert.equal(calls,before+1);assert.deepEqual(seen,{method:c.method,path:c.path,body:['GET','HEAD'].includes(c.method)?'':payload(c.path)});
   checkCharge(key.key,unBefore,c);
   if(c.path==='/v1internal:loadCodeAssist')continue;
   before=calls;r=await invoke(q,c);assert.equal(r.status,c.bounded?200:422,c.method+' '+c.path);assert.equal(calls,before+(c.bounded?1:0));if(c.bounded)checkCharge(bounded.key,boundedBefore,c);else assert.deepEqual(store.used(bounded.key),boundedBefore);
  }
  const exhausted=store.createKey({name:'exhausted',allowance:0}),e=new Peer(config.origin);peers.push(e);await e.auth(exhausted.token);const beforeExhausted=calls;
  for(const [path,status] of [['/v1internal:newFutureAction',422],['/v1internal:generateContent',429],['/v1internal:fetchAvailableModels',200]] as const){const r=await invoke(e,{method:'POST',path,allowed:true,bounded:true});assert.equal(r.status,status,path);}
  assert.equal(calls,beforeExhausted+1);assert.deepEqual({...store.used(exhausted.key)},{input:0,output:0,total:0});
  const before=calls;
  for(const c of matrix.filter(c=>!c.allowed)){
   const bad=new Peer(config.origin);peers.push(bad);await bad.auth(key.token);const closed=once(bad.ws,'close');bad.send({type:'start',id:rid(1),method:c.method,path:c.path,headers:{},deadline:Date.now()+10000});await closed;assert.equal(calls,before,c.path);
  }
  assert.equal((store.db.prepare('SELECT COUNT(*) n FROM reservations').get() as any).n,0);
 }finally{await Promise.all(peers.map(p=>p.stop()));await transport.close();await close(server);await close(upstream);store.close();rmSync(dir,{recursive:true,force:true});}
});

test('bounded WS bootstrap rejects query and raw variants without private fields or inadmissible dispatch',async()=>{
 const cases=JSON.parse(readFileSync(new URL('./fixtures/bounded-bootstrap-paths.json',import.meta.url),'utf8')) as {path:string;body:string;status:number}[];
 const dir=mkdtempSync(join(tmpdir(),'agyp-ws-bootstrap-variants-')),store=new Store(dir);let calls=0;
 const upstream=createServer(async(req,res)=>{calls++;assert.equal(req.url,'/v1internal:loadCodeAssist');let raw='';for await(const c of req)raw+=c;assert.equal(raw,'{"metadata":{"ideType":"ANTIGRAVITY"}}');res.end(JSON.stringify({currentTier:{id:'premium-tier',name:'Pro'},cloudaicompanionProject:'private-project',token:'private-token'}));});
 const config={origin:'',upstream:await listen(upstream),clientId:'',clientSecret:'',secure:false},{app,pool}=createApp(store,config),server=createServer(app),transport=attachWebSocket(server,store,pool);config.origin=await listen(server);
 store.putAccount({id:'a',email:'fake@example.invalid',refresh_token:'fake',access_token:'fake',token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets:[],cooldowns:{},denied:{},updated:Date.now()});
 const key=store.createKey({name:'zero-budget',allowance:0}),peers:Peer[]=[];
 try{for(const c of cases){const p=new Peer(config.origin);peers.push(p);await p.auth(key.token);const before=calls;
 if(!allowedProxy('POST',c.path)){const closed=once(p.ws,'close');p.send({type:'start',id:rid(1),method:'POST',path:c.path,headers:{},deadline:Date.now()+10000});await closed;}
 else{start(p,1,c.body,c.path);const response=await result(p);assert.equal(response.status,c.status,c.path);assert.doesNotMatch(response.body,/private-project|private-token|cloudaicompanionProject|unapproved/);}
 assert.equal(calls,before+(c.status===200?1:0),c.path);assert.deepEqual({...store.used(key.key)},{input:0,output:0,total:0});await p.stop();}
 assert.equal((store.db.prepare('SELECT COUNT(*) n FROM reservations').get() as any).n,0);
 }finally{await Promise.all(peers.map(p=>p.stop()));await transport.close();await close(server);await close(upstream);store.close();rmSync(dir,{recursive:true,force:true});}
});

test('every generation admission 400 has bounded value-free local diagnostics and no upstream work or charge',async()=>{
 const {LocalAdmissionDiagnostics}=await import('../server/diagnostics.js');
 const dir=mkdtempSync(join(tmpdir(),'agyp-ws-admission-')),store=new Store(dir),diagnostics=new LocalAdmissionDiagnostics();let calls=0,upstreamReject=false;
 const upstream=createServer(async(req,res)=>{calls++;for await(const _ of req){}res.setHeader('content-type','application/json');if(upstreamReject){res.writeHead(400).end('{"error":{"message":"CANARY_UPSTREAM"}}');return;}res.end('{"usageMetadata":{"promptTokenCount":2,"candidatesTokenCount":1,"totalTokenCount":3}}');});
 const config={origin:'',upstream:await listen(upstream),clientId:'',clientSecret:'',secure:false},{app,pool,bootstrap}=createApp(store,config),server=createServer(app),transport=attachWebSocket(server,store,pool,bootstrap,diagnostics);config.origin=await listen(server);
 store.putAccount({id:'a',email:'fake@example.invalid',refresh_token:'fake',access_token:'fake',token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets:[],cooldowns:{},denied:{},updated:Date.now()});
 const key=store.createKey({name:'unlimited'}),bounded=store.createKey({name:'bounded',allowance:100000}),p=new Peer(config.origin),q=new Peer(config.origin);let n=0;
 const valid={model:'gemini-flash',request:{contents:[{role:'user',parts:[{text:'CANARY_CONTENT'}]}]}};
 const body=(o:any)=>JSON.stringify(o),internal='/v1internal:generateContent';
 const cases:[string,string,string,string?][]=[
  ['invalid_json','{"CANARY_PARSE":',internal],
  ...[null,[],1,'CANARY_ROOT'].map(v=>['invalid_root',body(v),internal] as [string,string,string]),
  ['missing_model',body({request:{}}),internal],
  ['model_conflict',body(valid),internal+'?model=CANARY_QUERY'],
  ['model_conflict',body(valid),'/v1/models/CANARY_PATH:generateContent'],
  ...[undefined,null,[],1].map(request=>['missing_request',body({model:'gemini-flash',request}),internal] as [string,string,string]),
  ...['generationConfig','generation_config'].map(k=>['mixed_envelope',body({...valid,[k]:{}}),internal] as [string,string,string]),
  ['nested_envelope',body({request:{}}),'/v1/models/gemini-flash:generateContent'],
  ['noncanonical_config',body({...valid,request:{generation_config:{}}}),internal],
  ...['max_output_tokens','candidate_count','thinking_config'].map(k=>['noncanonical_config',body({...valid,request:{generationConfig:{[k]:1}}}),internal] as [string,string,string]),
  ...[[],1,'CANARY_CONFIG',true].map(generationConfig=>['invalid_config',body({...valid,request:{generationConfig}}),internal] as [string,string,string]),
  ...[0,-1,2147483648,Number.MAX_SAFE_INTEGER+1,1.5,'CANARY_BOUND',false,{}].map(maxOutputTokens=>['invalid_output_bound',body({...valid,request:{generationConfig:{maxOutputTokens}}}),internal] as [string,string,string]),
 ];
 try{
  await p.auth(key.token);await q.auth(bounded.token);
  const unauthorized=new Peer(config.origin);const challenge=await unauthorized.next();unauthorized.send({type:'auth',keyId:key.key.id,proof:'0'.repeat(64)});await once(unauthorized.ws,'close');assert.equal(diagnostics.snapshot().length,0);assert.equal(calls,0);
  const ids=new Set<string>();
  for(const [reason,raw,path] of cases){
   const before=calls;start(p,++n,raw,path);const r=await result(p);assert.equal(r.status,400,reason);const cid=JSON.parse(r.body).error.correlationId;assert.match(cid,/^[a-f0-9-]{36}$/);assert(!ids.has(cid));ids.add(cid);
   assert(JSON.parse(r.body).error.message.includes(cid));
   const record=diagnostics.snapshot().at(-1)!;assert.equal(record.reason,reason);assert.equal(record.correlationId,cid);assert.equal(calls,before);assert.deepEqual({...store.used(key.key)},{input:0,output:0,total:0});assert.equal((store.db.prepare('SELECT COUNT(*) n FROM reservations').get() as any).n,0);
   assert.doesNotMatch(JSON.stringify(record),/CANARY|gemini-flash|fake/);
  }
  // Same authenticated connection, fresh request then synthetic history-shaped turn.
  start(p,++n,body(valid));let r=await result(p);assert.equal(r.status,200);assert(!('correlationId' in JSON.parse(r.body)));
  start(p,++n,body({...valid,request:{contents:[...valid.request.contents,{role:'model',parts:[{text:'CANARY_REPLY'}]},{role:'user',parts:[{text:'CANARY_FOLLOWUP'}]}]}}));r=await result(p);assert.equal(r.status,200);assert.equal(store.used(key.key).total,6);
  const count=diagnostics.snapshot().length;
  upstreamReject=true;start(p,++n,body(valid));r=await result(p);assert.equal(r.status,400);assert.match(r.body,/Upstream request rejected/);assert(!JSON.parse(r.body).error.correlationId);assert.equal(diagnostics.snapshot().length,count);assert.equal(store.used(key.key).total,6);upstreamReject=false;
  for(const raw of ['{',body({metadata:{ideType:'CANARY_ENUM'},CANARY_UNKNOWN:'CANARY_VALUE'})]){
   const before=calls;start(q,++n,raw,'/v1internal:loadCodeAssist');r=await result(q);assert.equal(r.status,400);assert.equal(calls,before);assert.equal(diagnostics.snapshot().at(-1)!.reason,'invalid_bootstrap');assert.equal(diagnostics.snapshot().at(-1)!.correlationId,JSON.parse(r.body).error.correlationId);assert.doesNotMatch(JSON.stringify(diagnostics.snapshot()),/CANARY/);
  }
  assert.deepEqual({...store.used(bounded.key)},{input:0,output:0,total:0});
  assert.equal((store.db.prepare('SELECT COUNT(*) n FROM reservations').get() as any).n,0);
 }finally{await Promise.all([p.stop(),q.stop()]);await transport.close();await close(server);await close(upstream);store.close();rmSync(dir,{recursive:true,force:true});}
});

test('local diagnostics sanitizer cannot retain arbitrary keys, values, URLs, query or mutable references',async()=>{
 const {LocalAdmissionDiagnostics,admissionShape}=await import('../server/diagnostics.js');
 const diagnostics=new LocalAdmissionDiagnostics();
 const raw=Buffer.from(JSON.stringify({CANARY_KEY:'CANARY_VALUE',model:'CANARY_MODEL',request:{CANARY_REQUEST:'CANARY_VALUE',contents:[{CANARY_NESTED:'CANARY_TEXT'}],generationConfig:{maxOutputTokens:'CANARY_TOKENS',thinkingConfig:{thinkingBudget:'CANARY_BUDGET',CANARY_DEEP:'CANARY_VALUE'}}},metadata:{ideType:'CANARY_ENUM',CANARY_META:'CANARY_VALUE'}}));
 for(let i=0;i<40;i++)diagnostics.record('CANARY_METHOD','/v1internal:CANARY_PATH?CANARY_QUERY',raw,'invalid_output_bound');
 const records=diagnostics.snapshot();assert.equal(records.length,32);assert(records.every(r=>r.method==='other'&&r.path==='other'));assert.doesNotMatch(JSON.stringify(records),/CANARY/);assert(Buffer.byteLength(JSON.stringify(records))<=32*8192);
 assert.equal(records[0].shape.unknownKeys,4);assert(records[0].shape.fields.some(f=>f.field==='request.generationConfig.thinkingConfig.thinkingBudget'&&f.type==='string'));
 records[0].shape.fields.push({field:'CANARY_MUTATION',type:'CANARY_TYPE'});assert.doesNotMatch(JSON.stringify(diagnostics.snapshot()),/CANARY/);
 assert.equal(admissionShape(Buffer.alloc(16*1024*1024+1)).truncated,true);
 assert.equal(diagnostics.record('POST','/v1internal:generateContent',raw,'CANARY_REASON' as any),undefined);
});

test('uniform exact one-million output ceiling preserves every key budget over authenticated WSS',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-output-policy-')),store=new Store(dir);let calls=0,rawSeen='',reject=false,missingUsage=false;
 const upstream=createServer(async(req,res)=>{calls++;rawSeen='';for await(const c of req)rawSeen+=c;res.setHeader('content-type','application/json');if(reject){res.writeHead(400).end('{"error":{"message":"CANARY_UPSTREAM_VALUE"}}');return;}res.end(missingUsage?'{}':'{"usageMetadata":{"promptTokenCount":2,"candidatesTokenCount":1,"totalTokenCount":3}}');});
 const config={origin:'',upstream:await listen(upstream),clientId:'',clientSecret:'',secure:false},{app,pool}=createApp(store,config),server=createServer(app),transport=attachWebSocket(server,store,pool);config.origin=await listen(server);
 store.putAccount({id:'a',email:'fake@example.invalid',refresh_token:'fake',access_token:'fake',token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets:[],cooldowns:{},denied:{},updated:Date.now()});
 const defs=[{}, {allowance:1e7}, {inputCap:1e7}, {outputCap:1e7}, {allowance:0},{outputCap:0},{inputCap:0}, {allowance:1e7,inputCap:1e7}, {allowance:1e7,outputCap:1e7}, {inputCap:1e7,outputCap:1e7}, {allowance:1e7,inputCap:1e7,outputCap:1e7}, {allowance:1e7,period:'daily'}, {period:'daily'}];
 const peers:Peer[]=[];let id=0;
 const paths=['/v1internal:streamGenerateContent','/v1internal:generateContent','/v1/models/gemini-flash:generateContent','/v1/models/gemini-flash:streamGenerateContent'];
 const makeRaw=(value:any,internal:boolean)=>{const request={contents:[{parts:[{text:'SYNTHETIC_ONLY'}]}],generationConfig:{maxOutputTokens:value}};return JSON.stringify(internal?{model:'gemini-flash',request}:request);};
 const reservations=()=>Number((store.db.prepare('SELECT COUNT(*) n FROM reservations').get() as any).n);
 try{
  for(const [i,def] of defs.entries()){
   const key=store.createKey({name:'policy-'+i,...def}),p=new Peer(config.origin);peers.push(p);await p.auth(key.token);
   for(const path of paths)for(const value of [0,-1,1.5,1,131073,1000000,1000001,2147483647,2147483648,Number.MAX_SAFE_INTEGER,Number.MAX_SAFE_INTEGER+1,'1000000',false,{},null]){
    const before=calls,used={...store.used(key.key)},raw=makeRaw(value,path.startsWith('/v1internal'));
    start(p,++id,raw,path);const r=await result(p);
    const valid=typeof value==='number'&&Number.isInteger(value)&&value>=1&&value<=1000000,accepted=valid&&!(i>=4&&i<=6);
    assert.equal(r.status,valid?(accepted?200:429):400,JSON.stringify({i,value,path}));
    assert.equal(calls,before+(accepted?1:0));assert.equal(reservations(),0);
    if(accepted){assert.equal(rawSeen,raw);assert.equal(store.used(key.key).total,used.total+3);}
    else assert.deepEqual({...store.used(key.key)},used);
   }
   await p.stop();
  }
  // Raw literals, not JavaScript numeric literals: exercise IEEE-754 rounding
  // and exponent forms before any request serialization can erase the evidence.
  const numericCases:[string,number|undefined][]=[
   ['2147483647.0000001',undefined],['2147483646.99999999',undefined],
   ['131073.000000000001',undefined],['131072.000000000001',undefined],
   ['1000000.00000000001',undefined],['999999.99999999999',undefined],
   ['1.00000000000000001e6',undefined],['99999999999999999e-11',undefined],
   ['1e6',1000000],['1000000.00000',1000000],['100000000000000000e-11',1000000],['1000001',undefined],
   ['0.99999999999999999',undefined],['1.00000000000000001',undefined],
   ['2.1474836470000001e9',undefined],['1.31072000000000001e5',undefined],
   ['100000000000000001e-17',undefined],['1.'+'0'.repeat(10000)+'1',undefined],['1e999999999999999999',undefined],
   ['1e-999999999999999999',undefined],['-0.00000000000000001',undefined],
   ['2147483648',undefined],['1e0',1],['1.0000',1],['100000e-5',1],
   ['131072.00000',131072],['1.31072e5',131072],
   ['131073e0',131073],['2.147483647e9',2147483647],
   ['214748364700000000000000e-14',2147483647]
  ];
  for(const [i,def] of defs.entries()){
   const key=store.createKey({name:'raw-policy-'+i,...def}),p=new Peer(config.origin);peers.push(p);await p.auth(key.token);
   for(const path of paths){
    const internal=path.startsWith('/v1internal');
    for(const [lexeme,value] of numericCases){
     const raw=makeRaw('RAW_LITERAL',internal).replace('"RAW_LITERAL"',lexeme);
     const accepted=value!==undefined&&value<=1000000;
     const before=calls,used={...store.used(key.key)};start(p,++id,raw,path);const r=await result(p);
     // Zero caps reject valid admission at reservation, rather than sending upstream.
     const exhausted=i>=4&&i<=6;
     assert.equal(r.status,accepted?(exhausted?429:200):400,JSON.stringify({i,path,lexeme}));
     assert.equal(calls,before+(accepted&&!exhausted?1:0));assert.equal(reservations(),0);
     if(accepted&&!exhausted){assert.equal(rawSeen,raw);assert.equal(store.used(key.key).total,used.total+3);}
     else assert.deepEqual({...store.used(key.key)},used);
    }
    const rawBase=makeRaw(1,internal),gc='"generationConfig":{"maxOutputTokens":1}';
    const ambiguous=[
     rawBase.replace(gc,'"generationConfig":{"maxOutputTokens":2147483647.0000001,"maxOutputTokens":1}'),
     rawBase.replace(gc,'"generationConfig":{"maxOutputTokens":1,"maxOutputTokens":2147483647.0000001}'),
     rawBase.replace(gc,gc+',"generationConfig":{"maxOutputTokens":2}'),
     rawBase.replace(gc,'"generationConfig":{"maxOutputTokens":{"isLosslessNumber":true,"value":"2147483647"}}'),
     rawBase.replace(gc,'"generationConfig":{"maxOutputTokens":1,"maxOutputTokens":null}'),
     rawBase.replace(gc,'"generationConfig":{"maxOutputTokens":1,"maxOutput\\u0054okens":2}'),
     ...(internal?[rawBase.replace('"request":','"request":{"generationConfig":{"maxOutputTokens":2}},"request":')]:[])
    ];
    for(const raw of ambiguous){const before=calls,used={...store.used(key.key)};start(p,++id,raw,path);const r=await result(p);assert.equal(r.status,400,raw);assert.doesNotMatch(r.body,/2147483647|position|duplicate/i);assert.equal(calls,before);assert.deepEqual({...store.used(key.key)},used);assert.equal(reservations(),0);}
    if(i===0){
     // Identical duplicate values are unambiguous. Arbitrary unrelated numeric
     // fields and strings must not be mistaken for the canonical output bound.
     for(const raw of [
      rawBase.replace(gc,'"generationConfig":{"maxOutputTokens":1,"maxOutputTokens":1}'),
      rawBase.replace(gc,'"generationConfig":{"maxOutputTokens":1,"unrelated":2147483647.0000001}'),
      rawBase.replace(gc,gc+',"unrelated":{"maxOutputTokens":2147483647.0000001}'),
      rawBase.replace(gc,gc+',"__proto__":{"generationConfig":{"maxOutputTokens":2147483647.0000001}}'),
      rawBase.replace(gc,'"generationConfig":{"maxOutput\\u0054okens":1e0}'),
      rawBase.replace('SYNTHETIC_ONLY','maxOutputTokens 2147483647.0000001')
     ]){start(p,++id,raw,path);assert.equal((await result(p)).status,200,raw);assert.equal(rawSeen,raw);}
    }
   }
   await p.stop();
  }
  // Exhaust all absent/zero/positive cap combinations and reset periods.
  const combo=store.createKey({name:'all-cap-combinations'}),cp=new Peer(config.origin);peers.push(cp);await cp.auth(combo.token);
  for(const period of ['never','daily','weekly','monthly'])for(const allowance of [null,0,1e7])for(const inputCap of [null,0,1e7])for(const outputCap of [null,0,1e7]){
   store.db.prepare('UPDATE keys SET period=?,allowance=?,inputCap=?,outputCap=? WHERE id=?').run(period,allowance,inputCap,outputCap,combo.key.id);
   const key=store.key(combo.key.id)!,exhausted=[allowance,inputCap,outputCap].includes(0);
   for(const path of paths)for(const [literal,valid] of [['1',true],['1000000',true],['1000001',false],['1000000.00000000001',false],['0.99999999999999999',false]] as const){
    const raw=makeRaw('COMBO_LITERAL',path.startsWith('/v1internal')).replace('"COMBO_LITERAL"',literal),before=calls,used={...store.used(key)};
    start(cp,++id,raw,path);const r=await result(cp),expected=valid?(exhausted?429:200):400;
    assert.equal(r.status,expected,JSON.stringify({period,allowance,inputCap,outputCap,path,literal}));
    assert.equal(calls,before+(expected===200?1:0));assert.equal(reservations(),0);
    if(expected===200){assert.equal(rawSeen,raw);assert.equal(store.used(key).total,used.total+3);}
    else assert.deepEqual({...store.used(key)},used);
   }
  }
  await cp.stop();
  const bounded=store.createKey({name:'bounded-boundary',allowance:1e7}),q=new Peer(config.origin);peers.push(q);await q.auth(bounded.token);
  for(const value of [1,1000000]){const raw=makeRaw(value,true);start(q,++id,raw);assert.equal((await result(q)).status,200);assert.equal(rawSeen,raw);}
  const capped=store.createKey({name:'cap-enforcement',outputCap:4}),c=new Peer(config.origin);peers.push(c);await c.auth(capped.token);const beforeCap=calls;
  start(c,++id,makeRaw(5,true));assert.equal((await result(c)).status,429);assert.equal(calls,beforeCap);assert.equal(store.used(capped.key).total,0);
  const unlimited=store.createKey({name:'upstream-validation'}),p=new Peer(config.origin);peers.push(p);await p.auth(unlimited.token);
  reject=true;const raw=makeRaw(1000000,true);start(p,++id,raw,'/v1internal:streamGenerateContent');let r=await result(p);assert.equal(r.status,400);assert.match(r.body,/Upstream request rejected/);assert.doesNotMatch(r.body,/CANARY/);assert.equal(rawSeen,raw);assert.equal(store.used(unlimited.key).total,0);assert.equal(reservations(),0);
  reject=false;missingUsage=true;start(p,++id,raw);r=await result(p);assert.equal(r.status,200);assert.equal(store.used(unlimited.key).output,1000000);assert.equal(store.used(unlimited.key).input,Buffer.byteLength(raw)+1024);assert.equal(reservations(),0);
 }finally{await Promise.all(peers.map(p=>p.stop()));await transport.close();await close(server);await close(upstream);store.close();rmSync(dir,{recursive:true,force:true});}
});
