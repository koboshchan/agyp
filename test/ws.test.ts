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
