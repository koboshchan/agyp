import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer,type Server} from 'node:http';
import {once} from 'node:events';
import {createHmac} from 'node:crypto';
import WebSocket from 'ws';
import {Store,type Key} from '../server/store.js';
import {createApp} from '../server/app.js';
import {attachWebSocket} from '../server/ws.js';
import {displayQuota,mapQuotaDisplay,type quotaDisplayAction} from '../server/quota-display.js';
// Descriptor-derived synthetic fixtures, NOT captured traffic or an executed agy
// parser. These tests execute our HTTP+WSS adapters against a loopback fake only.
const fixtures=JSON.parse(readFileSync(new URL('./fixtures/quota-display.json',import.meta.url),'utf8'));
type Action=NonNullable<ReturnType<typeof quotaDisplayAction>>;
const actions:Action[]=['retrieveUserQuotaSummary','retrieveUserQuota','fetchAvailableModels'];
async function listen(s:Server){await new Promise<void>(r=>s.listen(0,'127.0.0.1',r));return 'http://127.0.0.1:'+(s.address() as any).port;}
async function close(s:Server){s.closeAllConnections();await new Promise<void>(r=>s.close(()=>r()));}
class Peer{
 ws:WebSocket;queue:any[]=[];wake?:()=>void;n=0;
 constructor(origin:string){this.ws=new WebSocket(origin.replace('http','ws')+'/transport','agyp.v1');this.ws.on('message',b=>{this.queue.push(JSON.parse(b.toString()));this.wake?.();});this.ws.on('error',()=>{});}
 async next(){if(!this.queue.length)await Promise.race([new Promise<void>(r=>this.wake=r),new Promise<void>((_,reject)=>{const t=setTimeout(()=>reject(new Error('frame timeout')),5000);t.unref();})]);this.wake=undefined;return this.queue.shift();}
 async auth(token:string){const c=await this.next();this.ws.send(JSON.stringify({type:'auth',keyId:token.slice(5,21),proof:createHmac('sha256',token).update('agyp-ws-v1\n'+c.salt+'\n'+c.nonce).digest('hex')}));assert.equal((await this.next()).type,'ready');}
 async request(path:string){const id=(++this.n).toString(16).padStart(32,'0');for(const f of [{type:'start',id,method:'POST',path,headers:{'content-type':'application/json'},deadline:Date.now()+10000},{type:'data',id,data:Buffer.from('{}').toString('base64')},{type:'end',id}])this.ws.send(JSON.stringify(f));const h=await this.next();assert.equal(h.type,'headers');let body='';for(;;){const f=await this.next();assert.equal(f.id,id);if(f.type==='end')return {status:h.status,body:JSON.parse(body)};assert.equal(f.type,'data');body+=Buffer.from(f.data,'base64').toString();}}
 async stop(){if(this.ws.readyState===WebSocket.CLOSED)return;const done=once(this.ws,'close');this.ws.terminate();await done;}
}
test('all three quota JSON paths share REST/WSS mapping for own fresh/partial/exhausted/reset/never/unlimited keys without changing pool or accounting',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-display-transport-')),store=new Store(dir);let calls=0;
 const upstream=createServer(async(req,res)=>{calls++;assert.equal(req.headers.authorization,'Bearer fake-access');for await(const _ of req){}const action=req.url?.split(':')[1]?.split('?')[0]!;assert(actions.includes(action as Action));res.setHeader('content-type','application/json');res.setHeader('x-provider-account','pool@example.invalid');res.end(JSON.stringify(fixtures[action]));});
 const config={origin:'',upstream:await listen(upstream),clientId:'',clientSecret:'',secure:false},{app,pool}=createApp(store,config),server=createServer(app),transport=attachWebSocket(server,store,pool);config.origin=await listen(server);
 store.putAccount({id:'a',email:'pool@example.invalid',refresh_token:'fake-refresh',access_token:'fake-access',token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets:[],cooldowns:{},denied:{},updated:Date.now()});
 const beforePool=store.accounts(),peers:Peer[]=[];let expectedCalls=0;
 const record=(key:Key)=>{const id=store.reserve(key,'gemini',0,0);store.finish(id,{input:20,output:10,cached:5,total:30},200);};
 try{
  const cases=[{name:'unlimited'},...['never','daily','weekly','monthly'].map(period=>({name:period,period:period as 'never'|'daily'|'weekly'|'monthly',allowance:100,inputCap:40,outputCap:80}))];
  for(const spec of cases){
   const k=store.createKey(spec),token=store.session(k.key).token,peer=new Peer(config.origin);peers.push(peer);await peer.auth(k.token);
   for(const state of ['fresh','partial','exhausted','reset']){
    if(state==='partial')record(k.key);
    if(state==='exhausted')record(k.key);
    if(state==='reset'&&k.key.period!=='never')store.db.prepare('UPDATE usage SET time=0 WHERE key_id=?').run(k.key.id);
    const before={...store.used(k.key)},q=displayQuota(store,k.key);
    if(spec.name!=='unlimited')assert.equal(q.fraction,state==='fresh'||state==='reset'&&spec.name!=='never'?1:state==='partial'?0.5:0);
    for(const action of actions){
     const path='/v1internal:'+action+'?alt=json',expected=mapQuotaDisplay(action,fixtures[action],q);
     const res=await fetch(config.origin+path,{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:'{}'});assert.equal(res.status,200);assert.equal(res.headers.get('x-provider-account'),null);assert.deepEqual(await res.json(),expected);
     const ws=await peer.request(path);assert.equal(ws.status,200);assert.deepEqual(ws.body,expected);expectedCalls+=2;
     assert.doesNotMatch(JSON.stringify(ws.body),/@|2099|123456/);
     assert.deepEqual({...store.used(k.key)},before);
    }
   }
  }
  assert.equal(calls,expectedCalls);assert.deepEqual(store.accounts(),beforePool);
  assert.equal((store.db.prepare('SELECT COUNT(*) n FROM reservations').get() as any).n,0);
 }finally{await Promise.all(peers.map(p=>p.stop()));await transport.close();await close(server);await close(upstream);store.close();rmSync(dir,{recursive:true,force:true});}
});
test('malformed/oversized display controls fail closed without provider identities, success headers, or invented usage',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-display-invalid-')),store=new Store(dir);let mode='invalid';
 const upstream=createServer(async(req,res)=>{for await(const _ of req){}res.setHeader('x-provider-account','pool@example.invalid');if(mode==='forbidden')res.statusCode=403;res.end(mode==='forbidden'?'{"error":{"message":"pool@example.invalid"}}':mode==='invalid'?'{"email":"pool@example.invalid"}':mode==='json'?'not json pool@example.invalid':'x'.repeat(8_388_609));});
 const config={origin:'',upstream:await listen(upstream),clientId:'',clientSecret:'',secure:false},{app}=createApp(store,config),server=createServer(app);config.origin=await listen(server);
 store.putAccount({id:'a',email:'pool@example.invalid',refresh_token:'fake-refresh',access_token:'fake',token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets:[],cooldowns:{},denied:{},updated:Date.now()});
 const k=store.createKey({name:'capped',allowance:0}),token=store.session(k.key).token;
 try{
  for(mode of ['invalid','json','oversized','forbidden'])for(const action of actions){const res=await fetch(config.origin+'/v1internal:'+action,{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:'{}'});assert.equal(res.status,mode==='forbidden'?403:502);assert.equal(res.headers.get('x-provider-account'),null);assert.doesNotMatch(await res.text(),/@|pool|fake/);}
  assert.deepEqual({...store.used(k.key)},{input:0,output:0,total:0});assert.equal((store.db.prepare('SELECT COUNT(*) n FROM reservations').get() as any).n,0);
 }finally{await close(server);await close(upstream);store.close();rmSync(dir,{recursive:true,force:true});}
});
