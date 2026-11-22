import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer,type Server} from 'node:http';
import {once} from 'node:events';
import {createHmac} from 'node:crypto';
import WebSocket from 'ws';
import {Store,type Account} from '../server/store.js';
import {createApp} from '../server/app.js';
import {attachWebSocket} from '../server/ws.js';
import {deniedLimitedModel,enforceLimitedModel} from '../server/model-policy.js';
async function listen(s:Server){await new Promise<void>(r=>s.listen(0,'127.0.0.1',r));return 'http://127.0.0.1:'+(s.address() as any).port;}
async function close(s:Server){s.closeAllConnections();await new Promise<void>(r=>s.close(()=>r()));}
class Peer{
 ws:WebSocket;queue:any[]=[];wake?:()=>void;n=0;
 constructor(origin:string){this.ws=new WebSocket(origin.replace('http','ws')+'/transport','agyp.v1');this.ws.on('message',b=>{this.queue.push(JSON.parse(b.toString()));this.wake?.();});this.ws.on('error',()=>{});}
 async next(){if(!this.queue.length)await Promise.race([new Promise<void>(r=>this.wake=r),new Promise<void>((_,reject)=>{const t=setTimeout(()=>reject(new Error('frame timeout')),5000);t.unref();})]);this.wake=undefined;return this.queue.shift();}
 async auth(token:string){const c=await this.next();this.ws.send(JSON.stringify({type:'auth',keyId:token.slice(5,21),proof:createHmac('sha256',token).update('agyp-ws-v1\n'+c.salt+'\n'+c.nonce).digest('hex')}));assert.equal((await this.next()).type,'ready');}
 async request(path:string,body:string='{}'){const id=(++this.n).toString(16).padStart(32,'0');for(const f of [{type:'start',id,method:'POST',path,headers:{'content-type':'application/json'},deadline:Date.now()+10000},{type:'data',id,data:Buffer.from(body).toString('base64')},{type:'end',id}])this.ws.send(JSON.stringify(f));const h=await this.next();assert.equal(h.type,'headers');let responseBody='';for(;;){const f=await this.next();assert.equal(f.id,id);if(f.type==='end')return {status:h.status,body:responseBody};assert.equal(f.type,'data');responseBody+=Buffer.from(f.data,'base64').toString();}}
 async stop(){if(this.ws.readyState===WebSocket.CLOSED)return;const done=once(this.ws,'close');this.ws.terminate();await done;}
}

const blocked=['gemini-4-argon','gemini-4-argon-high','gemini-4-argon-trial','gemini-4-argon-whatever','gemini-4-argonized','claude','claude-opus-5-5','claudeUNKNOWN','gpt','gpt-oss-120b','gpt-future'];
const allowed=['gemini-4-hydrogen-high','gemini-4-helium','gemini-flash','future-unknown','argon','carbon','hydrogen','helium','pro','ultra','flash','x-claude','x-gpt','not-gemini-4-argon','gemini-4-argo','models/models/gpt'];
test('literal canonical prefix denylist includes all suffixes, normalizes routing case and only one models/ prefix, never grants by family',()=>{
 for(const id of blocked)for(const value of [id,id.toUpperCase(),'models/'+id,'  MODELS/'+id.toUpperCase()+'  '])assert.equal(deniedLimitedModel(value),true,value);
 for(const id of allowed)assert.equal(deniedLimitedModel(id),false,id);
 for(const body of [{model:'gpt'},{model:'gemini-flash',request:{model:'claude'}},{request:{request:{model:'gemini-4-argon-trial'}}}])assert.throws(()=>enforceLimitedModel('/v1internal:generateContent',body),{status:403,message:'unsupported for limited key'});
 assert.throws(()=>enforceLimitedModel('/v1/models/gemini-flash:generateContent?model=gpt',{}),{status:403});
 assert.throws(()=>enforceLimitedModel('/v1internal:generateContent?model=gemini-flash&model=gpt',{}),{status:403});
 assert.throws(()=>enforceLimitedModel('/v1internal:generateContent',{model:'unknown-a',request:{model:'unknown-b'}}),{status:400});
 enforceLimitedModel('/v1internal:generateContent',{model:'unknown',request:{contents:[{parts:[{text:'gpt',functionCall:{args:{model:'gpt'}}}]}],metadata:{model:'gpt'}}});
});
async function setup(){
 const dir=mkdtempSync(join(tmpdir(),'agyp-policy-')),store=new Store(dir);const calls:{body:string;path:string}[]=[];
 const upstream=createServer(async(req,res)=>{let body='';for await(const c of req)body+=c;calls.push({body,path:req.url!});
  const answer={usageMetadata:{promptTokenCount:2,candidatesTokenCount:1,totalTokenCount:3},text:'complete'};
  if(req.url?.includes('streamGenerateContent')){res.setHeader('content-type','text/event-stream');res.end('data: '+JSON.stringify(answer)+'\n\ndata: [DONE]\n\n');}else{res.setHeader('content-type','application/json');res.end(JSON.stringify(answer));}
 });
 const config={origin:'',upstream:await listen(upstream),clientId:'',clientSecret:'',secure:false},{app,pool}=createApp(store,config),server=createServer(app),transport=attachWebSocket(server,store,pool);config.origin=await listen(server);
 const account:Account={id:'fake',email:'fake@example.invalid',refresh_token:'fake-refresh',access_token:'fake-access',token_expiry:0,status:'ready',shared:true,blocked:false,buckets:['gemini','argon','claude','gpt'].map(family=>({family:family as any,label:family,remaining:1,reset:0})),cooldowns:{},denied:{},updated:Date.now()};store.putAccount(account);
 const spy={route:0,access:0,refresh:0,reserve:0,finish:0};
 const route=pool.route.bind(pool);pool.route=(...args)=>{spy.route++;return route(...args);};
 const access=pool.access.bind(pool);pool.access=async(...args)=>{spy.access++;return access(...args);};
 (pool as any).oauth=()=>({setCredentials(){},async refreshAccessToken(){spy.refresh++;return {credentials:{access_token:'fake-access',expiry_date:Date.now()+1e6}};}});
 const reserve=store.reserve.bind(store);store.reserve=(...args)=>{spy.reserve++;return reserve(...args);};
 const finish=store.finish.bind(store);store.finish=(...args)=>{spy.finish++;return finish(...args);};
 const peers:Peer[]=[];
 const client=async(options:any)=>{const k=store.createKey({name:'test',...options}),token=store.session(k.key).token,p=new Peer(config.origin);peers.push(p);await p.auth(k.token);return {key:k.key,p,async rest(path:string,body:string){const r=await fetch(config.origin+path,{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body});return {status:r.status,body:await r.text()};}};};
 return {store,pool,spy,calls,client,async close(){await Promise.all(peers.map(p=>p.stop()));await transport.close();await close(server);await close(upstream);store.close();rmSync(dir,{recursive:true,force:true});}};
}
test('every limited cap and period denies prefixes on REST/WSS fresh partial exhausted before selection refresh reserve or charge; nested envelopes cannot bypass',async()=>{
 const h=await setup();try{
  for(const period of ['never','daily','weekly','monthly'])for(const cap of ['allowance','inputCap','outputCap']){
   const c=await h.client({period,[cap]:10});
   for(const state of ['fresh','partial','exhausted']){
    if(state!=='fresh'){const id=h.store.reserve(c.key,'seed',0,0);h.store.finish(id,{input:state==='partial'?1:20,output:state==='partial'?1:20,cached:0,total:state==='partial'?2:40},200);}
    const before={...h.spy},used={...h.store.used(c.key)},rows=(h.store.db.prepare('SELECT COUNT(*) n FROM usage').get() as any).n;
    const inputs=blocked.map(model=>({path:'/v1internal:streamGenerateContent',body:JSON.stringify({model:'models/'+model.toUpperCase(),request:{contents:[]}})}));
    inputs.push({path:'/v1/models/gpt-oss:generateContent',body:'{}'},
     {path:'/v1internal:generateContent',body:'{"model":"gemini-flash","request":{"model":"gpt","contents":[]}}'},
     {path:'/v1internal:generateContent?model=gemini-flash&model=claude',body:'{"model":"gemini-flash","request":{}}'},
     {path:'/v1internal:generateContent',body:'{"model":"gemini-flash","request":{"request":{"model":"gemini-4-argon"}}}'},
     {path:'/v1internal:countTokens',body:'{"model":"gpt","request":{}}'});
    for(const input of inputs)for(const r of [await c.rest(input.path,input.body),await c.p.request(input.path,input.body)]){assert.equal(r.status,403);assert.deepEqual(JSON.parse(r.body),{error:{message:'unsupported for limited key'}});}
    assert.deepEqual(h.spy,before);assert.deepEqual({...h.store.used(c.key)},used);assert.equal((h.store.db.prepare('SELECT COUNT(*) n FROM usage').get() as any).n,rows);assert.equal(h.calls.length,0);
   }
  }
 }finally{await h.close();}
});
test('allowed Gemini and unknown IDs preserve raw text/media JSON and SSE actual usage over REST/WSS; unlimited deny-prefix routing remains unchanged',async()=>{
 const h=await setup();try{
  for(const limited of [true,false]){
   const c=await h.client(limited?{allowance:100000}:{});
   for(const model of limited?allowed:[...blocked,...allowed])for(const stream of [true,false]){
    // A model string inside user/tool payload is not an inference selector.
    const body=JSON.stringify({model,request:{contents:[{parts:[{text:'gpt',inlineData:{mimeType:'image/png',data:'AAAA'}},{functionCall:{name:'tool',args:{model:'claude'}}}]}]}}),path='/v1internal:'+(stream?'streamGenerateContent':'generateContent');
    for(const r of [await c.rest(path,body),await c.p.request(path,body)]){assert.equal(r.status,200,model+' '+r.body);assert.match(r.body,/complete/);assert.equal(h.calls.at(-1)!.body,!limited&&model==='gemini-4-argon-trial'?body.replace(model,'gemini-4-argon-low'):body);}
   }
   assert.equal(h.store.used(c.key).total,(limited?allowed.length:blocked.length+allowed.length)*2*2*3);
  }
  // Existing exhaustion gate still rejects an otherwise allowed unknown ID.
  const c=await h.client({inputCap:0});const before=h.calls.length;
  const r=await c.rest('/v1internal:generateContent','{"model":"future-unknown","request":{}}');assert.equal(r.status,429);assert.equal(h.calls.length,before);
 }finally{await h.close();}
});
