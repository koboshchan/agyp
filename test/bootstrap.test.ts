import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer,type Server} from 'node:http';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store} from '../server/store.js';
import {createApp} from '../server/app.js';
import {allowedProxy} from '../server/proxy.js';
import {allowedBootstrap} from '../server/bootstrap.js';
async function listen(s:Server){await new Promise<void>(r=>s.listen(0,'127.0.0.1',r));return 'http://127.0.0.1:'+(s.address() as any).port;}
async function close(s:Server){s.closeAllConnections();await new Promise<void>(r=>s.close(()=>r()));}
test('loadCodeAssist is a separate normal-key eligibility capability, fixed request and sanitized response',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-bootstrap-')),store=new Store(dir);let calls=0;
 const upstream=createServer(async(req,res)=>{calls++;assert.equal(req.method,'POST');assert.equal(req.url,'/v1internal:loadCodeAssist');assert.equal(req.headers.authorization,'Bearer server-owned');for(const h of ['cookie','x-goog-api-key','x-client-secret','proxy-authorization','x-forwarded-for'])assert.equal(req.headers[h],undefined);let raw='';for await(const c of req)raw+=c;assert.equal(raw,'{"metadata":{"ideType":"ANTIGRAVITY"}}');res.setHeader('set-cookie','secret-cookie');res.end(JSON.stringify({currentTier:{id:'premium-tier',name:'Pro',description:'private',privacyNotice:{noticeText:'private'},upgradeSubscriptionUri:'https://private.invalid'},allowedTiers:[{id:'free-tier',name:'Free',isDefault:true,description:'private'}],paidTier:{id:'premium-tier',name:'Pro',availableCredits:[{creditType:'private'}]},cloudaicompanionProject:'private-project',gcpManaged:true,email:'private@example.invalid',token:'private-token'}));});
 const config={origin:'',upstream:await listen(upstream),clientId:'',clientSecret:'',secure:false},{app}=createApp(store,config),server=createServer(app);config.origin=await listen(server);
 const normal=store.createKey({name:'normal',allowance:10000}),session=store.session(normal.key);
 const request=(path:string,body:any={metadata:{ideType:'ANTIGRAVITY'}},method='POST',token=session.token)=>fetch(config.origin+path,{method,headers:{authorization:'Bearer '+token,'content-type':'application/json','cookie':'evil','x-goog-api-key':'evil','x-client-secret':'evil'},body:method==='GET'?undefined:JSON.stringify(body)});
 try{
  store.putAccount({id:'a',email:'owner@example.invalid',refresh_token:'fake',access_token:'server-owned',token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets:[],cooldowns:{},denied:{},updated:Date.now()});
  assert.equal(allowedProxy('POST','/v1internal:loadCodeAssist'),true);
  let res=await request('/v1internal:loadCodeAssist');assert.equal(res.status,200);assert.equal(res.headers.get('set-cookie'),null);assert.deepEqual(await res.json(),{currentTier:{id:'premium-tier',name:'Pro'},allowedTiers:[{id:'free-tier',name:'Free',isDefault:true}],paidTier:{id:'premium-tier',name:'Pro'}});assert.equal(calls,1);assert.equal(store.used(normal.key).total,0);
  for(const body of [{metadata:{ideType:'ANTIGRAVITY',project:'x'}},{metadata:{ideType:'OTHER'}},{metadata:{ideType:'ANTIGRAVITY'},project:'x'},{metadata:{ideType:'ANTIGRAVITY'},url:'http://evil.invalid'},{}]){res=await request('/v1internal:loadCodeAssist',body);assert.equal(res.status,400);}
  res=await request('/v1internal:loadCodeAssist',{metadata:{ideType:'ANTIGRAVITY'},padding:'x'.repeat(1024)});assert.equal(res.status,413);
  for(const path of ['/v1internal:onboardUser','/v1internal:loadCodeAssist/extra','/api/keys']){res=await request(path);assert([403,404,422].includes(res.status));}
  assert.equal(calls,1);
  for(const path of ['//evil.invalid/v1internal:loadCodeAssist','https://evil.invalid/v1internal:loadCodeAssist','/v1internal:loadCodeAssist?x=1','/%76%31internal:loadCodeAssist','/v1internal:loadCodeAssist\\x'])assert.equal(allowedBootstrap('POST',path),false);
  store.revoke(normal.key.id);res=await request('/v1internal:loadCodeAssist');assert.equal(res.status,401);assert.equal(calls,1);
 }finally{await close(server);await close(upstream);store.close();rmSync(dir,{recursive:true,force:true});}
});
test('canceling eligibility releases slots even when the shared OAuth refresh hangs',async()=>{
 const {PassThrough}=await import('node:stream');const {createBootstrap}=await import('../server/bootstrap.js');
 const dir=mkdtempSync(join(tmpdir(),'agyp-bootstrap-abort-')),store=new Store(dir);const {pool}=createApp(store,{origin:'',upstream:'http://127.0.0.1:1',clientId:'',clientSecret:'',secure:false});
 store.putAccount({id:'a',email:'owner@example.invalid',refresh_token:'fake',access_token:'',token_expiry:0,status:'ready',shared:false,blocked:false,buckets:[],cooldowns:{},denied:{},updated:Date.now()});
 const key=store.createKey({name:'normal'}).key;const rejectors:Array<(e:Error)=>void>=[];pool.access=()=>new Promise<string>((_resolve,reject)=>rejectors.push(reject));const bootstrap=createBootstrap(store,pool);
 try{
  for(let i=0;i<10;i++){
   const res=new PassThrough();const req={method:'POST',originalUrl:'/v1internal:loadCodeAssist',body:Buffer.from('{"metadata":{"ideType":"ANTIGRAVITY"}}')};
   const pending=bootstrap(req as any,res as any,key).then(()=>assert.fail('expected cancellation'),err=>assert.match(err.message,/canceled/));
   res.emit('close');await pending;assert.equal(res.listenerCount('close'),0);
  }
  assert.equal(rejectors.length,10);for(const reject of rejectors)reject(new Error('late refresh failure'));await new Promise<void>(r=>setImmediate(r));
 }finally{store.close();rmSync(dir,{recursive:true,force:true});}
});
