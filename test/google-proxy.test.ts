import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer,type Server} from 'node:http';
import {Store,type Account} from '../server/store.js';
import {createApp} from '../server/app.js';
import {repairSignatures,rewriteModel,rewriteURLModel,signatureError} from '../server/replay.js';
async function listen(s:Server){await new Promise<void>(r=>s.listen(0,'127.0.0.1',r));return 'http://127.0.0.1:'+(s.address() as any).port;}
async function close(s:Server){s.closeAllConnections();await new Promise<void>(r=>s.close(()=>r()));}
const account=(id:string):Account=>({id,email:id+'@example.invalid',refresh_token:'fake-refresh',access_token:'old-'+id,token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets:[{family:'gemini',label:'Gemini',remaining:1,reset:0},{family:'claude',label:'Claude',remaining:1,reset:0}],cooldowns:{},denied:{},updated:Date.now()});
test('surgical model rewrite leaves nested models, unicode, whitespace and numeric lexemes intact',()=>{
 const raw=Buffer.from('{ "nested":{"model":"unchanged"}, "m\\u006fdel" : "old", "n":1e+05,"text":"雪" }');
 assert.equal(rewriteModel(raw,'new').toString(),'{ "nested":{"model":"unchanged"}, "m\\u006fdel" : "new", "n":1e+05,"text":"雪" }');
 assert.equal(rewriteURLModel('/v1/models/old:generateContent?x=a%20b&model=old','new'),'/v1/models/new:generateContent?x=a%20b&model=new');
});
test('reactive sanitizer matches Go part rules, fallback and unchanged bytes',()=>{
 const raw=Buffer.from('{ "contents": [{"role":"model","parts":[{"thought":true,"text":"hidden"},{"functionCall":{},"thoughtSignature":"bad"},7]},{"parts":[{"thought":true}]}] }');
 const fixed=repairSignatures(raw);const o=JSON.parse(fixed.toString());assert.deepEqual(o.contents[0].parts,[{functionCall:{},thoughtSignature:'skip_thought_signature_validator'},7]);assert.deepEqual(o.contents[1].parts,[{text:''}]);assert.deepEqual(repairSignatures(fixed),fixed);
 const untouched=Buffer.from('{ "contents": [{"parts":[{"text":"ok"}]}] }');assert.equal(repairSignatures(untouched),untouched);
 assert(signatureError('thought_signature'));assert(!signatureError('arbitrary invalid argument'));
});
test('raw passthrough, forced refresh same account, reactive repair, family403 and allowance admission',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-google-')),store=new Store(dir);let mode='ok';const calls:{body:string;auth:string;ua:string}[]=[];
 const upstream=createServer(async(req,res)=>{let body='';for await(const c of req)body+=c;calls.push({body,auth:String(req.headers.authorization),ua:String(req.headers['user-agent'])});
  if(mode==='401'&&req.headers.authorization==='Bearer old-a'){res.writeHead(401).end('{}');return;}
  if(mode==='sig'&&!body.includes('skip_thought_signature_validator')){res.writeHead(400).end('{"error":{"message":"Corrupted thought signature"}}');return;}
  if(mode==='403'&&req.headers.authorization==='Bearer old-a'){res.writeHead(403).end('{"error":{"status":"RATE_LIMIT_EXCEEDED"}}');return;}
  if(mode==='server-error'){res.setHeader('x-account-secret','must-not-leak');res.writeHead(500).end('{"private":"must-not-leak"}');return;}
  if(mode==='forbid'){res.writeHead(403).end('{"private":"must-not-leak"}');return;}
  res.setHeader('content-type','application/json');res.end('{"usageMetadata":{"promptTokenCount":2,"candidatesTokenCount":1,"totalTokenCount":3},"text":"OK"}');
 });
 const config={origin:'',upstream:await listen(upstream),clientId:'',clientSecret:'',secure:false};const {app,pool}=createApp(store,config),server=createServer(app);config.origin=await listen(server);
 let refreshed=0;(pool as any).oauth=()=>({setCredentials(){},async refreshAccessToken(){refreshed++;return {credentials:{access_token:'renewed-a',expiry_date:Date.now()+1e6}};}});
 const key=store.createKey({name:'unlimited'}),session=store.session(key.key);
 const call=(body:string,token=session.token)=>fetch(config.origin+'/v1internal:generateContent',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json','user-agent':'client-unchanged'},body});
 try{
 store.putAccount(account('a'));store.putAccount(account('b'));
 const raw='{ "model":"gemini-flash", "request": {"contents":[{"parts":[{"text":"hi"}]}]}, "n":1e+05 }';
 let r=await call(raw);assert.equal(r.status,200);await r.text();assert.equal(calls.at(-1)?.body,raw);assert.equal(calls.at(-1)?.ua,'client-unchanged');
 const bounded=store.createKey({name:'bounded',allowance:10000}),bs=store.session(bounded.key);let before=calls.length;
 r=await call(raw,bs.token);assert.equal(r.status,200);await r.text();assert.equal(calls.length,before+1);assert.equal(store.used(bounded.key).total,3);
 mode='401';r=await call(raw);assert.equal(r.status,200);await r.text();assert.equal(refreshed,1);assert.deepEqual(calls.slice(-2).map(c=>c.auth),['Bearer old-a','Bearer renewed-a']);assert(calls.slice(-2).every(c=>c.body===raw));
 mode='sig';const sig=JSON.stringify({model:'gemini-flash',request:{contents:[{parts:[{functionCall:{name:'x'},thoughtSignature:'bad'}]}]}});before=calls.length;r=await call(sig);assert.equal(r.status,200);await r.text();assert.equal(calls.length,before+2);assert.equal(calls[before].body,sig);assert(calls.at(-1)?.body.includes('skip_thought_signature_validator'));
 const a=account('a');store.putAccount(a);mode='403';r=await call(raw);assert.equal(r.status,200);await r.text();assert(!store.accounts().find(a=>a.id==='a')!.blocked);assert(pool.eligible(store.accounts().find(a=>a.id==='a')!,'claude-x'));
 mode='server-error';r=await call(raw);assert.equal(r.status,500);assert.equal(r.headers.get('x-account-secret'),null);assert.equal(r.headers.get('x-agyp-upstream-model'),null);assert(!(await r.text()).includes('must-not-leak'));
 mode='forbid';r=await call(raw);assert.equal(r.status,403);assert(!(await r.text()).includes('must-not-leak'));
 }finally{await close(server);await close(upstream);store.close();rmSync(dir,{recursive:true,force:true});}
});
test('capped text and media stream to completion with concurrent actual overshoot and no estimated charges',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-actual-')),store=new Store(dir);let calls=0,mode='stream';
 let release!:()=>void;const gate=new Promise<void>(r=>release=r);
 const upstream=createServer(async(req,res)=>{
  for await(const _ of req){}calls++;
  if(mode==='stream'){
   await gate;res.setHeader('content-type','text/event-stream');
   const event='data: '+JSON.stringify({response:{text:'untruncated',usageMetadata:{promptTokenCount:4,candidatesTokenCount:6,cachedContentTokenCount:2,totalTokenCount:10}}})+'\n\n';
   res.write(event);res.write(event);res.end('data: [DONE]\n\n');
  }else{res.setHeader('content-type','application/json');res.end('{"text":"missing metadata"}');}
 });
 const config={origin:'',upstream:await listen(upstream),clientId:'',clientSecret:'',secure:false};
 const {app}=createApp(store,config),server=createServer(app);config.origin=await listen(server);store.putAccount(account('a'));
 const {key}=store.createKey({name:'tiny-media',allowance:1,inputCap:1,outputCap:1}),session=store.session(key);
 const call=(request:any,token=session.token)=>fetch(config.origin+'/v1internal:streamGenerateContent',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify({model:'gemini-flash',request})});
 try{
  const requests=[
   {contents:[{parts:[{text:'text without explicit output limit'}]}]},
   {contents:[{parts:[{inlineData:{mimeType:'image/png',data:'dGVzdA=='}},{fileData:{mimeType:'image/png',fileUri:'https://example.invalid/offline-only'}}]}],generationConfig:{maxOutputTokens:1000000,candidateCount:2,thinkingConfig:{thinkingBudget:1000000}}}
  ];
  const both=requests.map(b=>call(b));
  await new Promise<void>((resolve,reject)=>{let n=0;function check(){if(calls===2)return resolve();if(++n>200)return reject(new Error('fake upstream did not receive both concurrent requests'));setTimeout(check,5);}check();});
  assert.equal(store.used(key).total,0);release();
  for(const r of await Promise.all(both)){assert.equal(r.status,200);const body=await r.text();assert(body.endsWith('data: [DONE]\n\n'));assert.equal(body.split('untruncated').length-1,2);}
  assert.deepEqual({...store.used(key)},{input:8,output:12,total:20});
  assert.equal((await call(requests[0])).status,429);assert.equal(calls,2);
  const other=store.createKey({name:'missing',allowance:1}),otherSession=store.session(other.key);mode='missing';
  let r=await call(requests[1],otherSession.token);assert.equal(r.status,200);await r.text();assert.equal(store.used(other.key).total,0);
  r=await call(requests[0],otherSession.token);assert.equal(r.status,200);await r.text();assert.equal(store.used(other.key).total,0);
 }finally{release();await close(server);await close(upstream);store.close();rmSync(dir,{recursive:true,force:true});}
});
