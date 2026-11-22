import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer,type Server} from 'node:http';
import {createHmac} from 'node:crypto';
import {Store,type Key} from '../server/store.js';
import {createApp} from '../server/app.js';
async function listen(s:Server){await new Promise<void>(r=>s.listen(0,'127.0.0.1',r));return 'http://127.0.0.1:'+(s.address() as any).port;}
async function close(s:Server){s.closeAllConnections();await new Promise<void>(r=>s.close(()=>r()));}
test('single-port HTTP handshake RBAC CSRF replay exact proxy rotation streaming and allowance',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-')),store=new Store(dir);let calls:any[]=[],mode='ok';
 const upstream=createServer(async(req,res)=>{let body='';for await(const c of req)body+=c;
 calls.push({url:req.url,auth:req.headers.authorization,body,headers:req.headers});
 if(req.url?.includes('retrieveUserQuota')){res.setHeader('content-type','application/json');res.end(JSON.stringify({groups:[{displayName:'Gemini Models',buckets:[{remainingFraction:1,bucketId:'gemini'}]}]}));return;}
 if(mode==='rotate'&&req.headers.authorization==='Bearer google-a'){res.writeHead(429);res.end('RESOURCE_EXHAUSTED');return;}
 res.setHeader('content-type','text/event-stream');res.setHeader('x-test-fidelity','yes');
 res.write('data: {"response":{"text":"hello"}}\n\n');res.end('data: {"response":{"usageMetadata":{"promptTokenCount":12,"candidatesTokenCount":4,"cachedContentTokenCount":3,"totalTokenCount":16}}}\n\ndata: [DONE]\n\n');
 });
 const up=await listen(upstream);let origin='';const config={origin:'',upstream:up,clientId:'',clientSecret:'',secure:false};const {app,pool}=createApp(store,config);const server=createServer(app);origin=await listen(server);config.origin=origin;
 const call=(path:string,options:any={})=>fetch(origin+path,options);
 async function login(token:string,client='cli'){
 const keyId=token.slice(5,21),c=await (await call('/auth/challenge',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({keyId})})).json() as any;
 const payload={keyId,nonce:c.nonce,proof:createHmac('sha256',token).update(c.nonce).digest('hex'),client};
 const r=await call('/auth/verify',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
 return {r,data:await r.json() as any,payload};
 }
 try{
 assert.equal((await call('/api/me')).status,401);assert.equal((await call('/api/me',{headers:{authorization:'Bearer '+store.adminToken}})).status,401);
 const admin=await login(store.adminToken);assert.equal(admin.r.status,200);assert(!JSON.stringify(admin.data).includes(store.adminToken));
 assert.equal((await call('/auth/verify',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(admin.payload)})).status,401);
 const ah={authorization:'Bearer '+admin.data.token,'content-type':'application/json'};
 const created=await call('/api/keys',{method:'POST',headers:ah,body:JSON.stringify({name:'normal',allowance:10000})});assert.equal(created.status,201);const user=await created.json() as any;
 const normal=await login(user.token),nh={authorization:'Bearer '+normal.data.token,'content-type':'application/json'};
 assert.equal((await call('/api/accounts',{headers:nh})).status,403);assert.equal((await call('/api/keys',{headers:nh})).status,403);
 const list=await (await call('/api/keys',{headers:ah})).text();assert(!list.includes(user.token));assert(!list.includes(store.adminToken));
 const web=await login(store.adminToken,'web'),cookie=web.r.headers.get('set-cookie')!.split(';')[0];assert(web.r.headers.get('set-cookie')?.includes('HttpOnly'));assert(!web.data.token);
 assert.equal((await call('/api/keys',{method:'POST',headers:{cookie,'content-type':'application/json',origin},body:'{"name":"CSRF"}'})).status,403);
 assert.equal((await call('/api/keys',{method:'POST',headers:{cookie,'content-type':'application/json',origin,'x-csrf-token':web.data.csrf},body:'{"name":"CSRF"}'})).status,201);
 assert.equal((await call('/auth/challenge',{method:'POST',headers:{origin:'https://evil.test','content-type':'application/json'},body:JSON.stringify({keyId:user.key.id})})).status,403);
 for(const id of ['a','b'])store.putAccount({id,email:id+'@example.com',refresh_token:'GOOGLE-REFRESH',access_token:'google-'+id,token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets:[{family:'argon',label:'Argon',remaining:1,reset:0}],cooldowns:{},denied:{},updated:Date.now()});
 mode='rotate';
 const reqBody=JSON.stringify({model:'gemini-4-argon-trial',request:{contents:[{parts:[{text:'test'}]}],generationConfig:{maxOutputTokens:20}}});
 const proxied=await call('/v1internal:streamGenerateContent?alt=sse',{method:'POST',headers:{...nh,'x-test-client':'kept'},body:reqBody});
 assert.equal(proxied.status,200);assert.equal(proxied.headers.get('x-test-fidelity'),'yes');assert((await proxied.text()).includes('[DONE]'));
 assert.equal(calls.length,2);for(const c of calls){assert.equal(c.body,reqBody);assert.equal(c.url,'/v1internal:streamGenerateContent?alt=sse');assert.equal(c.headers['x-test-client'],'kept');assert(!c.auth.includes('agyp_'));}
 const stats=await(await call('/api/stats',{headers:nh})).json() as any;assert.equal(stats.models[0].input,12);assert.equal(stats.models[0].output,4);assert.equal(stats.models[0].cached,3);
 const ownMe=await(await call('/api/me',{headers:nh})).json() as any;assert.equal(ownMe.key.used.total,16);
 const accounts=await(await call('/api/accounts',{headers:ah})).text();assert(!accounts.includes('GOOGLE-REFRESH'));assert(!accounts.includes('google-a'));
 const small=store.createKey({name:'tiny',allowance:1}),sm=await login(small.token);assert.equal((await call('/v1internal:generateContent',{method:'POST',headers:{authorization:'Bearer '+sm.data.token,'content-type':'application/json'},body:reqBody})).status,429);
 // Mixed envelopes cannot reduce the reservation below the forwarded generation limit.
 const before=calls.length;
 for(const b of [
 {model:'gemini-4-argon-trial',generationConfig:{maxOutputTokens:1},request:{generationConfig:{candidateCount:1}}},
 {model:'gemini-4-argon-trial',request:{generation_config:{max_output_tokens:1}}},
 {model:'gemini-4-argon-trial',request:{generationConfig:{max_output_tokens:1}}},
 ])assert.equal((await call('/v1internal:generateContent',{method:'POST',headers:nh,body:JSON.stringify(b)})).status,400);
 assert.equal(calls.length,before);
 const unbounded=store.createKey({name:'default-bound'}),un=await login(unbounded.token);
 const defaulted=await call('/v1internal:generateContent',{method:'POST',headers:{authorization:'Bearer '+un.data.token,'content-type':'application/json'},body:JSON.stringify({model:'gemini-4-argon-trial',request:{contents:[]}})});assert.equal(defaulted.status,200);await defaulted.text();
 assert.equal(JSON.parse(calls.at(-1).body).request.generationConfig.maxOutputTokens,65536);
 store.revoke(user.key.id);assert.equal((await call('/api/me',{headers:nh})).status,401);
 }finally{await close(server);await close(upstream);store.close();rmSync(dir,{recursive:true,force:true});}
});
test('handshake rate limit',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-')),s=new Store(dir),config={origin:'http://localhost',upstream:'http://localhost',clientId:'',clientSecret:'',secure:false,loginLimit:2};const {app}=createApp(s,config),server=createServer(app),base=await listen(server);try{
 for(let n=0;n<2;n++)assert.equal((await fetch(base+'/auth/challenge',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({keyId:'f'.repeat(16)})})).status,200);
 assert.equal((await fetch(base+'/auth/challenge',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({keyId:'f'.repeat(16)})})).status,429);
 }finally{await close(server);s.close();rmSync(dir,{recursive:true,force:true});}
});
