import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer,type Server} from 'node:http';
import {Store} from '../server/store.js';
import {createApp} from '../server/app.js';
import {allowedProxy,boundedControl} from '../server/proxy.js';
const matrix=JSON.parse(readFileSync(new URL('./fixtures/cloudcode-paths.json',import.meta.url),'utf8')) as {method:string;path:string;allowed:boolean;bounded:boolean}[];
async function listen(s:Server){await new Promise<void>(r=>s.listen(0,'127.0.0.1',r));return 'http://127.0.0.1:'+(s.address() as any).port;}
async function close(s:Server){s.closeAllConnections();await new Promise<void>(r=>s.close(()=>r()));}
test('switcher namespace method matrix is strict, canonical and bounded-control classified',()=>{
 for(const c of matrix){assert.equal(allowedProxy(c.method,c.path),c.allowed,c.method+' '+c.path);if(c.allowed&&!c.path.includes(':generateContent')&&!c.path.includes(':streamGenerateContent')&&!c.path.includes('/v1beta/models/'))assert.equal(boundedControl(c.method,c.path),c.bounded,c.path);}
});
test('REST full Cloud Code compatibility preserves methods, path/query, request and response bytes; bounded unknown cannot bypass accounting',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-compat-')),store=new Store(dir);let calls=0,seen:any;
 const raw='{ "metadata":{"ideType":"ANTIGRAVITY"}, "model":"gemini-flash", "request":{"contents":[],"generationConfig":{"maxOutputTokens":10}}, "n":1e+05 }';
 const reply='{ "cloudaicompanionProject":"fixture-project", "operation":{"name":"fixture-op"}, "unknownField":true }';
 const upstream=createServer(async(req,res)=>{calls++;let body='';for await(const c of req)body+=c;seen={method:req.method,path:req.url,body};assert.equal(req.headers.authorization,'Bearer fixture-access');for(const h of ['cookie','x-goog-api-key','x-client-secret','proxy-authorization'])assert.equal(req.headers[h],undefined);res.setHeader('content-type','application/json');res.end(reply);});
 const config={origin:'',upstream:await listen(upstream),clientId:'',clientSecret:'',secure:false},{app}=createApp(store,config),server=createServer(app);config.origin=await listen(server);
 store.putAccount({id:'a',email:'fixture@example.invalid',refresh_token:'fake',access_token:'fixture-access',token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets:[],cooldowns:{},denied:{},updated:Date.now()});
 const un=store.createKey({name:'unlimited'}),bounded=store.createKey({name:'bounded',allowance:100000});const sessions=[store.session(un.key).token,store.session(bounded.key).token];
 const payload=(path:string)=>path.startsWith('/v1internal')?raw:'{ \"contents\":[],\"generationConfig\":{\"maxOutputTokens\":10},\"n\":1e+05 }';
 const request=(c:typeof matrix[number],token:string)=>fetch(config.origin+c.path,{method:c.method,headers:{authorization:'Bearer '+token,'content-type':'application/json','cookie':'evil','x-goog-api-key':'evil','x-client-secret':'evil'},body:['GET','HEAD'].includes(c.method)?undefined:payload(c.path)});
 try{
  const expectedCharge=(c:typeof matrix[number])=>c.method==='POST'&&/:(?:generateContent|streamGenerateContent)$/.test(c.path)?{input:Buffer.byteLength(payload(c.path))+1024,output:10}:{input:0,output:0};
  const checkCharge=(key:any,before:any,c:typeof matrix[number])=>{const charge=expectedCharge(c),after=store.used(key);assert.deepEqual({...after},{input:before.input+charge.input,output:before.output+charge.output,total:before.total+charge.input+charge.output},c.method+' '+c.path+' exact accounting');};
  for(const c of matrix.filter(c=>c.allowed)){
   const unBefore=store.used(un.key),boundedBefore=store.used(bounded.key);
   let before=calls;const res=await request(c,sessions[0]);assert.equal(res.status,200,c.method+' '+c.path);assert.equal(await res.text(),c.method==='HEAD'?'':reply);assert.equal(calls,before+1);assert.deepEqual(seen,{method:c.method,path:c.path,body:['GET','HEAD'].includes(c.method)?'':payload(c.path)});
   checkCharge(un.key,unBefore,c);
   // loadCodeAssist retains the old safe bounded-key bootstrap, tested separately.
   if(c.path==='/v1internal:loadCodeAssist')continue;
   before=calls;const boundedRes=await request(c,sessions[1]);assert.equal(boundedRes.status,c.bounded?200:422,c.method+' '+c.path);await boundedRes.text();assert.equal(calls,before+(c.bounded?1:0));if(c.bounded)checkCharge(bounded.key,boundedBefore,c);else assert.deepEqual(store.used(bounded.key),boundedBefore);
  }
  const exhausted=store.createKey({name:'exhausted',allowance:0}),exhaustedToken=store.session(exhausted.key).token;
  const beforeExhausted=calls;
  for(const [path,status] of [['/v1internal:newFutureAction',422],['/v1internal:generateContent',429],['/v1internal:fetchAvailableModels',200]] as const){const c={method:'POST',path,allowed:true,bounded:true},res=await request(c,exhaustedToken);assert.equal(res.status,status,path);await res.text();}
  assert.equal(calls,beforeExhausted+1);assert.deepEqual({...store.used(exhausted.key)},{input:0,output:0,total:0});
  const before=calls;
  for(const path of ['/v1internal:fetchAdminControls','/v1internal:updateCredentials','/v1internal:deleteAccount','/api/accounts','/oauth/token']){const res=await request({method:'POST',path,allowed:false,bounded:false},sessions[0]);assert([403,404].includes(res.status));await res.text();}
  const noauth=await fetch(config.origin+'/v1internal:onboardUser',{method:'POST',body:'{}'});assert.equal(noauth.status,401);assert.equal(calls,before);
  store.revoke(un.key.id);const revoked=await request({method:'POST',path:'/v1internal:onboardUser',allowed:true,bounded:false},sessions[0]);assert.equal(revoked.status,401);assert.equal(calls,before);
  assert.equal((store.db.prepare('SELECT COUNT(*) n FROM reservations').get() as any).n,0);
 }finally{await close(server);await close(upstream);store.close();rmSync(dir,{recursive:true,force:true});}
});
