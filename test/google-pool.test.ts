import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store,type Account} from '../server/store.js';
import {Pool,parseQuota,family,requiresUltra,UA} from '../server/pool.js';
import {detectVerification,safeVerificationURL} from '../server/google.js';

const account=(id:string,extra:Partial<Account>={}):Account=>({id,email:id+'@example.test',access_token:'old',refresh_token:'refresh',token_expiry:Date.now()+3600_000,status:'ready',shared:false,blocked:false,buckets:[],cooldowns:{},denied:{},updated:0,...extra});
const gemini=()=>parseQuota({groups:[{displayName:'Gemini',buckets:[{bucketId:'gemini-burst',remainingFraction:1}]}]});
const pro=()=>parseQuota({groups:[{displayName:'Argon',buckets:[{bucketId:'gemini-argon-wtu-weekly',remainingFraction:1}]}]});
function setup(){
 const dir=mkdtempSync(join(tmpdir(),'agyp-google-pool-')),store=new Store(dir),pool=new Pool(store,'https://upstream.invalid','id','secret');
 return {store,pool,close(){store.close();rmSync(dir,{recursive:true,force:true});}};
}
function fakeOAuth(pool:Pool,refresh:()=>Promise<any>){pool.oauth=(()=>({setCredentials(){},async refreshAccessToken(){return {credentials:await refresh()};}})) as any;}
function deferred<T>(){let resolve!:(value:T)=>void;const promise=new Promise<T>(r=>resolve=r);return {promise,resolve};}
const verify=(url='https://accounts.google.com/verify')=>JSON.stringify({error:{details:[{'@type':'type.googleapis.com/google.rpc.ErrorInfo',reason:'VALIDATION_REQUIRED',metadata:{validation_url:url}}]}});

test('verification URL allowlist rejects credentials ports fragments and suffix tricks',()=>{
 for(const u of ['http://google.com','https://google.com.evil.test/','https://evilgoogle.com/','https://google.com:444/','https://user@google.com/','https://google.com/#','https://google.com/#verify','javascript:alert(1)','https://google.com/'+ 'x'.repeat(8193)])assert.equal(safeVerificationURL(u),'',u);
 for(const u of ['https://accounts.google.com/verify?x=1','https://google.com/','https://antigravity.google/'])assert.equal(safeVerificationURL(u),u);
 assert.equal(detectVerification(verify())?.url,'https://accounts.google.com/verify');
 assert.equal(detectVerification(verify('https://evil.test'))?.url,'');
 assert.equal(detectVerification('invalid'),undefined);
 assert.equal(detectVerification(JSON.stringify({message:'VALIDATION_REQUIRED https://google.com'})),undefined);
 assert.equal(detectVerification(' '.repeat(1024*1024+1)),undefined);
});
test('eligibility context skips irrelevant tier notices but not actual error requirements',()=>{
 const notice={reasonCode:'VERIFICATION_REQUIRED',verificationUrl:'https://accounts.google.com/verify'};
 for(const context of [
  {cloudaicompanionProject:'p',currentTier:{id:'paid'}},
  {cloudaicompanionProject:{projectId:'p'},paidTier:{}},
  {allowedTiers:[{id:'free-tier'}]},
  {allowedTiers:[{id:'offered',isDefault:true}]}
 ]){assert.equal(detectVerification(JSON.stringify({...context,ineligibleTiers:[notice]})),undefined);assert(detectVerification(JSON.stringify({...context,error:notice})));}
 assert(detectVerification(JSON.stringify({ineligibleTiers:[notice]})));
 assert(detectVerification(JSON.stringify({response:{details:[notice]}})));
 assert.equal(detectVerification(JSON.stringify({'@type':'evil',verificationUrl:'https://google.com'})),undefined);
});
test('model aliases and provider families match switcher including Carbon quota',()=>{
 for(const m of ['carbon','carbon-high','models/GEMINI-4-CARBON','argon','argon-low']){assert.equal(family(m),'argon');assert(requiresUltra(m));}
 for(const m of ['sonnet','opus','haiku','anthropic','o1','o3-mini','o4_high'])assert.equal(family(m),'claude');
 for(const m of ['hydrogen','helium','pro','ultra','flash'])assert.equal(family(m),'gemini');
 assert.equal(family('custom-model'),'unknown');
 assert.equal(requiresUltra('models/GEMINI-4-ARGON-TRIAL'),false);
 assert.match(UA,new RegExp('^antigravity/hub/2\\.23\\.0 '+(process.platform==='win32'?'windows':process.platform)+'/'));
});
test('60 second refresh margin, forced refresh coalescing and rotated refresh token',async()=>{
 const x=setup();try{
  x.store.putAccount(account('a',{token_expiry:Date.now()+90_000}));let calls=0;const wait=deferred<any>();
  fakeOAuth(x.pool,async()=>{calls++;return wait.promise;});
  assert.equal(await x.pool.access('a'),'old');assert.equal(calls,0);
  const first=x.pool.access('a',true),second=x.pool.access('a',true),third=x.pool.access('a');
  await Promise.resolve();assert.equal(calls,1);
  wait.resolve({access_token:'new',refresh_token:'rotated',expiry_date:Date.now()+1e6});
  assert.deepEqual(await Promise.all([first,second,third]),['new','new','new']);
  assert.equal(x.store.accounts()[0].refresh_token,'rotated');assert.equal(x.pool.refreshes.size,0);
  x.store.putAccount({...x.store.accounts()[0],token_expiry:Date.now()+30_000});
  fakeOAuth(x.pool,async()=>{calls++;return {access_token:'soon'};});
  assert.equal(await x.pool.access('a'),'soon');assert.equal(calls,2);
 }finally{x.close();}
});
test('transient refresh errors preserve status, revoked errors flag auth and manual disables win',async()=>{
 const x=setup();try{
  x.store.putAccount(account('a'));
  for(const e of [new Error('network timeout'),new Error('HTTP 503'),{response:{data:{error:'temporarily_unavailable'}}}]){
   fakeOAuth(x.pool,async()=>{throw e;});await assert.rejects(x.pool.access('a',true));assert.equal(x.store.accounts()[0].status,'ready');assert.equal(x.pool.refreshes.size,0);
  }
  fakeOAuth(x.pool,async()=>{throw {response:{data:{error:'invalid_grant'}}};});
  await assert.rejects(x.pool.access('a',true));assert.equal(x.store.accounts()[0].status,'auth_error');
  x.store.putAccount(account('a',{status:'disabled'}));await assert.rejects(x.pool.access('a',true));assert.equal(x.store.accounts()[0].status,'disabled');
  x.pool.oauth=()=>{throw new Error('setup failed');};await assert.rejects(x.pool.access('a',true));assert.equal(x.pool.refreshes.size,0);
 }finally{x.close();}
});
test('Argon trial prefers Ultra and promotes, Pro weekly fallback requires positive explicit evidence',()=>{
 const x=setup();try{
  x.store.putAccount(account('pro',{buckets:pro()}));
  x.store.putAccount(account('ultra',{shared:true,buckets:gemini()}));
  assert.equal(x.pool.route('models/GEMINI-4-ARGON-TRIAL')?.account.id,'ultra');
  assert.equal(x.pool.route('models/GEMINI-4-ARGON-TRIAL')?.model,'gemini-4-argon-low');
  assert.equal(x.pool.route('gemini-4-argon-high')?.account.id,'ultra');
  assert.equal(x.pool.route('gemini-4-argon-high',new Set(['ultra'])),undefined,'excluding eligible Ultra alone must not grant trial fallback');
  x.pool.failed('ultra','gemini-4-argon-low',429,'');
  const route=x.pool.route('gemini-4-argon-high');assert.equal(route?.account.id,'pro');assert.equal(route?.model,'gemini-4-argon-trial');
  assert.equal(x.pool.route('carbon'),undefined);
  assert.equal(x.pool.route('gemini-4-argon-trial')?.model,'gemini-4-argon-trial','promotion must not stick to Pro');
  const p=x.store.accounts().find(a=>a.id==='pro')!;p.buckets[0].bucketId='other-argon';x.store.putAccount(p);
  assert.equal(x.pool.route('gemini-4-argon-high'),undefined);
  p.buckets=pro();p.buckets[0].remaining=0;x.store.putAccount(p);assert.equal(x.pool.route('gemini-4-argon-high'),undefined);
 }finally{x.close();}
});
test('all family windows govern routing, unknown legacy quota is not Ultra proof',()=>{
 const x=setup();try{
  const buckets=gemini();buckets.push({...buckets[0],bucketId:'weekly',remaining:0,reset:Date.now()+1e6});
  const a=account('a',{shared:true,buckets});
  assert(!x.pool.eligible(a,'gemini-4-argon-trial'));assert(!x.pool.eligible(a,'gemini-4-argon-low'));assert(x.pool.eligible(a,'claude'));
  buckets[1].reset=Date.now()-1;assert(x.pool.eligible(a,'gemini-4-argon-low'));
  assert(!x.pool.eligible(account('unknown',{shared:true}),'gemini-4-argon'));
  assert(x.pool.eligible(account('legacy'),'gemini-flash'));
  assert(!x.pool.eligible(account('disabled',{status:'disabled',buckets:gemini()}),'gemini-flash'));
  assert(!x.pool.eligible(account('auth',{status:'auth_error',buckets:gemini()}),'gemini-flash'));
 }finally{x.close();}
});
test('subscription backoff is normalized and isolated, quota 403 blocks only the shared family',()=>{
 const x=setup();try{
  x.store.putAccount(account('a',{shared:true,buckets:gemini()}));
  const sub=JSON.stringify({error:{details:[{reason:'SUBSCRIPTION_REQUIRED'}]}});
  assert(x.pool.failed('a','models/GEMINI-4-ARGON-HIGH',403,sub));
  let a=x.store.accounts()[0];assert(!a.blocked);assert(a.denied['gemini-4-argon-high']>Date.now());
  assert(x.pool.eligible(a,'gemini-4-argon-low'));
  assert(x.pool.failed('a','gemini-4-argon-low',403,'RATE_LIMIT_EXCEEDED'));
  a=x.store.accounts()[0];assert(!a.blocked);assert(a.cooldowns.gemini>Date.now());assert(x.pool.eligible(a,'claude'));
  assert(!x.pool.failed('a','claude',403,'permission denied quota project configuration'));
  assert(x.pool.failed('a','claude',400,sub));
 }finally{x.close();}
});
test('verification persists independent of status and safe output strips tokens and unsafe links',()=>{
 const x=setup();try{
  x.store.putAccount(account('a',{status:'disabled'}));assert(x.pool.failed('a','gemini',400,verify('https://evil.test')));
  const a=x.store.accounts()[0];assert.equal(a.status,'disabled');assert.equal(a.verification?.url,'');
  const safe=x.pool.safe()[0];assert.equal(safe.verification?.url,'');assert(!('refresh_token' in safe));assert(!('access_token' in safe));
  x.store.putAccount({...a,status:'ready',verification:{url:'javascript:alert(1)',observedAt:1}});
  assert(!x.pool.select('gemini-flash'));assert.equal(x.pool.safe()[0].verification?.url,'');
 }finally{x.close();}
});
test('direct poll forces one 401 refresh, uses hub runtime UA and 404 legacy fallback',async()=>{
 const x=setup(),original=globalThis.fetch;try{
  x.store.putAccount(account('a'));let refresh=0;fakeOAuth(x.pool,async()=>{refresh++;return {access_token:'new'};});
  const calls:{url:string;auth:string;ua:string;body:any}[]=[];
  globalThis.fetch=(async(url:any,init:any)=>{
   calls.push({url:String(url),auth:init.headers.authorization,ua:init.headers['user-agent'],body:init.body});
   if(calls.length===1)return new Response('{}',{status:401});
   if(calls.length===2)return new Response('{}',{status:404});
   return Response.json({buckets:[{model_id:'gemini-flash',remaining_fraction:1}]});
  }) as any;
  await x.pool.poll('a');assert.equal(refresh,1);assert.equal(calls.length,3);
  assert.equal(calls[0].body,'{}');assert.equal(calls[0].ua,UA);assert.equal(calls[1].auth,'Bearer new');
  assert(calls[2].url.endsWith(':retrieveUserQuota'));assert.equal(calls[2].body,'{"project":""}');assert(x.store.accounts()[0].shared);
 }finally{globalThis.fetch=original;x.close();}
});
test('failed direct polls preserve quota and transient status but revoke shared topology',async()=>{
 const x=setup(),original=globalThis.fetch;try{
  for(const status of [400,429,500,501]){
   const a=account('a',{shared:true,buckets:gemini()});x.store.putAccount(a);let calls=0;
   globalThis.fetch=(async()=>{calls++;return Response.json({error:{}},{status});}) as any;
   await assert.rejects(x.pool.poll('a'));assert.equal(calls,1);const after=x.store.accounts()[0];
   assert.deepEqual(after.buckets,JSON.parse(JSON.stringify(a.buckets)));assert.equal(after.shared,false);assert.equal(after.status,'ready');assert.equal(after.blocked,false);
  }
  globalThis.fetch=(async()=>new Response(verify(),{status:200})) as any;
  await assert.rejects(x.pool.poll('a'));assert(x.store.accounts()[0].verification);
  globalThis.fetch=(async()=>new Response('x'.repeat(1024*1024+1))) as any;
  await assert.rejects(x.pool.poll('a'),/maximum size/);assert(x.store.accounts()[0].verification);
 }finally{globalThis.fetch=original;x.close();}
});
test('poll clears only older verification blocking and healthy-family cooldown observations',async()=>{
 const x=setup(),original=globalThis.fetch;try{
  const a=account('a',{blocked:true,buckets:gemini(),cooldowns:{gemini:Date.now()+1e6,claude:Date.now()+1e6},verification:{url:'https://google.com/',observedAt:1}});
  x.store.putAccount(a);
  globalThis.fetch=(async()=>Response.json({groups:[{displayName:'Gemini',buckets:[{bucketId:'g',remainingFraction:1}]}]})) as any;
  await x.pool.poll('a');let after=x.store.accounts()[0];assert(!after.blocked);assert(!after.verification);assert(!after.cooldowns.gemini);assert(after.cooldowns.claude);
  // Observe a fresh verification and family error while the direct fetch is in flight.
  const wait=deferred<Response>(),entered=deferred<void>();
  globalThis.fetch=(async()=>{entered.resolve();return wait.promise;}) as any;
  const pending=x.pool.poll('a');await entered.promise;
  x.pool.failed('a','gemini-flash',403,verify());
  x.pool.failed('a','gemini-flash',429,'');
  wait.resolve(Response.json({groups:[{displayName:'Gemini',buckets:[{bucketId:'g',remainingFraction:1}]}]}));
  await pending;after=x.store.accounts()[0];assert(after.verification);assert(after.cooldowns.gemini>Date.now());
 }finally{globalThis.fetch=original;x.close();}
});
test('poll success never re-enables manual disables or independent auth errors',async()=>{
 const x=setup(),original=globalThis.fetch;try{
  x.store.putAccount(account('a'));const wait=deferred<Response>(),entered=deferred<void>();
  globalThis.fetch=(async()=>{entered.resolve();return wait.promise;}) as any;
  const pending=x.pool.poll('a');await entered.promise;
  x.store.putAccount({...x.store.accounts()[0],status:'disabled'});
  wait.resolve(Response.json({buckets:[]}));await pending;assert.equal(x.store.accounts()[0].status,'disabled');
  x.store.putAccount(account('a',{status:'auth_error'}));globalThis.fetch=(async()=>Response.json({buckets:[]})) as any;
  await x.pool.poll('a');assert.equal(x.store.accounts()[0].status,'auth_error');
 }finally{globalThis.fetch=original;x.close();}
});
