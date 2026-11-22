import {test} from 'node:test';
import assert from 'node:assert/strict';
import {hasMedia,allowedProxy} from '../server/proxy.js';
import {Store} from '../server/store.js';
import {Pool,parseQuota} from '../server/pool.js';
import {mkdtempSync,rmSync,statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
test('escaped and deeply nested media keys are recognized after JSON parse',()=>{
 const body=JSON.parse('{"request":{"contents":[{"parts":[{"\\u0066ileData":{"mimeType":"image/png","fileUri":"gs://x"}}]}]}}');
 assert(hasMedia(body));assert(hasMedia({a:[{inline_data:{}}]}));assert(!hasMedia({text:'fileData is a word'}));
});
test('upstream account/control paths forbidden, inference explicit method allowlist',()=>{
 for(const p of ['//attacker.invalid/v1/models/gemini-flash:generateContent','/\\attacker.invalid/v1/models/gemini-flash:generateContent','https://attacker.invalid/v1/models/x:generateContent','/v1internal:retrieveUserQuotaSummary','/v1internal:onboardUser','/v1internal:loadCodeAssist','/v1internal:deleteAccount','/api/keys','/v1internal:fetchAvailableModels/../onboardUser','/v1/models/x:generateContent/evil'])assert(!allowedProxy('POST',p),p);
 assert(allowedProxy('POST','/v1internal:streamGenerateContent?alt=sse'));assert(allowedProxy('POST','/v1/models/exact:countTokens'));assert(!allowedProxy('DELETE','/v1/models/x'));assert(!allowedProxy('GET','/v1internal:generateContent'));
});
test('quota routing follows Go family windows, including model-labeled and shared weekly buckets',()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-')),s=new Store(dir),p=new Pool(s,'http://localhost','','');
 try{
 const buckets=parseQuota({buckets:[{model_id:'gemini-flash',remaining_fraction:1},{model_id:'gemini-pro',remaining_fraction:0}]});
 assert.deepEqual(parseQuota({groups:[{displayName:'Models',modelIds:['gemini-flash'],buckets:[{remainingFraction:1}]}]})[0].models,['gemini-flash']);
 assert.deepEqual(buckets[0].models,['gemini-flash']);
 s.putAccount({id:'x',email:'x',refresh_token:'x',access_token:'x',token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets,cooldowns:{},denied:{},updated:Date.now()});
 // The switcher evaluates every window in the provider family, not a per-model entitlement.
 assert(!p.select('gemini-flash'));assert(!p.select('gemini-pro'));
 const healthy=s.accounts()[0];healthy.buckets[1].remaining=1;s.putAccount(healthy);assert(p.select('gemini-flash'));
 const a=s.accounts()[0];a.buckets.push({family:'gemini',label:'Shared weekly',remaining:0,reset:Date.now()+1e6});s.putAccount(a);assert(!p.select('gemini-flash'));
 for(const file of ['agyp.sqlite','agyp.sqlite-wal','agyp.sqlite-shm'])assert.equal(statSync(join(dir,file)).mode&0o777,0o600);
 }finally{s.close();rmSync(dir,{recursive:true,force:true});}
});
