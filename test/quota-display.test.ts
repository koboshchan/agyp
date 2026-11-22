import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store,nextReset} from '../server/store.js';
import {displayQuota,mapQuotaSummary} from '../server/quota-display.js';
// Synthetic provider-wire fixture based on independently decoded protobuf fields.
// This is NOT captured Google traffic or an executed real agy parser fixture.
const fixture={email:'pool@example.invalid',accountId:'private-account',description:'owner@example.invalid',groups:[
 {displayName:'Gemini Models',description:'private@example.invalid',buckets:[
  {bucketId:'gemini-weekly',displayName:'Weekly',window:'weekly',remainingAmount:'9223372036854775807',resetTime:'2099-01-01T00:00:00Z'},
  {bucketId:'gemini-5h',displayName:'5 hours',window:'5h',remainingFraction:0.04,disabled:false}]},
 {displayName:'Claude and GPT',buckets:[{bucketId:'claude-weekly',window:'weekly',remainingFraction:0.7},{bucketId:'claude-5h',window:'5h',remainingAmount:'999'}]},
 {displayName:'Gemini 4 Argon',buckets:[{bucketId:'gemini-argon-weekly',displayName:'Weekly',window:'weekly',remainingFraction:0.3,disabled:true}]}],buckets:[{bucketId:'not-used-by-real-mapper',remainingFraction:0.1}]};
test('summary keeps provider-wire grouped fields and one fraction arm, never printmode names or account metadata',()=>{
 const out=mapQuotaSummary(fixture,{fraction:0.4,capped:true,reset:'2026-12-01T00:00:00.000Z'});
 assert.equal(out.groups.length,3);
 for(const [i,g] of out.groups.entries())for(const b of g.buckets){
  assert.equal(b.remainingFraction,i===0?0.4:0);
  assert.equal(b.resetTime,'2026-12-01T00:00:00.000Z');
  for(const f of ['remainingAmount','remaining_amount','remaining_fraction','reset_time','id','name'])assert.equal(f in b,false,f);
 }
 assert.equal(out.groups[2].buckets[0].bucketId,'gemini-argon-weekly');
 assert.equal(out.groups[2].buckets[0].disabled,true);
 assert.doesNotMatch(JSON.stringify(out),/@|private-account|2099|not-used/);
 assert.equal('buckets' in out,false);
 assert.throws(()=>mapQuotaSummary({buckets:fixture.buckets},{fraction:1,capped:false}));
 assert.throws(()=>mapQuotaSummary({groups:[{displayName:'Gemini Models',buckets:[null]}]},{fraction:1,capped:false}));
});
test('every grouped bar is 100% unlimited and only Gemini Models tracks capped fresh/partial/exhausted fractions',()=>{
 for(const fraction of [1,0.7,0])for(const capped of [true,false]){
  const out=mapQuotaSummary(fixture,{fraction,capped});
  for(const [i,g]of out.groups.entries())for(const b of g.buckets){assert.equal(b.remainingFraction,capped?(i===0?fraction:0):1);assert.equal('resetTime' in b,false);}
 }
});
test('display fraction uses only own recorded usage, minimum binding cap, clamp and key reset; inflight estimates irrelevant',()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-display-')),s=new Store(dir);
 try{
  for(const period of ['never','daily','weekly','monthly'] as const){
   const key=s.createKey({name:'private-key-name',allowance:100,inputCap:40,outputCap:80,period}).key;
   assert.equal(displayQuota(s,key).fraction,1);
   const pending=s.reserve(key,'gemini',999999,999999);
   assert.equal(displayQuota(s,key).fraction,1);
   s.finish(pending,{input:20,output:10,cached:5,total:30},200);
   const q=displayQuota(s,key);assert.equal(q.fraction,0.5);assert.equal(q.capped,true);
   assert.equal(q.reset,period==='never'?undefined:new Date(nextReset(period)!).toISOString());
   const out=mapQuotaSummary(fixture,q);assert.doesNotMatch(JSON.stringify(out),/private-key-name/);
   assert.equal(out.groups[0].buckets[0].remainingFraction,0.5);
   // Own period rollovers read the same source of truth as admission.
   if(period!=='never'){
    s.db.prepare('UPDATE usage SET time=0 WHERE key_id=?').run(key.id);
    assert.equal(displayQuota(s,key).fraction,1);
   }
  }
  for(const caps of [{allowance:0},{inputCap:0},{outputCap:0}])assert.equal(displayQuota(s,s.createKey({name:'zero',...caps}).key).fraction,0);
  const other=s.createKey({name:'other'}).key;assert.deepEqual(displayQuota(s,other),{fraction:1,capped:false,period:'never'});
  for(const caps of [{allowance:10},{inputCap:10},{outputCap:10}]){
   const k=s.createKey({name:'exact',...caps}).key,id=s.reserve(k,'gemini',0,0);s.finish(id,{input:10,output:10,cached:0,total:20},200);assert.equal(displayQuota(s,k).fraction,0);
  }
 }finally{s.close();rmSync(dir,{recursive:true,force:true});}
});

test('legacy and model discovery retain model IDs, enum/capability metadata, not amount arms or pool resets',async()=>{
 const {mapLegacyQuota,mapAvailableModels,quotaDisplayAction}=await import('../server/quota-display.js');
 const {readFileSync}=await import('node:fs');
 const f=JSON.parse(readFileSync(new URL('./fixtures/quota-display.json',import.meta.url),'utf8'));
 for(const capped of [true,false])for(const fraction of [1,0.6,0]){
  const q={capped,fraction,reset:'2026-12-01T00:00:00.000Z'},legacy=mapLegacyQuota(f.retrieveUserQuota,q),models=mapAvailableModels(f.fetchAvailableModels,q);
  assert.equal(legacy.buckets.length,4);
  for(const [i,b]of legacy.buckets.entries()){
   assert.equal(b.modelId,f.retrieveUserQuota.buckets[i].modelId);assert.equal(b.tokenType,1);assert.equal(b.remainingFraction,!capped?1:i===0?fraction:0);assert.equal(b.resetTime,q.reset);assert.equal('remainingAmount' in b,false);
  }
  assert.deepEqual(Object.keys(models.models),Object.keys(f.fetchAvailableModels.models));
  for(const [i,d]of Object.values(models.models).entries()){
   const details=d as any;assert.equal(details.supportsThinking,true);assert.equal(details.quotaInfo.remainingFraction,!capped?1:i===0?fraction:0);assert.equal(details.quotaInfo.resetTime,q.reset);
  }
  assert.doesNotMatch(JSON.stringify([legacy,models]),/@|2099|123456/);
 }
 assert.equal(quotaDisplayAction('POST','/v1internal:retrieveUserQuotaSummary?alt=json'),'retrieveUserQuotaSummary');
 for(const path of ['/v1internal:retrieveUserQuota/extra','/v1internal:generateContent','/v1internal/retrieveUserQuotaSummary'])assert.equal(quotaDisplayAction('POST',path),undefined);
 assert.equal(quotaDisplayAction('GET','/v1internal:fetchAvailableModels'),'fetchAvailableModels');
});

test('provider group/bucket descriptors, IDs and extra capability metadata survive without account fields',async()=>{
 const {mapLegacyQuota,mapAvailableModels}=await import('../server/quota-display.js');
 const q={fraction:0.5,capped:true};
 const summary=mapQuotaSummary({description:'Quota limits',modelAvailabilities:[{modelId:'gemini-flash',available:true}],groups:[{displayName:'Gemini Models',description:'Shared limits',buckets:[{bucketId:'original',description:'Original quota description',displayName:'Original label',window:'WEEKLY',disabled:true,remainingAmount:'20'}]}]},q) as any;
 assert.equal(summary.description,'Quota limits');assert.equal(summary.groups[0].description,'Shared limits');assert.equal(summary.groups[0].buckets[0].description,'Original quota description');assert.equal(summary.groups[0].buckets[0].disabled,true);assert.equal(summary.groups[0].buckets[0].window,'WEEKLY');assert.deepEqual(summary.modelAvailabilities,[{modelId:'gemini-flash',available:true}]);
 const legacy=mapLegacyQuota({buckets:[{modelId:'gemini-flash',tokenType:'SYNTHETIC_UNKNOWN_ENUM',additionalInfo:{name:'retained'},remainingFraction:0.1,accountId:'private'}]},q) as any;
 assert.equal(legacy.buckets[0].tokenType,'SYNTHETIC_UNKNOWN_ENUM');assert.deepEqual(legacy.buckets[0].additionalInfo,{name:'retained'});assert.equal('accountId' in legacy.buckets[0],false);
 const models=mapAvailableModels({models:{'gemini-flash':{supportsThinking:true,quotaInfo:{remainingFraction:0.1},contextWindow:1000},'no-quota':{displayName:'No quota'}},arbitraryCapability:{flag:true}},q) as any;
 assert.equal(models.models['gemini-flash'].contextWindow,1000);assert.equal('quotaInfo' in models.models['no-quota'],false);assert.deepEqual(models.arbitraryCapability,{flag:true});
});

test('model quotaInfo retains sanitized unknown non-quota metadata while replacing every quota arm/reset alias',async()=>{
 const {mapAvailableModels}=await import('../server/quota-display.js');
 for(const reset of [undefined,'2026-12-01T00:00:00.000Z']){
  const out=mapAvailableModels({models:{'gemini-4-hydrogen':{quotaInfo:{additionalInfo:{capability:true,email:'private@example.invalid'},description:'retained',remainingAmount:'999',remaining_amount:'998',remainingFraction:0.1,remaining_fraction:0.2,resetTime:'2099',reset_time:'2098',accountId:'private'}}}},{capped:true,fraction:0.4,reset}) as any;
  assert.deepEqual(out.models['gemini-4-hydrogen'].quotaInfo,{additionalInfo:{capability:true},description:'retained',remainingFraction:0.4,...(reset?{resetTime:reset}:{})});
 }
});

test('opposite-period full applies only to eligible Gemini even at zero balance',async()=>{
 const {mapLegacyQuota}=await import('../server/quota-display.js');
 for(const period of ['5h','weekly'])for(const fraction of [0,0.5,1])for(const capped of [true,false]){
  const q={period,fraction,capped},windows=['5h','weekly'];
  const names=['Gemini Models','Claude Models','GPT Models','Argon Models'];
  const summary=mapQuotaSummary({groups:names.map(displayName=>({displayName,buckets:windows.map(window=>({window}))}))},q) as any;
  for(const [i,g]of summary.groups.entries())for(const [j,b]of g.buckets.entries())assert.equal(b.remainingFraction,!capped?1:i!==0?0:windows[j]===period?fraction:1);
  for(const [i,modelId]of ['gemini-flash','claude-sonnet','gpt-5','argon'].entries()){
   const legacy=mapLegacyQuota({buckets:windows.map(window=>({modelId,window}))},q) as any;
   for(const [j,b]of legacy.buckets.entries())assert.equal(b.remainingFraction,!capped?1:i!==0?0:windows[j]===period?fraction:1);
  }
 }
});
