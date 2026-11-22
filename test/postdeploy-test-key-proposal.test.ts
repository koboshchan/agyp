import test from 'node:test';import assert from 'node:assert/strict';import {mkdtempSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {Store} from '../server/store.js';import {displayQuota,mapQuotaSummary} from '../server/quota-display.js';import {createPostdeployTestKey} from '../server/postdeploy-test-key-proposal.js';
test('postdeploy test keys are separately gated, atomic, 50% with own reset/opposite full; duplicates refuse and old key stays deleted',()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-postdeploy-')),s=new Store(dir);
 try{
  const old=s.createKey({name:'test-usage-half',period:'daily',allowance:1000000}).key;s.deleteKey(old.id);
  const gate={freshlyApprovedDeployVerified:true,postdeployStepApproved:true};
  for(const name of ['test-5h-half','test-weekly-half'] as const){
   for(const closed of [{...gate,freshlyApprovedDeployVerified:false},{...gate,postdeployStepApproved:false}])assert.throws(()=>createPostdeployTestKey(s,name,closed),/gate closed/);
   assert.equal(s.db.prepare('SELECT 1 FROM keys WHERE name=?').get(name),undefined);
   const k=createPostdeployTestKey(s,name,gate).key,q=displayQuota(s,k),stats=s.stats(k.id).models as any[];
   assert.equal(k.admin,0);assert.equal(q.fraction,0.5);assert(q.reset);assert.equal(stats.length,1);assert.equal(stats[0].requests,1);assert.equal(stats[0].input,500000);assert.equal(stats[0].cached,0);assert.equal(stats[0].output,0);assert.equal(stats[0].total,500000);assert.equal(stats[0].model,'test-synthetic-usage');
   const out=mapQuotaSummary({groups:[{displayName:'Gemini Models',buckets:[{window:'5h'},{window:'weekly'}]}]},q);
   assert.equal(out.groups[0].buckets[0].remainingFraction,name==='test-5h-half'?0.5:1);assert.equal(out.groups[0].buckets[1].remainingFraction,name==='test-weekly-half'?0.5:1);
   assert.throws(()=>createPostdeployTestKey(s,name,gate),/Duplicate/);assert.equal((s.stats(k.id).models as any[])[0].requests,1);
  }
  assert.equal(s.key(old.id)!.revoked,1);assert.equal(s.key(old.id)!.name,'Deleted key');
 }finally{s.close();rmSync(dir,{recursive:true,force:true})}
});
