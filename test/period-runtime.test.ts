import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store,nextReset} from '../server/store.js';
import {displayQuota,mapQuotaSummary} from '../server/quota-display.js';
const hour=3600000;
test('5h first generation request anchors, serialized callers share anchor, idle expiry reanchors without sliding',()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-period-'));const s=new Store(dir),other=new Store(dir);const original=Date.now;let now=Date.parse('2026-11-22T05:00Z');Date.now=()=>now;
 try{
  const k=s.createKey({name:'new',period:'5h',allowance:100}).key;
  assert.equal(s.safeKey(k).resets,null);now+=hour;
  const control=s.reserve(k,'(control)',0,0,false);s.finish(control,{input:0,output:0,cached:0,total:0},200);assert.equal(s.safeKey(k).resets,null);
  const first=now,a=s.reserve(k,'gemini-high',999,999);now+=hour;const b=other.reserve(k,'gemini-low',999,999);
  assert.equal(other.safeKey(k).resets,first+5*hour);
  s.finish(a,{input:60,output:10,cached:20,total:70},200);other.finish(b,{input:40,output:10,cached:0,total:50},200);
  assert.equal(s.used(k).total,120);assert.throws(()=>s.reserve(k,'gemini',0,0),/exhausted/);
  now=first+5*hour;assert.equal(s.used(k).total,0);assert.equal(s.keyReset(k),null);
  now+=17*hour+123;s.reserve(k,'gemini',0,0);assert.equal(s.keyReset(k),now+5*hour);assert.equal(s.used(k).total,0);
  assert.equal((s.stats(k.id).models as any[]).find(r=>r.model==='gemini-high').total,70);
 }finally{Date.now=original;other.close();s.close();rmSync(dir,{recursive:true,force:true})}
});
test('weekly/5h mapping and lifetime balance use own reset; legacy periods retain original semantics',()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-period-')),s=new Store(dir);
 try{
  for(const period of ['5h','weekly','never','daily','monthly']){
   const k=s.createKey({name:period,period,allowance:100}).key,id=s.reserve(k,'gemini',0,0);s.finish(id,{input:40,output:10,cached:10,total:50},200);
   const q=displayQuota(s,k);assert.equal(q.fraction,0.5);
   if(period==='never')assert.equal(q.reset,undefined);else if(period!=='5h')assert.equal(q.reset,new Date(nextReset(period)!).toISOString());
   const out=mapQuotaSummary({groups:[{displayName:'Gemini Models',buckets:[{window:'5h'},{window:'weekly'}]}]},q);
   assert.equal(out.groups[0].buckets[0].remainingFraction,period==='weekly'?1:0.5);
   assert.equal(out.groups[0].buckets[1].remainingFraction,period==='5h'?1:0.5);
   if(period==='5h')assert.equal(out.groups[0].buckets[1].resetTime,undefined);
   if(period==='weekly')assert.equal(out.groups[0].buckets[0].resetTime,undefined);
  }
 }finally{s.close();rmSync(dir,{recursive:true,force:true})}
});
