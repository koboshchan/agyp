import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {Store} from '../server/store.js';import {proposedPeriodMigration,applyApprovedPeriodMigration} from '../server/period-migration-proposal.js';
test('offline named migration carries exact balance/history, starts on first request, retry idempotent, other daily untouched',()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-migrate-')),s=new Store(dir),original=Date.now;let now=Date.parse('2026-11-22T05:44Z');Date.now=()=>now;
 try{
  const a=s.createKey({name:'makieify',period:'daily',allowance:10000000}).key,b=s.createKey({name:'test-usage-half',period:'daily',allowance:1000000}).key,c=s.createKey({name:'unrelated',period:'daily',allowance:7}).key;
  for(const [k,total]of [[a,25552],[b,500000]] as const){const id=s.reserve(k,'synthetic-fixture',0,0);s.finish(id,{input:total,output:0,cached:0,total},200);}
  s.deleteKey(b.id);const history=JSON.stringify(s.db.prepare('SELECT * FROM usage').all()),plan=proposedPeriodMigration(s,now);
  assert.equal(applyApprovedPeriodMigration(s,plan,now),'applied');assert.equal(applyApprovedPeriodMigration(s,plan,now),'already-applied');
  const migrated=s.key(a.id)!;assert.equal(s.key(b.id)!.period,'daily');assert.equal(s.used(migrated).total,25552);assert.equal(s.keyReset(migrated),null);assert.equal(s.key(c.id)!.period,'daily');assert.equal(s.key(a.id)!.allowance,2000000);
  now+=3600000;s.reserve(migrated,'gemini-high',0,0);assert.equal(s.keyReset(migrated),now+18000000);assert.equal(s.used(migrated).total,25552);
  assert.equal(applyApprovedPeriodMigration(s,plan,now),'already-applied');assert.equal(JSON.stringify(s.db.prepare('SELECT * FROM usage').all()),history);
  now+=18000000;assert.equal(s.used(migrated).total,0);assert.equal(JSON.stringify(s.db.prepare('SELECT * FROM usage').all()),history);
 }finally{Date.now=original;s.close();rmSync(dir,{recursive:true,force:true})}
});
test('offline migration refuses duplicates, altered caps and usage snapshots atomically',()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-migrate-')),s=new Store(dir),now=Date.now();
 try{
  const a=s.createKey({name:'makieify',period:'daily',allowance:10000000}).key,b=s.createKey({name:'test-usage-half',period:'daily',allowance:1000000}).key;
  const plan=proposedPeriodMigration(s,now);s.db.prepare('UPDATE keys SET allowance=99 WHERE id=?').run(a.id);assert.throws(()=>applyApprovedPeriodMigration(s,plan,now));assert.equal(s.key(a.id)!.period,'daily');
  s.db.prepare('UPDATE keys SET allowance=10000000 WHERE id=?').run(a.id);const id=s.reserve(a,'synthetic-fixture',0,0);s.finish(id,{input:1,output:0,cached:0,total:1},200);assert.throws(()=>applyApprovedPeriodMigration(s,plan,now),/snapshot changed/);
  s.createKey({name:'makieify',period:'daily',allowance:10000000});assert.throws(()=>proposedPeriodMigration(s,now),/exactly one/);assert.equal(s.key(a.id)!.period,'daily');
 }finally{s.close();rmSync(dir,{recursive:true,force:true})}
});

test('migration fingerprints expiry and rejects expiry reached at apply atomically',()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-expiry-')),s=new Store(dir),now=Date.parse('2026-11-22T06:00Z');
 try{
  const k=s.createKey({name:'makieify',period:'daily',allowance:10000000,expires:now+1000}).key;
  const plan=proposedPeriodMigration(s,now);
  s.db.prepare('UPDATE keys SET expires=? WHERE id=?').run(now+2000,k.id);
  assert.throws(()=>applyApprovedPeriodMigration(s,plan,now),/snapshot changed/);
  s.db.prepare('UPDATE keys SET expires=? WHERE id=?').run(now+1000,k.id);
  assert.throws(()=>applyApprovedPeriodMigration(s,plan,now+1000),/expired/);
  assert.throws(()=>proposedPeriodMigration(s,now+1000),/configuration/);
  assert.equal(s.key(k.id)!.period,'daily');assert.equal(s.key(k.id)!.allowance,10000000);
  assert.equal(s.db.prepare('SELECT 1 FROM key_windows WHERE key_id=?').get(k.id),undefined);
  assert.equal(applyApprovedPeriodMigration(s,plan,now),'applied');
  s.db.prepare('UPDATE keys SET expires=? WHERE id=?').run(now+2000,k.id);
  assert.throws(()=>applyApprovedPeriodMigration(s,plan,now));
 }finally{s.close();rmSync(dir,{recursive:true,force:true})}
});
