import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,statSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHmac} from 'node:crypto';
import {Store,windowStart,nextReset} from '../server/store.js';
function setup(){const dir=mkdtempSync(join(tmpdir(),'agyp-'));const s=new Store(dir);return {s,dir,cleanup(){s.close();rmSync(dir,{recursive:true,force:true});}};}
test('plaintext protected keys persist; no key exposure in safe lists',()=>{
 const {s,dir,cleanup}=setup();try{const k=s.createKey({name:'test'});assert.equal(s.key(k.key.id)?.token,k.token);assert.equal(statSync(join(dir,'agyp.sqlite')).mode&0o777,0o600);assert.equal(statSync(dir).mode&0o777,0o700);
 assert(!JSON.stringify(s.keys()).includes(k.token));assert.equal(s.adminToken,s.key(s.keys()[0].id)?.token);}finally{cleanup();}
});
test('challenge HMAC succeeds once; invalid proof consumes challenge; unknown key indistinguishable',()=>{
 const {s,cleanup}=setup();try{const {key,token}=s.createKey({name:'test'}),c=s.challenge(key.id),proof=createHmac('sha256',token).update(c.nonce).digest('hex');
 assert.equal(s.verify(key.id,c.nonce,proof)?.id,key.id);assert.equal(s.verify(key.id,c.nonce,proof),undefined);
 const bad=s.challenge(key.id);assert.equal(s.verify(key.id,bad.nonce,'bad'),undefined);assert.equal(s.verify(key.id,bad.nonce,createHmac('sha256',token).update(bad.nonce).digest('hex')),undefined);
 assert(s.challenge('f'.repeat(16)).nonce);assert.equal(s.verify('f'.repeat(16),s.challenge('f'.repeat(16)).nonce,'0'.repeat(64)),undefined);
 }finally{cleanup();}
});
test('expired, cross-key challenges and revoked sessions reject',()=>{
 const {s,cleanup}=setup();try{const a=s.createKey({name:'a'}),b=s.createKey({name:'b'});let c=s.challenge(a.key.id);
 assert.equal(s.verify(b.key.id,c.nonce,createHmac('sha256',b.token).update(c.nonce).digest('hex')),undefined);
 c=s.challenge(a.key.id);s.db.prepare('UPDATE challenges SET expires=0').run();assert.equal(s.verify(a.key.id,c.nonce,createHmac('sha256',a.token).update(c.nonce).digest('hex')),undefined);
 const session=s.session(a.key);assert.equal(s.authSession(session.token)?.key.id,a.key.id);assert.equal(s.authSession(a.token),undefined);s.revoke(a.key.id);assert.equal(s.authSession(session.token),undefined);
 }finally{cleanup();}
});
test('admission reservations prevent concurrency overspend; accounting separates cache',()=>{
 const {s,cleanup}=setup();try{const a=s.createKey({name:'capped',allowance:100,inputCap:80,outputCap:40});const r=s.reserve(a.key,'exact',60,30);assert.throws(()=>s.reserve(a.key,'exact',10,10),/allowance/);s.finish(r,{input:20,output:10,cached:5,total:30},200);
 assert.equal(s.used(a.key).total,30);const stats=s.stats(a.key.id).models[0] as any;assert.equal(stats.noncached,15);assert.equal(stats.cached,5);
 const other=s.createKey({name:'other'});assert.equal(s.stats(other.key.id).models.length,0);
 }finally{cleanup();}
});
test('UTC calendar daily weekly monthly reset',()=>{const now=Date.UTC(2026,10,21,20);assert.equal(windowStart('daily',now),Date.UTC(2026,10,21));assert.equal(windowStart('weekly',now),Date.UTC(2026,10,16));assert.equal(nextReset('monthly',now),Date.UTC(2026,11,1));assert.equal(nextReset('never',now),null);});
