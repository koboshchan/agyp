import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store,type Account} from '../server/store.js';
import {Pool,parseQuota,requiresUltra,family} from '../server/pool.js';
import {UsageReader,extractModel,usageOf} from '../server/proxy.js';
const a=(id:string,extra:Partial<Account>={}):Account=>({id,email:id+'@example.com',refresh_token:'secret',access_token:'secret',token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets:[{family:'gemini',label:'Gemini burst',remaining:.5,reset:0},{family:'argon',label:'Argon weekly',remaining:.6,reset:0},{family:'claude',label:'Claude',remaining:1,reset:0}],cooldowns:{},denied:{},updated:Date.now(),...extra});
test('family model and authoritative quota normalize all windows',()=>{assert.equal(family('gemini-4-argon-trial'),'argon');assert.equal(family('claude-x'),'claude');assert(requiresUltra('gemini-4-carbon'));assert(!requiresUltra('gemini-4-argon-trial'));const q=parseQuota({groups:[{displayName:'Gemini Models',buckets:[{bucketId:'a',remainingFraction:1},{bucket_id:'weekly',remaining_fraction:0,reset_time:'2026-11-30T00:00:00Z'}]},{display_name:'Gemini Argon',buckets:[{remaining_fraction:.5}]}]});assert.equal(q.length,3);assert.equal(q[1].remaining,0);assert.equal(q[2].family,'argon');});
test('per family cooldown, weekly depletion, ultra and exact model',()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-')),s=new Store(dir),p=new Pool(s,'http://localhost','','');try{
 s.putAccount(a('a'));s.putAccount(a('b'));
 assert.equal(p.select('gemini-4-argon-trial')?.id,'a');assert.equal(p.select('gemini-4-argon'),undefined);
 p.failed('a','gemini-4-argon-trial',429,'');assert.equal(p.select('gemini-4-argon-trial')?.id,'b');assert.equal(p.select('gemini-4-carbon'),undefined);assert(p.eligible(s.accounts().find(a=>a.id==='a')!,'claude'));
 const shared=a('u',{shared:true});shared.buckets=shared.buckets.filter(x=>x.family!=='argon');s.putAccount(shared);assert.equal(p.select('gemini-4-carbon')?.id,'u');
 shared.buckets.push({family:'gemini',label:'weekly',remaining:0,reset:Date.now()+1e6});s.putAccount(shared);assert.equal(p.select('gemini-4-carbon'),undefined);
 assert.equal(extractModel('/v1internal:generateContent',{model:'gemini-4-argon-trial'}),'gemini-4-argon-trial');
 assert.throws(()=>extractModel('/v1/models/modelA:generateContent',{model:'modelB'}),/Conflicting/);
 }finally{s.close();rmSync(dir,{recursive:true,force:true});}
});
test('SSE usage parses split UTF8, nested metadata, cumulative totals and thoughts',()=>{
 const r=new UsageReader(true);const b=Buffer.from('data: '+JSON.stringify({response:{text:'喵',usageMetadata:{promptTokenCount:20,candidatesTokenCount:5,thoughtsTokenCount:3,totalTokenCount:28,cachedContentTokenCount:8}}})+'\n\ndata: [DONE]\n\n');
 for(const n of b)r.feed(Uint8Array.of(n));r.end();assert.deepEqual(r.value,{input:20,output:8,cached:8,total:28});
 assert.equal(usageOf({usageMetadata:{promptTokenCount:-1}})?.input,0);
});
