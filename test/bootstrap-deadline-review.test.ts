import {test} from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import type {Request,Response} from 'express';
import {Store} from '../server/store.js';
import {Pool} from '../server/pool.js';
import {createBootstrap} from '../server/bootstrap.js';

test('bootstrap deadlines release all eight slots during shared hung OAuth refresh',async t=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-bootstrap-deadline-')),store=new Store(dir);
 const pool=new Pool(store,'http://127.0.0.1:1','',''),bootstrap=createBootstrap(store,pool);
 const key=store.createKey({name:'deadline-review'}).key;
 store.putAccount({id:'a',email:'fake@example.invalid',refresh_token:'fake',access_token:'',token_expiry:0,status:'ready',shared:false,blocked:false,buckets:[],cooldowns:{},denied:{},updated:Date.now()});
 let rejectRefresh!:(e:Error)=>void,accessCalls=0;
 const sharedRefresh=new Promise<string>((_resolve,reject)=>{rejectRefresh=reject;});
 pool.access=()=>{accessCalls++;return sharedRefresh;};
 const req={method:'POST',originalUrl:'/v1internal:loadCodeAssist',body:Buffer.from('{"metadata":{"ideType":"ANTIGRAVITY"}}')} as Request;
 const response=()=>Object.assign(new EventEmitter(),{writableEnded:false,destroyed:false}) as unknown as Response;
 const invoke=(res=response())=>bootstrap(req,res,key).then(()=>undefined,(e:Error&{status?:number})=>e);
 t.mock.timers.enable({apis:['setTimeout']});
 try{
  const responses=Array.from({length:8},response),first=responses.map(invoke);
  assert.equal(accessCalls,8);
  assert.equal((await invoke())?.status,429);
  t.mock.timers.tick(14999);await Promise.resolve();
  assert.equal((await invoke())?.status,429);
  t.mock.timers.tick(1);
  for(const err of await Promise.all(first))assert.match(err?.message??'',/Eligibility request canceled/);
  for(const res of responses)assert.equal(res.listenerCount('close'),0);
  // Every slot must be reusable even though the shared refresh remains unresolved.
  const secondResponses=Array.from({length:8},response),second=secondResponses.map(invoke);
  assert.equal(accessCalls,16);
  assert.equal((await invoke())?.status,429);
  // Disconnects must release the same slots without waiting another deadline.
  secondResponses.forEach(res=>res.emit('close'));
  for(const err of await Promise.all(second))assert.match(err?.message??'',/Eligibility request canceled/);
  for(const res of secondResponses)assert.equal(res.listenerCount('close'),0);
  // Late failure of shared work must remain handled after all callers abandoned it.
  rejectRefresh(new Error('late shared refresh failure'));await Promise.resolve();
 }finally{t.mock.timers.reset();store.close();rmSync(dir,{recursive:true,force:true});}
});
