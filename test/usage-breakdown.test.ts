import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:http';
import {once} from 'node:events';
import {createHmac} from 'node:crypto';
import WebSocket from 'ws';
import {attachWebSocket} from '../server/ws.js';
import {Store} from '../server/store.js';
import {createApp} from '../server/app.js';
import {allowedProxy} from '../server/proxy.js';
import {allowedBootstrap} from '../server/bootstrap.js';
test('admin recorded per-key/model aggregation preserves deleted history and user scope',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-breakdown-')),store=new Store(dir);
 const a=store.createKey({name:'Key A'}),b=store.createKey({name:'Key B'}),admin=store.key(store.adminToken.slice(5,21))!;
 const config={origin:'',upstream:'http://127.0.0.1:1',clientId:'',clientSecret:'',secure:false};
 const {app,pool}=createApp(store,config),server=createServer(app);const transport=attachWebSocket(server,store,pool);await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));config.origin='http://127.0.0.1:'+(server.address() as any).port;
 try{
  for(const [key,model] of [[a.key,'gemini-test'],[a.key,'__proto__'],[b.key,'gemini-test']] as const){
   const id=store.reserve(key,model,0,0);store.finish(id,{input:20,output:5,cached:8,total:25},200);store.finish(id,{input:999,output:999,cached:999,total:1998},200);
  }
  store.deleteKey(b.key.id);
  async function stats(k:typeof a.key,query=''){
   const session=store.session(k);const res=await fetch(config.origin+'/api/stats'+query,{headers:{cookie:'agyp_session=' +session.token}});return {status:res.status,body:await res.json() as any};
  }
  const all=await stats(admin);assert.equal(all.status,200);assert.equal(all.body.models.length,3);
  assert.equal(all.body.models.reduce((n:number,r:any)=>n+r.total,0),75);
  for(const row of all.body.models){assert.equal(row.input,20);assert.equal(row.cached,8);assert.equal(row.noncached,12);assert.equal(row.output,5);assert.equal(row.total,25);assert.equal(row.requests,1)}
  assert.equal(all.body.overview.find((r:any)=>r.model==='gemini-test').total,50);
  for(const model of ['gemini-high','gemini-medium','gemini-low','(control)']){
   const id=store.reserve(a.key,model,0,0,false);store.finish(id,{input:0,output:0,cached:0,total:0},200);
  }
  const combined=(await stats(admin)).body;
  for(const model of ['gemini-high','gemini-medium','gemini-low'])assert.equal(combined.overview.filter((r:any)=>r.model===model).length,1);
  assert.equal(combined.overview.some((r:any)=>r.model==='(control)'),false);assert.equal(combined.control.requests,1);assert.equal(combined.control.total,0);
  const deleted=all.body.models.find((r:any)=>r.key_id===b.key.id);assert.equal(deleted.key_name,'Deleted key');assert.equal(deleted.key_revoked,1);
  const own=await stats(a.key,'?key_id='+b.key.id);assert.equal(own.status,200);assert.equal(own.body.models.length,6);assert(own.body.models.every((r:any)=>r.key_id===a.key.id));
  assert(own.body.models.some((r:any)=>r.model==='__proto__'));assert(!JSON.stringify(own.body).includes(b.key.id));assert(!JSON.stringify(own.body).includes('key_name'));
  for(const token of [a.token,b.token,store.adminToken])assert(!JSON.stringify(all.body).includes(token));
  assert.equal((await fetch(config.origin+'/api/stats')).status,401);
  // The WSS transport shares these allowlists and cannot tunnel admin REST stats.
  for(const path of ['/api/stats','/api/stats?key_id='+b.key.id]){assert.equal(allowedProxy('GET',path),false);assert.equal(allowedBootstrap('GET',path),false)}

  for(const k of [a, {token:store.adminToken}]){
   const ws=new WebSocket(config.origin.replace('http','ws')+'/transport','agyp.v1');
   try{
    const [raw]=await once(ws,'message');const challenge=JSON.parse(raw.toString());
    const ready=once(ws,'message');ws.send(JSON.stringify({type:'auth',keyId:k.token.slice(5,21),proof:createHmac('sha256',k.token).update('agyp-ws-v1\n'+challenge.salt+'\n'+challenge.nonce).digest('hex')}));assert.equal(JSON.parse((await ready)[0].toString()).type,'ready');
    const closed=once(ws,'close');ws.send(JSON.stringify({type:'start',id:'a'.repeat(32),method:'GET',path:'/api/stats?key_id='+b.key.id,headers:{},deadline:Date.now()+10000}));await closed;

   }finally{if(ws.readyState!==WebSocket.CLOSED){const closed=once(ws,'close');ws.terminate();await closed}}
  }
 }finally{transport.close();server.closeAllConnections();await new Promise<void>(r=>server.close(()=>r()));store.close();rmSync(dir,{recursive:true,force:true})}
});
