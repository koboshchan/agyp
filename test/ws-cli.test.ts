import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer,type Server} from 'node:http';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {Store} from '../server/store.js';
import {createApp} from '../server/app.js';
import {attachWebSocket} from '../server/ws.js';
async function listen(s:Server){await new Promise<void>(r=>s.listen(0,'127.0.0.1',r));return 'http://127.0.0.1:'+(s.address() as any).port;}
async function close(s:Server){s.closeAllConnections();await new Promise<void>(r=>s.close(()=>r()));}
test('native Go websocket client interoperates with real Node adapter, concurrent streaming and billing',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-ws-cli-')),store=new Store(dir);let calls=0,connections=0;
 const raw='{ "model":"gemini-flash", "request":{"contents":[{"parts":[{"text":"雪"}]}]}, "n":1e+05 }';
 const upstream=createServer(async(req,res)=>{if(req.url==='/v1internal:loadCodeAssist'){res.end(JSON.stringify({currentTier:{id:'premium-tier',name:'Pro',description:'private'},cloudaicompanionProject:'private'}));return;}calls++;let body='';for await(const c of req)body+=c;if(req.method==='POST')assert.equal(body,raw);res.setHeader('content-type','text/event-stream');res.write('data: {"response":{"text":"OK"}}\n\n');setTimeout(()=>res.end('data: {"response":{"usageMetadata":{"promptTokenCount":2,"candidatesTokenCount":1,"totalTokenCount":3}}}\n\n'),20);});
 const config={origin:'',upstream:await listen(upstream),clientId:'',clientSecret:'',secure:false}, {app,pool}=createApp(store,config),server=createServer(app);server.on('upgrade',()=>connections++);const transport=attachWebSocket(server,store,pool);config.origin=await listen(server);
 store.putAccount({id:'a',email:'fake@example.invalid',refresh_token:'fake',access_token:'fake',token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets:[{family:'gemini',label:'Gemini',remaining:1,reset:0}],cooldowns:{},denied:{},updated:Date.now()});
 const key=store.createKey({name:'fixture'});
 try{
  const proc=spawn('go',['test','-race','-run','^TestWSNodeIntegration$','-count=1','.'],{cwd:join(process.cwd(),'cli'),env:{...process.env,AGYP_WS_TEST_BASE:config.origin,AGYP_WS_TEST_KEY:key.token},stdio:['ignore','pipe','pipe']});
  let output='';proc.stdout.on('data',c=>output+=c);proc.stderr.on('data',c=>output+=c);
  const code=await new Promise<number|null>((resolve,reject)=>{proc.on('error',reject);proc.on('close',resolve);});
  assert.equal(code,0,output);assert.equal(connections,1);assert.equal(calls,5);assert.equal(store.used(key.key).total,15);
  assert.equal((store.db.prepare('SELECT COUNT(*) n FROM sessions').get() as any).n,0);
  assert.equal((store.db.prepare('SELECT COUNT(*) n FROM reservations').get() as any).n,0);
 }finally{await transport.close();await close(server);await close(upstream);store.close();rmSync(dir,{recursive:true,force:true});}
});
