// Real Go CLI + Express/SQLite handshake/accounting, fake Google upstream only.
// Run npx tsx test/cli-e2e.ts.
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createServer,type Server} from 'node:http';
import {spawn} from 'node:child_process';
import {Store} from '../server/store.js';
import {createApp} from '../server/app.js';
import {attachWebSocket} from '../server/ws.js';

async function listen(s:Server){
 await new Promise<void>((r,j)=>{s.once('error',j);s.listen(0,'127.0.0.1',()=>{s.off('error',j);r();});});
 const a=s.address();assert(a&&typeof a==='object');return 'http://127.0.0.1:'+a.port;
}
async function close(s:Server){if(!s.listening)return;s.closeAllConnections();await new Promise<void>((r,j)=>s.close(e=>e?j(e):r()));}
function execute(command:string,args:string[],env=process.env,cwd=process.cwd()){
 return new Promise<string>((resolve,reject)=>{
 const child=spawn(command,args,{env,cwd,stdio:['ignore','pipe','pipe']});
 let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);
 const timer=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('child timeout'));},45000);
 child.on('error',e=>{clearTimeout(timer);reject(e);});
 child.on('close',code=>{clearTimeout(timer);code===0?resolve(stdout):reject(new Error('child failed '+code+': '+stderr));});
 });
}
const dir=await mkdtemp(join(tmpdir(),'agyp-cli-e2e-'));
const store=new Store(join(dir,'data'));
const calls:{path:string;auth:string|undefined;body:string;proxyAuth:unknown}[]=[];
let releaseStream:(()=>void)|undefined;
const upstream=createServer(async(req,res)=>{
 let body='';for await(const chunk of req)body+=chunk;
 calls.push({path:req.url!,auth:req.headers.authorization,body,proxyAuth:req.headers['proxy-authorization']});
 assert.equal(req.headers.authorization,'Bearer fake-google-access');
 assert.equal(req.headers['proxy-authorization'],undefined);
 assert(!body.includes('agyp_'));
 res.writeHead(200,{'content-type':'text/event-stream','x-e2e-upstream':'real-forward'});
 res.write('data: {"response":{"text":"first"}}\n\n');
 // Parent releases the stream only after the CLI child confirms receiving the first event.
 await new Promise<void>(r=>{releaseStream=r;});
 res.end('data: {"response":{"usageMetadata":{"promptTokenCount":12,"candidatesTokenCount":4,"cachedContentTokenCount":3,"totalTokenCount":16}}}\n\ndata: [DONE]\n\n');
});
const direct=createServer((req,res)=>{
 assert.equal(req.headers.authorization,undefined);
 assert.equal(req.headers['proxy-authorization'],undefined);
 assert.equal(req.headers.cookie,undefined);
 res.end('direct-ok');
});
let server:Server|undefined,transport:ReturnType<typeof attachWebSocket>|undefined;
let releaseTimer:ReturnType<typeof setInterval>|undefined;
try {
 const binary=join(dir,'agyp');
 await execute('go',['build','-o',binary,'.'],process.env,resolve('cli'));
 const upstreamURL=await listen(upstream),directURL=await listen(direct);
 store.putAccount({id:'fake',email:'fake@example.invalid',refresh_token:'fake-refresh',access_token:'fake-google-access',token_expiry:Date.now()+1e6,status:'ready',shared:false,blocked:false,buckets:[{family:'argon',label:'Argon',remaining:1,reset:0}],cooldowns:{},denied:{},updated:Date.now()});
 const normal=store.createKey({name:'CLI integration normal',allowance:10000});
 assert.equal(normal.key.admin,0);
 const config={origin:'',upstream:upstreamURL,clientId:'',clientSecret:'',secure:false};
 const {app,pool,bootstrap}=createApp(store,config);
 // A separate test-only listener confirms first-chunk delivery before allowing upstream completion.
 let gotFirst=false;
 const observer=createServer((_req,res)=>{gotFirst=true;res.end('ok');});
 try{
 const observerURL=await listen(observer);
 server=createServer(app);transport=attachWebSocket(server,store,pool,bootstrap);config.origin=await listen(server);
 const child=String.raw`
 const assert=require('node:assert/strict'),http=require('node:http');
 (async()=>{
 assert.equal(process.env.AGYP_TOKEN,undefined);
 const cloud=new URL(process.env.CLOUD_CODE_URL),proxy=new URL(process.env.HTTP_PROXY);
 assert.match(cloud.pathname,/^\/[A-Za-z0-9_-]{43}$/);
 assert.equal(proxy.username,'agyp');assert.equal(proxy.password,cloud.pathname.slice(1));
 assert.equal(process.env.HTTPS_PROXY,process.env.HTTP_PROXY);
 const body=JSON.stringify({model:'gemini-4-argon-trial',request:{contents:[{parts:[{text:'hello'}]}],generationConfig:{maxOutputTokens:20}}});
 const denied=await fetch(cloud.origin+'/api/keys');assert.equal(denied.status,403);
 const admin=await fetch(cloud.href+'/api/keys');assert.equal(admin.status,403);
 const stream=await fetch(cloud.href+'/v1internal:streamGenerateContent?alt=sse',{method:'POST',headers:{'content-type':'application/json'},body});
 assert.equal(stream.status,200);assert.equal(stream.headers.get('x-e2e-upstream'),'real-forward');
 const reader=stream.body.getReader(),first=await reader.read();assert(!first.done);let text=Buffer.from(first.value).toString();
 assert(text.includes('first'));assert(!text.includes('[DONE]'));
 await fetch(process.env.TEST_OBSERVER);
 for(;;){const c=await reader.read();if(c.done)break;text+=Buffer.from(c.value).toString();}
 assert(text.includes('[DONE]'));
 const auth='Basic '+Buffer.from(decodeURIComponent(proxy.username)+':'+decodeURIComponent(proxy.password)).toString('base64');
 async function through(target,credential){return await new Promise((resolve,reject)=>{
 const req=http.request({hostname:proxy.hostname,port:proxy.port,path:target,method:'GET',headers:{...(credential?{'Proxy-Authorization':credential}:{}),Authorization:'Bearer must-not-leak',Cookie:'must-not-leak'}},res=>{
 let out='';res.on('data',b=>out+=b);res.on('end',()=>resolve({status:res.statusCode,body:out}));});req.on('error',reject);req.end();});}
 assert.equal((await through(process.env.TEST_DIRECT)).status,407);
 const forwarded=await through(process.env.TEST_DIRECT,auth);assert.equal(forwarded.status,200);assert.equal(forwarded.body,'direct-ok');
 console.log('child-pass');
 })().catch(e=>{console.error(e);process.exitCode=1;});
 `;
 releaseTimer=setInterval(()=>{if(gotFirst&&releaseStream){releaseStream();releaseStream=undefined;}},5);
 const output=await execute(binary,['--',process.execPath,'-e',child],{...process.env,AGYP_BASE:config.origin,AGYP_TOKEN:normal.token,TEST_DIRECT:directURL,TEST_OBSERVER:observerURL});
 assert.match(output,/child-pass/);
 }finally{await close(observer);}
 // Accounting finishes asynchronously when the response stream closes.
 for(let i=0;i<100&&store.used(normal.key).total!==16;i++)await new Promise(r=>setTimeout(r,10));
 assert.equal(calls.length,1);assert.equal(calls[0].path,'/v1internal:streamGenerateContent?alt=sse');
 const stats=store.stats(normal.key.id).models as any[];
 assert.equal(stats.length,1);assert.equal(stats[0].key_id,normal.key.id);
 assert.equal(stats[0].input,12);assert.equal(stats[0].output,4);assert.equal(stats[0].cached,3);assert.equal(stats[0].total,16);
 assert.equal(store.used(normal.key).total,16);
 assert.equal((store.db.prepare('SELECT COUNT(*) AS n FROM sessions WHERE key_id=?').get(normal.key.id) as any).n,0);
 assert.equal((store.db.prepare('SELECT COUNT(*) AS n FROM challenges').get() as any).n,0);
 console.log('PASS real Go CLI + createApp/Store: normal-key HMAC handshake, consumed nonce, capability/admin boundary, streamed first chunk before completion, usage 12 input/4 output/3 cached/16 total, authenticated HTTP proxy, credential stripping');
}finally{
 if(releaseTimer)clearInterval(releaseTimer);releaseStream?.();
 await transport?.close();if(server)await close(server);await close(upstream);await close(direct);store.close();await rm(dir,{recursive:true,force:true});
}
