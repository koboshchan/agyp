import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,lstatSync,chmodSync,existsSync,symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {connect,createServer} from 'node:net';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {LocalAdmissionDiagnostics} from '../server/diagnostics.js';
import {diagnosticDeadline,startDiagnosticControl} from '../server/diagnostic-control.js';
function exchange(path:string,command:string){return new Promise<string>((resolve,reject)=>{const socket=connect(path);let out='';socket.setTimeout(2000,()=>socket.destroy(new Error('test timeout')));socket.on('connect',()=>socket.write(command));socket.on('data',b=>out+=b);socket.on('end',()=>resolve(out));socket.on('error',reject);});}
async function helper(dir:string,command:string,uid?:number){
 const child=spawn(process.execPath,['scripts/admission-diagnostics.mjs',command],{env:{...process.env,DATA_DIR:dir},...(uid!==undefined?{uid,gid:uid}:{})});let output='';child.stdout.on('data',b=>output+=b);child.stderr.resume();const [code]=await once(child,'close');return {code,output};
}
test('diagnostics deadline is default-off, absolute, bounded and never rearmed by restart',()=>{
 const now=1800000000000;assert.equal(diagnosticDeadline(undefined,now),undefined);assert.equal(diagnosticDeadline(String(now),now),undefined);assert.equal(diagnosticDeadline(String(now+600000),now),now+600000);assert.equal(diagnosticDeadline(String(now+1),now+2),undefined);
 for(const v of ['1','CANARY',String(now+600001),'-1800000000000'])assert.throws(()=>diagnosticDeadline(v,now));
});
test('record retention, irreversible stop and absolute auto-expiry cannot emit correlation IDs',()=>{
 let now=100;const d=new LocalAdmissionDiagnostics(()=>now,300000);d.record('POST','/v1internal:generateContent',Buffer.from('{"model":"CANARY"}'),'missing_request');assert.equal(d.snapshot().length,1);now+=120001;assert.equal(d.snapshot().length,0);
 assert(d.record('POST','/v1internal:generateContent',Buffer.from('{}'),'missing_model'));now=300000;assert.equal(d.snapshot().length,0);assert.equal(d.record('POST','/v1internal:generateContent',Buffer.from('{}'),'missing_model'),undefined);
 const capped=new LocalAdmissionDiagnostics();let sampled=0;for(let i=0;i<100;i++)if(capped.record('POST','/',Buffer.from('{}'),'missing_model'))sampled++;assert.equal(sampled,64);assert.equal(capped.snapshot().length,32);
 const stopped=new LocalAdmissionDiagnostics();stopped.stop();assert.equal(stopped.record('POST','/',Buffer.from('{}'),'missing_model'),undefined);
});
test('server-local control has owner-only access, helper, canaries, expiry and cleanup',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-control-'));chmodSync(dir,0o700);let now=Date.now();const c=await startDiagnosticControl(dir,now+600000,()=>now);
 try{
  assert.equal(lstatSync(c.path).mode&0o777,0o600);assert.equal(lstatSync(dir).mode&0o777,0o700);
  c.collector.record('POST','/v1internal:generateContent?CANARY_QUERY',Buffer.from('{"model":"CANARY_VALUE","CANARY_KEY":"CANARY"}'),'missing_request');
  const result=await helper(dir,'snapshot');assert.equal(result.code,0);assert.doesNotMatch(result.output,/CANARY/);const records=JSON.parse(result.output).records;assert.equal(records.length,1);assert.equal(records[0].source,'proxy_admission');
  if(process.getuid?.()===0){const denied=await helper(dir,'snapshot',65534);assert.notEqual(denied.code,0);assert.equal(denied.output,'');}
  const invalid=await helper(dir,'CANARY_COMMAND');assert.notEqual(invalid.code,0);assert.equal(invalid.output,'');
  assert.equal(await exchange(c.path,'CANARY\n'),'');
  now+=120001;assert.deepEqual(JSON.parse(await exchange(c.path,'snapshot\n')).records,[]);
  c.collector.record('GET','/v1internal:countTokens',Buffer.from('{}'),'missing_model');
  const stop=await helper(dir,'stop');assert.equal(stop.code,0);assert.equal(JSON.parse(stop.output).stopped,true);assert.deepEqual(c.collector.snapshot(),[]);assert.equal(c.collector.record('GET','/',Buffer.from('{}'),'missing_model'),undefined);
 }finally{await c.stop();rmSync(dir,{recursive:true,force:true});}
});
test('unsafe access paths and auto-expiring control fail closed',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-control-expiry-'));chmodSync(dir,0o755);const path=join(dir,'admission-diagnostics.sock');
 try{
  await assert.rejects(startDiagnosticControl(dir,Date.now()+1000));chmodSync(dir,0o700);
  symlinkSync('/nonexistent',path);await assert.rejects(startDiagnosticControl(dir,Date.now()+1000));assert(lstatSync(path).isSymbolicLink());rmSync(path);
  const c=await startDiagnosticControl(dir,Date.now()+60);
  c.collector.record('POST','/',Buffer.from('{}'),'missing_model');
  // Event-driven close condition, no polling. Deadline is driven by a real timer.
  await new Promise<void>(resolve=>{const socket=connect(c.path);socket.on('connect',()=>{});socket.on('close',()=>resolve());socket.on('error',()=>{});});
  assert.deepEqual(c.collector.snapshot(),[]);assert.equal(existsSync(path),false);await c.stop();
 }finally{rmSync(dir,{recursive:true,force:true});}
});
async function mainFixture(dir:string,until?:string){
 const reservation=createServer();await new Promise<void>(r=>reservation.listen(0,'127.0.0.1',r));const port=(reservation.address() as any).port;await new Promise<void>(r=>reservation.close(()=>r()));
 const env:NodeJS.ProcessEnv={...process.env,DATA_DIR:dir,PORT:String(port),DISABLE_POLLER:'1'};delete env.AGYP_ADMISSION_DIAGNOSTICS_UNTIL;if(until!==undefined)env.AGYP_ADMISSION_DIAGNOSTICS_UNTIL=until;
 const child=spawn(process.execPath,['--import','tsx','server/main.ts'],{env});child.stderr.resume();
 await new Promise<void>((resolve,reject)=>{const timeout=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('server start timeout'));},5000);child.once('exit',()=>{clearTimeout(timeout);reject(new Error('server startup failed'));});child.stdout.on('data',b=>{if(b.toString().includes('agyp listening')){clearTimeout(timeout);resolve();}});});
 return Object.assign(child,{base:'http://127.0.0.1:'+port});
}
test('actual server default-off exposes no HTTP diagnostic route or socket',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-main-off-'));const child=await mainFixture(dir);try{
  assert.equal(existsSync(join(dir,'admission-diagnostics.sock')),false);
  const response=await fetch(child.base+'/api/admission-diagnostics');assert.equal(response.status,401);
 }finally{const done=once(child,'close');child.kill('SIGTERM');const [code]=await done;assert.equal(code,0);rmSync(dir,{recursive:true,force:true});}
});
test('actual enabled server shutdown clears records and removes socket',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'agyp-main-on-'));const child=await mainFixture(dir,String(Date.now()+30000));try{
  const path=join(dir,'admission-diagnostics.sock');assert.equal(lstatSync(path).mode&0o777,0o600);assert.deepEqual(JSON.parse(await exchange(path,'snapshot\n')).records,[]);
 }finally{const done=once(child,'close');child.kill('SIGTERM');const [code]=await done;assert.equal(code,0);assert.equal(existsSync(join(dir,'admission-diagnostics.sock')),false);rmSync(dir,{recursive:true,force:true});}
});
