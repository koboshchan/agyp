// Server-local Unix socket, never HTTP. Filesystem ownership is the access boundary.
import {createServer,type Socket} from 'node:net';
import {chmodSync,lstatSync,unlinkSync} from 'node:fs';
import {join} from 'node:path';
import {LocalAdmissionDiagnostics} from './diagnostics.js';
export function diagnosticDeadline(value:string|undefined,now=Date.now()){
 if(value===undefined)return undefined;
 if(!/^[0-9]{13}$/.test(value))throw new Error('Invalid diagnostic deadline');
 const until=Number(value);if(until<=now)return undefined;
 if(until-now>600_000)throw new Error('Diagnostic window exceeds ten minutes');
 return until;
}
export async function startDiagnosticControl(dir:string,until:number,now:()=>number=Date.now){
 if(!Number.isSafeInteger(until)||until<=now()||until-now()>600_000)throw new Error('Invalid diagnostic window');
 const parent=lstatSync(dir),uid=process.getuid?.();
 if(uid===undefined||!parent.isDirectory()||parent.isSymbolicLink()||parent.uid!==uid||(parent.mode&0o777)!==0o700)throw new Error('Diagnostic directory must be private and owned');
 const path=join(dir,'admission-diagnostics.sock');
 // Never overwrite any existing filesystem entry, including stale sockets/symlinks.
 try{lstatSync(path);throw new Error('Diagnostic socket path already exists');}catch(e:any){if(e.code!=='ENOENT')throw e;}
 const collector=new LocalAdmissionDiagnostics(now,until),peers=new Set<Socket>();let stopped=false;
 const server=createServer(socket=>{
  if(stopped||now()>=until||peers.size>=2){socket.destroy();return;}
  peers.add(socket);socket.setTimeout(1000,()=>socket.destroy());socket.once('close',()=>peers.delete(socket));socket.on('error',()=>{});
  let command='';socket.on('data',chunk=>{
   if(stopped||now()>=until){socket.destroy();void stop();return;}
   command+=chunk.toString();if(command.length>16){socket.destroy();return;}
   if(!command.endsWith('\n'))return;
   if(command==='snapshot\n')socket.end(JSON.stringify({v:1,records:collector.snapshot()})+'\n');
   else if(command==='stop\n'){collector.stop();socket.end('{"stopped":true}\n',()=>{void stop();});}
   else socket.destroy();
  });
 });
 const sweeper=setInterval(()=>collector.expire(),1000);sweeper.unref();
 const timer=setTimeout(()=>{void stop();},Math.max(1,until-now()));timer.unref();
 async function stop(){
  if(stopped)return;stopped=true;clearTimeout(timer);clearInterval(sweeper);collector.stop();
  for(const socket of peers)socket.destroy();
  await new Promise<void>(resolve=>server.close(()=>resolve()));
  // Cleanup failure must not retain records or crash the application. An inert
  // stale socket is fail-closed: a later activation refuses to overwrite it.
  try{const stat=lstatSync(path);if(stat.isSocket()&&stat.uid===uid)unlinkSync(path);}catch{}
 }
 server.on('error',()=>{collector.stop();void stop();});
 try{
  await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(path,()=>{server.off('error',reject);resolve();});});
  chmodSync(path,0o600);
 }catch(e){await stop();throw e;}
 return {collector,stop,path};
}
