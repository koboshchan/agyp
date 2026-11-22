// Server-local, same-UID/root operator only. No HTTP route or credential needed.
import {connect} from 'node:net';
import {resolve,join} from 'node:path';
import {lstatSync} from 'node:fs';
const command=process.argv[2];
if(!['snapshot','stop'].includes(command)||process.argv.length!==3)throw new Error('Expected snapshot or stop');
const dir=resolve(process.env.DATA_DIR??'./data'),path=join(dir,'admission-diagnostics.sock');
const parent=lstatSync(dir),socket=lstatSync(path),uid=process.getuid?.();
if(!parent.isDirectory()||parent.isSymbolicLink()||(parent.mode&0o777)!==0o700||!socket.isSocket()||(socket.mode&0o777)!==0o600||!([0,parent.uid].includes(uid))||socket.uid!==parent.uid)throw new Error('Unsafe diagnostic socket');
const client=connect(path);let bytes=0,output='';
client.setTimeout(2000,()=>client.destroy(new Error('Diagnostic timeout')));
client.on('connect',()=>client.write(command+'\n'));
client.on('data',chunk=>{bytes+=chunk.length;if(bytes>270000){client.destroy(new Error('Diagnostic response limit'));return;}output+=chunk.toString();});
let completed=false;
client.on('end',()=>{try{JSON.parse(output);completed=true;process.stdout.write(output);}catch{process.exitCode=1;}});
client.on('close',()=>{if(!completed)process.exitCode=1;});
client.on('error',()=>{process.stderr.write('Diagnostic control unavailable\n');process.exitCode=1;});
