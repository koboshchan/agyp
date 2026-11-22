// A multiplexed transport adapter only. Admission, routing and billing stay in proxy().
import {WebSocketServer,WebSocket} from 'ws';
import type {Server} from 'node:http';
import type {Request,Response} from 'express';
import {Writable} from 'node:stream';
import {createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
import {z} from 'zod';
import {Store,type Key} from './store.js';
import {Pool} from './pool.js';
import {proxy,allowedProxy,boundedKey} from './proxy.js';
import {createBootstrap,allowedBootstrap} from './bootstrap.js';
import {AdmissionError,LocalAdmissionDiagnostics} from './diagnostics.js';

const MAX_BODY=16*1024*1024,MAX_BUFFER=1024*1024;
const id=z.string().regex(/^[a-f0-9]{32}$/);
const headers=z.record(z.string().regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/),z.string().max(8192).refine(v=>!/[\r\n\x00]/.test(v))).refine(h=>Object.keys(h).length<=64&&JSON.stringify(h).length<=32768);
const frames=z.discriminatedUnion('type',[
 z.object({type:z.literal('start'),id,method:z.enum(['POST','GET','HEAD','PUT','PATCH','DELETE','OPTIONS']),path:z.string().max(8192),headers:headers.default({}),deadline:z.number().int().positive()}).strict(),
 z.object({type:z.literal('data'),id,data:z.string().min(4).max(45000).regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/)}).strict(),
 z.object({type:z.literal('end'),id}).strict(),z.object({type:z.literal('cancel'),id}).strict()
]);
const authFrame=z.object({type:z.literal('auth'),keyId:z.string().regex(/^[a-f0-9]{16}$/),proof:z.string().regex(/^[a-f0-9]{64}$/)}).strict();

class SocketResponse extends Writable{
 statusCode=200;headersSent=false;h:Record<string,string>={};
 constructor(private send:(o:unknown,cb:(e?:Error)=>void)=>void,private id:string){super({highWaterMark:65536,autoDestroy:false});this.on('error',()=>{});}
 status(n:number){this.statusCode=n;return this;}
 setHeader(k:string,v:unknown){if(!this.headersSent)this.h[k.toLowerCase()]=String(v);return this;}
 private head(){if(!this.headersSent){this.headersSent=true;this.send({type:'headers',id:this.id,status:this.statusCode,headers:this.h},()=>{});}}
 json(o:unknown){this.setHeader('content-type','application/json');this.end(JSON.stringify(o));return this;}
 _write(chunk:Buffer,_enc:BufferEncoding,cb:(e?:Error|null)=>void){
  this.head();let offset=0;
  const next=(err?:Error)=>{if(err){cb(err);return;}if(offset>=chunk.length){cb();return;}
   const part=chunk.subarray(offset,offset+32768);offset+=part.length;this.send({type:'data',id:this.id,data:part.toString('base64')},next);};next();
 }
 _final(cb:(e?:Error|null)=>void){this.head();this.send({type:'end',id:this.id},cb);}
 _destroy(err:Error|null,cb:(e?:Error|null)=>void){this.send({type:'error',id:this.id,message:'Request interrupted; not replayed'},()=>cb(err));}
}
type Pending={method:string;path:string;headers:Record<string,string>;parts:Buffer[];bytes:number;timer:NodeJS.Timeout;res?:SocketResponse};

export function attachWebSocket(server:Server,store:Store,pool:Pool,bootstrap=createBootstrap(store,pool),diagnostics?:LocalAdmissionDiagnostics){
 const wss=new WebSocketServer({noServer:true,maxPayload:65536,perMessageDeflate:false});
 const jobs=new Set<Promise<unknown>>();let stopping=false;
 let active=0,buffered=0,rateWindow=Date.now(),rateTotal=0;const perKey=new Map<string,number>(),ipRates=new Map<string,number>(),ipConnections=new Map<string,number>();
 server.on('upgrade',(req,socket,head)=>{
  // Rate limits deliberately use the TCP peer, never spoofable forwarding headers.
  if(Date.now()-rateWindow>=60000){rateWindow=Date.now();rateTotal=0;ipRates.clear();}
  const ip=req.socket.remoteAddress??'unknown',rate=(ipRates.get(ip)??0)+1;
  rateTotal++;if(ipRates.has(ip)||ipRates.size<4096)ipRates.set(ip,rate);else{socket.destroy();return;}
  if(stopping||rate>60||rateTotal>1000||(ipConnections.get(ip)??0)>=16){socket.end('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n');return;}
  // CLI-only endpoint. Reject all browser origins, cookies, query credentials and unknown protocols.
  if(req.url!=='/transport'||req.headers.origin||req.headers.cookie||req.headers['sec-websocket-protocol']!=='agyp.v1'||wss.clients.size>=128){socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');return;}
  wss.handleUpgrade(req,socket,head,ws=>{
   ipConnections.set(ip,(ipConnections.get(ip)??0)+1);
   ws.once('close',()=>{const n=(ipConnections.get(ip)??1)-1;if(n>0)ipConnections.set(ip,n);else ipConnections.delete(ip);});
   wss.emit('connection',ws,req);
  });
 });
 wss.on('connection',ws=>{
  const nonce=randomBytes(32).toString('base64url'),salt=randomBytes(32).toString('base64url');
  const authExpires=Date.now()+5000;
  let keyId:string|undefined,alive=true,closed=false,used=0;
  const pending=new Map<string,Pending>(),seen=new Set<string>();
  const send=(o:unknown,cb:(e?:Error)=>void=()=>{})=>{
   if(ws.readyState!==WebSocket.OPEN||ws.bufferedAmount>MAX_BUFFER){cb(new Error('Transport closed'));ws.terminate();return;}
   ws.send(JSON.stringify(o),e=>{cb(e??undefined);if(e)ws.terminate();});
  };
  const remove=(rid:string,destroy=false)=>{const p=pending.get(rid);if(!p)return;clearTimeout(p.timer);
   // Dispatched work stays charged against concurrency/memory until the pipeline settles.
   if(destroy&&p.res){p.res.destroy();return;}
   pending.delete(rid);buffered-=p.bytes;used-=p.bytes;p.parts=[];if(p.res)active--;
  };
  const stop=()=>{if(closed)return;closed=true;clearTimeout(authTimer);clearInterval(heartbeat);for(const rid of pending.keys())remove(rid,true);if(keyId){const remaining=(perKey.get(keyId)??1)-1;if(remaining>0)perKey.set(keyId,remaining);else perKey.delete(keyId);}};
  const authTimer=setTimeout(()=>ws.terminate(),5000);authTimer.unref();
  const heartbeat=setInterval(()=>{
   if(!alive||(keyId&&!store.valid(store.key(keyId)))){ws.terminate();return;}alive=false;ws.ping();
  },15000);heartbeat.unref();
  ws.on('pong',()=>alive=true);ws.on('close',stop);ws.on('error',()=>{ws.terminate();});
  send({type:'challenge',nonce,salt,expires:authExpires});
  ws.on('message',(data,binary)=>{
   try{
    if(closed)return;
    if(binary)throw new Error('Text frames only');
    const msg=JSON.parse(data.toString());
    if(!keyId){
     if(Date.now()>=authExpires)throw new Error('Proof expired');
     const a=authFrame.parse(msg),key=store.key(a.keyId);
     const expected=createHmac('sha256',key?.token??salt).update('agyp-ws-v1\n'+salt+'\n'+nonce).digest();
     if(!timingSafeEqual(expected,Buffer.from(a.proof,'hex'))||!store.valid(key)||(perKey.get(a.keyId)??0)>=4)throw new Error('Invalid proof');
     keyId=a.keyId;perKey.set(keyId,(perKey.get(keyId)??0)+1);clearTimeout(authTimer);send({type:'ready'});return;
    }
    const key=store.key(keyId);if(!store.valid(key))throw new Error('Key expired or revoked');
    const f=frames.parse(msg);
    if(f.type==='start'){
     if(seen.has(f.id)||seen.size>=10000||pending.size>=8||active>=128||(!allowedProxy(f.method,f.path)&&!allowedBootstrap(f.method,f.path))||f.deadline<=Date.now()||f.deadline>Date.now()+600000)throw new Error('Request rejected');
     seen.add(f.id);
     const timer=setTimeout(()=>{send({type:'error',id:f.id,message:'Request deadline exceeded; not replayed'});remove(f.id,true);},Math.min(600000,f.deadline-Date.now()));timer.unref();
     pending.set(f.id,{method:f.method,path:f.path,headers:f.headers,parts:[],bytes:0,timer});return;
    }
    const p=pending.get(f.id);
    // Cancellations can race a completed response. Unknown data/end are protocol errors.
    if(f.type==='cancel'){remove(f.id,true);return;}
    if(!p||p.res)throw new Error('Unknown or dispatched request');
    if(f.type==='data'){
     const b=Buffer.from(f.data,'base64');
     if(!b.length||p.parts.length>=4096||p.bytes+b.length>MAX_BODY||used+b.length>32*1024*1024||buffered+b.length>64*1024*1024)throw new Error('Request body limit');
     p.parts.push(b);p.bytes+=b.length;used+=b.length;buffered+=b.length;return;
    }
    if(active>=128)throw new Error('Concurrency limit');
    const res=new SocketResponse(send,f.id);p.res=res;active++;
    // Mark dispatched before invoking the pipeline. There is no resume/replay protocol.
    const req={method:p.method,originalUrl:p.path,path:new URL(p.path,'http://local').pathname,headers:Object.fromEntries(Object.entries(p.headers).map(([k,v])=>[k.toLowerCase(),v])),body:Buffer.concat(p.parts)} as Request;
    p.parts=[];
    const job=(boundedKey(key as Key)&&allowedBootstrap(req.method,req.originalUrl)?bootstrap(req,res as unknown as Response,key as Key):proxy(req,res as unknown as Response,key as Key,store,pool)).catch((err:any)=>{
     if(!res.headersSent&&!res.destroyed){
      const status=err instanceof z.ZodError?400:[400,401,403,413,422,429].includes(err?.status)?err.status:502;
      const reason=err instanceof AdmissionError?err.reason:allowedBootstrap(req.method,req.originalUrl)&&(err instanceof z.ZodError||err?.status===400)?'invalid_bootstrap':undefined;
      const correlationId=status===400&&reason?diagnostics?.record(req.method,req.originalUrl,req.body,reason):undefined;
      res.status(status).json({error:{message:correlationId?'Request rejected [agyp diagnostic '+correlationId+']':'Request rejected',...(correlationId?{correlationId}:{})}});
     }
     else if(!res.writableEnded)res.destroy();
    }).finally(()=>{remove(f.id);jobs.delete(job);});
    jobs.add(job);
   }catch{ws.close(1008,'Invalid transport message');stop();}
  });
 });
 return {close:async()=>{stopping=true;for(const ws of wss.clients)ws.terminate();await new Promise<void>(resolve=>wss.close(()=>resolve()));await Promise.allSettled([...jobs]);}};
}
