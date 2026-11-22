// Narrow, read-only CLI eligibility capability. Not a generic CloudCode proxy.
import {z} from 'zod';
import type {Request,Response} from 'express';
import {Store,type Key} from './store.js';
import {Pool,UA} from './pool.js';
const PATH='/v1internal:loadCodeAssist';
const requestSchema=z.object({metadata:z.object({ideType:z.literal('ANTIGRAVITY')}).strict()}).strict();
const tier=z.object({id:z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),name:z.string().max(100).regex(/^[A-Za-z0-9 ()+._-]*$/).optional()});
export function allowedBootstrap(method:string,path:string){return method==='POST'&&path===PATH;}
export function createBootstrap(store:Store,pool:Pool){
 let inflight=0,window=Date.now(),total=0;const rates=new Map<string,number>();
 return async function bootstrap(req:Request,res:Response,key:Key){
  if(!allowedBootstrap(req.method,req.originalUrl))throw Object.assign(new Error('Bootstrap endpoint forbidden'),{status:403});
  if(!store.valid(store.key(key.id)))throw Object.assign(new Error('Key expired or revoked'),{status:401});
  const raw=Buffer.isBuffer(req.body)?req.body:Buffer.alloc(0);
  if(raw.length>1024)throw Object.assign(new Error('Bootstrap body too large'),{status:413});
  let value;try{value=JSON.parse(raw.toString());}catch{throw Object.assign(new Error('Expected JSON object'),{status:400});}
  requestSchema.parse(value);
  if(Date.now()-window>=60000){window=Date.now();total=0;rates.clear();}
  const count=(rates.get(key.id)??0)+1;
  if(!rates.has(key.id)&&rates.size>=4096)throw Object.assign(new Error('Bootstrap busy'),{status:429});
  rates.set(key.id,count);total++;
  if(count>30||total>300||inflight>=8)throw Object.assign(new Error('Bootstrap rate limit'),{status:429});
  const account=store.accounts().find(a=>pool.eligible(a,''));
  if(!account)throw Object.assign(new Error('No eligible account'),{status:503});
  const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),15000);
  const disconnect=()=>{if(!res.writableEnded)abort.abort();};res.on('close',disconnect);inflight++;
  try{
   const token=await abortable(pool.access(account.id),abort.signal);
   if(abort.signal.aborted||res.destroyed)return;
   if(!store.valid(store.key(key.id)))throw Object.assign(new Error('Key expired or revoked'),{status:401});
   const current=store.accounts().find(a=>a.id===account.id);
   if(!current||!pool.eligible(current,''))throw Object.assign(new Error('Account no longer eligible'),{status:503});
   const url=new URL(pool.base);url.pathname=PATH;url.search='';url.hash='';
   const upstream=await fetch(url,{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json','user-agent':UA},body:'{"metadata":{"ideType":"ANTIGRAVITY"}}',redirect:'error',signal:abort.signal});
   const chunks:Uint8Array[]=[];let size=0;
   if(upstream.body)for await(const chunk of upstream.body){size+=chunk.length;if(size>65536)throw new Error('Bootstrap response too large');chunks.push(chunk);}
   if(!upstream.ok){res.status([401,403,429].includes(upstream.status)?upstream.status:502).json({error:{message:'Eligibility check unavailable'}});return;}
   const body=JSON.parse(Buffer.concat(chunks).toString());
   const out:{currentTier?:z.infer<typeof tier>;paidTier?:z.infer<typeof tier>;allowedTiers?:Array<z.infer<typeof tier>&{isDefault?:boolean}>}={};
   if(body.currentTier!==undefined)out.currentTier=tier.parse(body.currentTier);
   if(body.paidTier!==undefined)out.paidTier=tier.parse(body.paidTier);
   if(body.allowedTiers!==undefined)out.allowedTiers=z.array(tier.extend({isDefault:z.boolean().optional()})).max(16).parse(body.allowedTiers);
   if(!out.currentTier&&!out.paidTier&&!out.allowedTiers?.length)throw new Error('Missing eligibility');
   if(!store.valid(store.key(key.id)))throw Object.assign(new Error('Key expired or revoked'),{status:401});
   // Never expose project IDs, account details, credits, links or arbitrary Google fields.
   res.status(200).json(out);
  }finally{clearTimeout(timer);res.off('close',disconnect);inflight--;}
 };
}
// OAuth refresh is shared pool work and cannot be aborted by one CLI request.
// Bound this caller's wait without leaving a listener or an unhandled rejection.
async function abortable<T>(work:Promise<T>,signal:AbortSignal):Promise<T>{
 let listener:()=>void=()=>{};
 const canceled=new Promise<never>((_resolve,reject)=>{listener=()=>reject(new Error('Eligibility request canceled'));if(signal.aborted)listener();else signal.addEventListener('abort',listener,{once:true});});
 try{return await Promise.race([work,canceled]);}finally{signal.removeEventListener('abort',listener);}
}
