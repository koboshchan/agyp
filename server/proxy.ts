import type {Request,Response} from 'express';
import {createParser} from 'eventsource-parser';
import {Pool} from './pool.js';
import {Store,type Key,type Usage} from './store.js';
import {once} from 'node:events';

const strip=new Set(['host','authorization','proxy-authorization','cookie','connection','keep-alive','transfer-encoding','te','trailer','upgrade','content-length','accept-encoding','forwarded','x-forwarded-for','x-forwarded-proto','x-forwarded-host','x-csrf-token','set-cookie']);
export function allowedProxy(method:string,path:string){
 const p=new URL(path,'http://local').pathname;
 return (method==='POST'&&/^\/v1internal:(generateContent|streamGenerateContent|countTokens|fetchAvailableModels)$/.test(p))
 ||(method==='POST'&&/^\/v1(?:beta)?\/models\/[^/:]+:(generateContent|streamGenerateContent|countTokens)$/.test(p))
 ||(method==='GET'&&/^\/v1(?:beta)?\/models(?:\/[^/:]+)?$/.test(p));
}
export function hasMedia(value:any):boolean{
 if(!value||typeof value!=='object')return false;
 return Object.entries(value).some(([key,v])=>['inlineData','fileData','inline_data','file_data','cachedContent','cached_content'].includes(key)||hasMedia(v));
}
export function extractModel(path:string,body:any){
 const byPath=/\/models\/([^/:?]+)/.exec(path)?.[1];
 const byBody=typeof body?.model==='string'?body.model:undefined;
 const byQuery=new URL(path,'http://local').searchParams.get('model')??undefined;
 const models=[byBody,byPath&&decodeURIComponent(byPath),byQuery].filter(Boolean) as string[];
 if(new Set(models).size>1)throw Object.assign(new Error('Conflicting model identifiers'),{status:400});
 return models[0]??'';
}
export function usageOf(data:any):Usage|undefined{
 const m=data?.usageMetadata??data?.response?.usageMetadata;if(!m)return;
 const num=(n:any)=>Number.isSafeInteger(n)&&n>=0?n:0;
 const input=num(m.promptTokenCount),output=num(m.candidatesTokenCount)+num(m.thoughtsTokenCount),cached=Math.min(input,num(m.cachedContentTokenCount));
 return {input,output,cached,total:Math.max(input+output,num(m.totalTokenCount))};
}
export class UsageReader {
 value:Usage|undefined; json=''; bytes=0;decoder=new TextDecoder();parser;
 constructor(public sse:boolean){this.parser=createParser({onEvent:e=>{if(e.data==='[DONE]')return;try{this.observe(JSON.parse(e.data));}catch{}}});}
 observe(o:any){if(Array.isArray(o)){for(const item of o)this.observe(item);return;}const u=usageOf(o);if(u){if(!this.value)this.value=u;else for(const k of ['input','output','cached','total'] as const)this.value[k]=Math.max(this.value[k],u[k]);}}
 feed(b:Uint8Array){const s=this.decoder.decode(b,{stream:true});if(this.sse)this.parser.feed(s);else{this.bytes+=b.length;if(this.bytes<=8_388_608)this.json+=s;}}
 end(){const s=this.decoder.decode();if(this.sse)this.parser.feed(s);else{this.json+=s;try{this.observe(JSON.parse(this.json));}catch{}}}
}
export async function proxy(req:Request,res:Response,key:Key,store:Store,pool:Pool){
 if(!allowedProxy(req.method,req.originalUrl))throw Object.assign(new Error('Upstream action not allowed'),{status:403});
 const raw=Buffer.isBuffer(req.body)?req.body:Buffer.alloc(0);let body:any={};if(raw.length){try{body=JSON.parse(raw.toString());}catch{throw Object.assign(new Error('Expected JSON body'),{status:400});}}
 const model=extractModel(req.originalUrl,body);
 const generation=/:streamGenerateContent|:generateContent/.test(req.path);
 if(generation&&!model)throw Object.assign(new Error('Model is required'),{status:400});
 // Reserve a conservative upper bound before starting. byte length bounds text tokens;
 // multimodal bounded keys require countTokens first (arbitrary media has no byte bound).
 const bounded=key.allowance!==null||key.inputCap!==null||key.outputCap!==null;
 if(generation&&bounded&&hasMedia(body))throw Object.assign(new Error('Media requests require an unlimited key; text allowances cannot safely bound media tokens'),{status:422});
 const gc=body?.request?.generationConfig??body?.generationConfig??{};
 if(generation&&bounded&&((gc.candidateCount??1)!==1||(gc.candidate_count??1)!==1))throw Object.assign(new Error('Bounded keys require one candidate'),{status:422});
 const maxOutput=body?.request?.generationConfig?.maxOutputTokens??body?.generationConfig?.maxOutputTokens??65536;
 if(generation&&(!Number.isSafeInteger(maxOutput)||maxOutput<1||maxOutput>131072))throw Object.assign(new Error('maxOutputTokens must be 1..131072'),{status:400});
 if(generation&&bounded&&(gc.thinkingConfig?.thinkingBudget??gc.thinking_config?.thinking_budget??0)>maxOutput)throw Object.assign(new Error('Thinking budget exceeds reserved output'),{status:422});
 const input=generation?raw.length+1024:0,output=generation?maxOutput:0;
 const reservation=store.reserve(key,model||'(control)',input,output);
 let final:Usage|undefined,status=502,started=false;
 const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),600_000);
 res.on('close',()=>{if(!res.writableEnded)abort.abort();});
 try{
  const tried=new Set<string>();let lastText='No eligible account for requested model',lastStatus=503;
  while(tried.size<50){
   const account=pool.select(model,tried);if(!account)break;tried.add(account.id);
   let token:string;try{token=await pool.access(account.id);}catch{continue;}
   const headers=new Headers();const connection=(req.headers.connection??'').split(',').map(h=>h.trim().toLowerCase());
   for(const [name,val] of Object.entries(req.headers))if(!strip.has(name)&&!connection.includes(name)&&!name.startsWith('x-forwarded-')&&val!==undefined)headers.set(name,Array.isArray(val)?val.join(', '):val);
   headers.set('authorization','Bearer '+token);headers.set('accept-encoding','identity');
   const url=new URL(pool.base);url.pathname=req.path;url.search=new URL(req.originalUrl,'http://local').search;
   const upstream=await fetch(url,{method:req.method,headers,body:['GET','HEAD'].includes(req.method)?undefined:new Uint8Array(raw),redirect:'error',signal:abort.signal});
   if([401,403,429].includes(upstream.status)){
    // Error bodies are bounded; never forward account credentials or quota internals.
    const text=(await readBounded(upstream,1_048_576)).toString();lastText=text;lastStatus=upstream.status;
    if(pool.failed(account.id,model,upstream.status,text))continue;
    status=upstream.status;res.status(status);res.setHeader('content-type','application/json');res.end(JSON.stringify({error:{message:'Upstream request rejected',code:status}}));final={input:0,output:0,cached:0,total:0};return;
   }
   status=upstream.status;res.status(status);
   const responseConnection=(upstream.headers.get('connection')??'').split(',').map(x=>x.trim());
   for(const [name,value]of upstream.headers)if(!strip.has(name)&&!responseConnection.includes(name)&&!['content-encoding','content-security-policy','strict-transport-security','x-frame-options'].includes(name))res.setHeader(name,value);
   res.setHeader('x-accel-buffering','no');
   const reader=new UsageReader((upstream.headers.get('content-type')??'').includes('text/event-stream'));started=true;
   try{if(upstream.body)for await(const chunk of upstream.body){reader.feed(chunk);if(!res.write(chunk))await Promise.race([once(res,'drain'),once(res,'close').then(()=>{throw new Error('Client disconnected');})]);}
   reader.end();final=reader.value;
   if(!generation||status>=400)final??={input:0,output:0,cached:0,total:0};
   res.end();return;
   }finally{reader.end();final??=reader.value;}
  }
  status=lastStatus;
  // Do not forward Google error strings that may contain account details.
  res.status(status===403?429:status).json({error:{code:status===403?429:status,message:tried.size?'No eligible account remains for the exact requested model':'No eligible account for the exact requested model'}});
  final={input:0,output:0,cached:0,total:0};
 }catch(e){if(!started&&!abort.signal.aborted){res.status(502).json({error:{message:'Upstream connection failed'}});}else if(!res.writableEnded)res.destroy();}
 finally{clearTimeout(timer);
  // Missing usage after a generation may have spent tokens. Charge its reservation, not zero.
  store.finish(reservation,final??{input,output,cached:0,total:input+output},status);
 }
}
async function readBounded(r:globalThis.Response,max:number){const chunks:Uint8Array[]=[];let n=0;if(r.body)for await(const c of r.body){n+=c.length;if(n>max){await r.body.cancel().catch(()=>{});break;}chunks.push(c);}return Buffer.concat(chunks);}
