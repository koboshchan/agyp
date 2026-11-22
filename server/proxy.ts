import {parse as parseLossless,isLosslessNumber,compareNumber} from 'lossless-json';
import type {Request,Response} from 'express';
import {createParser} from 'eventsource-parser';
import {Pool,family} from './pool.js';
import {rewriteModel,rewriteURLModel,repairSignatures,signatureError} from './replay.js';
import {Store,type Key,type Usage} from './store.js';
import {once} from 'node:events';
import {abortable} from './bootstrap.js';
import {admissionError} from './diagnostics.js';

const strip=new Set(['host','authorization','proxy-authorization','cookie','connection','keep-alive','transfer-encoding','te','trailer','upgrade','content-length','accept-encoding','forwarded','x-forwarded-for','x-forwarded-proto','x-forwarded-host','x-csrf-token','set-cookie','x-goog-api-key','x-client-secret']);
// The switcher handler forwards the request method/path without an RPC allowlist
// (internal/proxy/handler.go ServeHTTP, request construction). Expose the Cloud
// Code service namespace, not its arbitrary-host forward proxy or admin services.
const methods=new Set(['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS']);
const deniedService=/admin|credential|oauth|accessToken|refreshToken|apiKey|secret|iam|permission|serviceAccount|(?:create|delete|update|list|get)Accounts?/i;
export function allowedProxy(method:string,path:string){
 if(!methods.has(method)||path.length>8192||!path.startsWith('/')||path.startsWith('//')||/[\\\r\n\x00#]/.test(path))return false;
 const p=path.split('?')[0];
 // No URL normalization, encoded separators, dot segments or ambiguous path forms.
 if(p.includes('%')||p.includes('//')||p.split('/').some(v=>v==='.'||v==='..')||deniedService.test(p))return false;
 if(/^\/v1internal(?=[:/])[:/][A-Za-z][A-Za-z0-9_:/.-]*$/.test(p))return true;
 return (method==='POST'&&/^\/v1(?:beta)?\/models\/[A-Za-z0-9._-]+:(generateContent|streamGenerateContent|countTokens)$/.test(p))
 ||(method==='GET'&&/^\/v1(?:beta)?\/models(?:\/[A-Za-z0-9._-]+)?$/.test(p));
}
const boundedControls=new Set(['fetchAvailableModels','retrieveUserQuota','retrieveUserQuotaSummary','listExperiments','fetchUserInfo','recordCodeAssistMetrics','countTokens']);
export function boundedControl(method:string,path:string){
 const p=path.split('?')[0];
 return method==='POST'&&(boundedControls.has(p.replace(/^\/v1internal:/,''))||/^\/v1(?:beta)?\/models\/[A-Za-z0-9._-]+:countTokens$/.test(p))
 ||method==='GET'&&(p==='/v1internal/cascadeNuxes'||/^\/v1(?:beta)?\/models(?:\/[A-Za-z0-9._-]+)?$/.test(p));
}
export function boundedKey(key:Key){return key.allowance!==null||key.inputCap!==null||key.outputCap!==null;}
export function hasMedia(value:any):boolean{
 if(!value||typeof value!=='object')return false;
 return Object.entries(value).some(([key,v])=>['inlineData','fileData','inline_data','file_data','cachedContent','cached_content'].includes(key)||hasMedia(v));
}
export function extractModel(path:string,body:any){
 const byPath=/\/models\/([^/:?]+)/.exec(path)?.[1];
 const byBody=typeof body?.model==='string'?body.model:undefined;
 const byQuery=new URL(path,'http://local').searchParams.get('model')??undefined;
 const models=[byBody,byPath&&decodeURIComponent(byPath),byQuery].filter(Boolean) as string[];
 if(new Set(models).size>1)throw admissionError('model_conflict','Conflicting model identifiers');
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
 const generation=req.method==='POST'&&/:(?:streamGenerateContent|generateContent)$/.test(req.path);
 const raw=Buffer.isBuffer(req.body)?req.body:Buffer.alloc(0);let body:any={};
 if(raw.length){try{body=JSON.parse(raw.toString());}catch{if(generation)throw admissionError('invalid_json','Expected JSON body');}}
 if(!body||typeof body!=='object'||Array.isArray(body)){if(generation)throw admissionError('invalid_root','Expected JSON object');body={};}
 const model=extractModel(req.originalUrl,body);
 if(generation&&!model)throw admissionError('missing_model','Model is required');
 // Reserve a conservative upper bound before starting. byte length bounds text tokens;
 // multimodal bounded keys require countTokens first (arbitrary media has no byte bound).
 const bounded=boundedKey(key);
 if(bounded&&!generation&&!boundedControl(req.method,req.originalUrl))throw Object.assign(new Error('Unknown Cloud Code action requires an unlimited key'),{status:422});
 if(generation&&bounded&&hasMedia(body))throw Object.assign(new Error('Media requests require an unlimited key; text allowances cannot safely bound media tokens'),{status:422});
 const internal=req.path.startsWith('/v1internal:');
 if(generation&&internal&&(!body.request||typeof body.request!=='object'||Array.isArray(body.request)))throw admissionError('missing_request','Internal generation requires request envelope');
 if(generation&&internal&&(body.generationConfig!==undefined||body.generation_config!==undefined))throw admissionError('mixed_envelope','Mixed generation envelopes are not allowed');
 if(generation&&!internal&&body.request!==undefined)throw admissionError('nested_envelope','Unexpected nested request envelope');
 const target=internal?body.request:body;
 if(generation&&(target.generation_config!==undefined||target.generationConfig?.max_output_tokens!==undefined||target.generationConfig?.candidate_count!==undefined||target.generationConfig?.thinking_config!==undefined))throw admissionError('noncanonical_config','Use canonical camelCase generation configuration');
 const gc=target?.generationConfig??{};
 if(generation&&(typeof gc!=='object'||Array.isArray(gc)))throw admissionError('invalid_config','Invalid generation configuration');
 if(generation&&bounded&&(gc.candidateCount??1)!==1)throw Object.assign(new Error('Bounded keys require one candidate'),{status:422});
 if(generation&&bounded&&gc.maxOutputTokens===undefined)throw Object.assign(new Error('Bounded keys require explicit generationConfig.maxOutputTokens'),{status:422});
 const maxOutput=gc.maxOutputTokens??0;
 // Uniform admission policy for every key; reservations still enforce each key's caps.
 // Google remains responsible for model-specific limits. Forward raw bytes unchanged.
 const outputCeiling=1000000;
 if(generation&&gc.maxOutputTokens!==undefined&&(!Number.isSafeInteger(maxOutput)||maxOutput<1||maxOutput>outputCeiling))throw admissionError('invalid_output_bound','maxOutputTokens outside supported range');
 // JSON.parse rounds decimal literals before validation. Inspect the actual JSON
 // number at the same canonical path; never rewrite forwarded bytes. The parser
 // rejects conflicting duplicate keys, so last-key selection cannot hide a bound.
 if(generation){
  let exact:any;try{exact=parseLossless(raw.toString());}catch{throw admissionError('invalid_json','Expected unambiguous JSON body');}
  const literal=(internal?exact.request:exact)?.generationConfig?.maxOutputTokens;
  if(gc.maxOutputTokens!==undefined&&(!isLosslessNumber(literal)||compareNumber(literal.value,String(maxOutput))!==0))
   throw admissionError('invalid_output_bound','maxOutputTokens outside supported range');
 }
 if(generation&&bounded&&(gc.thinkingConfig?.thinkingBudget??0)>maxOutput)throw Object.assign(new Error('Thinking budget exceeds reserved output'),{status:422});
 // Do not mutate generation JSON. Unlimited requests may omit output bounds.
 // Missing usage remains conservatively charged for bounded keys.
 const input=generation?raw.length+1024:0,output=generation?maxOutput:0;
 const reservation=store.reserve(key,model||'(control)',input,output);
 let final:Usage|undefined,status=502,started=false;
 const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),600_000);
 const disconnect=()=>{if(!res.writableEnded)abort.abort();};res.on('close',disconnect);
 try{
  const tried=new Set<string>();let lastStatus=503,attempts=0;
  const maxAttempts=Math.min(50,store.accounts().length*2+1);
  while(attempts++<maxAttempts){
   const route=pool.route(model,tried);if(!route)break;
   const {account,model:routedModel}=route;tried.add(account.id);
   let requestRaw=routedModel===model?raw:rewriteModel(raw,routedModel);
   const requestPath=routedModel===model?req.originalUrl:rewriteURLModel(req.originalUrl,routedModel);
   let token:string;try{token=await abortable(pool.access(account.id),abort.signal);}catch{continue;}
   if(abort.signal.aborted)throw new Error('Request canceled');
   if(!store.valid(store.key(key.id)))throw Object.assign(new Error('Key expired or revoked'),{status:401});
   const headers=new Headers();const connection=(req.headers.connection??'').split(',').map(h=>h.trim().toLowerCase());
   for(const [name,val] of Object.entries(req.headers))if(!strip.has(name)&&!connection.includes(name)&&!name.startsWith('x-forwarded-')&&val!==undefined)headers.set(name,Array.isArray(val)?val.join(', '):val);
   headers.set('authorization','Bearer '+token);headers.set('accept-encoding','identity');
   const url=new URL(pool.base);
   const parsedPath=new URL(requestPath,'http://agyp.invalid');
   if(parsedPath.origin!=='http://agyp.invalid')throw new Error('Invalid upstream path');
   url.pathname=parsedPath.pathname;url.search=parsedPath.search;
   const send=()=>{
    // A reactive repair can grow the payload. Never exceed the admitted input bound.
    if(generation&&bounded&&requestRaw.length>input)throw new Error('Repaired request exceeds reserved input');
    return fetch(url,{method:req.method,headers,body:['GET','HEAD'].includes(req.method)?undefined:new Uint8Array(requestRaw),redirect:'error',signal:abort.signal});
   };
   let upstream=await send();
   if(upstream.status===401){
    await readBounded(upstream,1_048_576);
    try{token=await abortable(pool.access(account.id,true),abort.signal);headers.set('authorization','Bearer '+token);upstream=await send();}
    catch{lastStatus=401;continue;}
   }
   if([400,404].includes(upstream.status)){
    const text=(await readBounded(upstream,1_048_576)).toString();
    if(signatureError(text)&&family(routedModel)==='gemini'){
     const repaired=repairSignatures(requestRaw);
     if(!repaired.equals(requestRaw)){requestRaw=repaired;upstream=await send();}
     else{pool.failed(account.id,routedModel,429,text);lastStatus=upstream.status;continue;}
    }else if(pool.failed(account.id,routedModel,upstream.status,text)){lastStatus=upstream.status;continue;}
    else{status=upstream.status;res.status(status).json({error:{message:'Upstream request rejected',code:status}});final={input:0,output:0,cached:0,total:0};return;}
   }
   if([400,401,403,404,429].includes(upstream.status)){
    // Error bodies are bounded; never forward account credentials or quota internals.
    const text=(await readBounded(upstream,1_048_576)).toString();lastStatus=upstream.status;
    const retry=([400,404].includes(upstream.status)&&signatureError(text))?pool.failed(account.id,routedModel,429,text):pool.failed(account.id,routedModel,upstream.status,text);
    if(retry){
     if(routedModel!==model&&[400,403].includes(upstream.status))pool.failed(account.id,model,upstream.status,text);
     continue;
    }
    status=upstream.status;res.status(status);res.setHeader('content-type','application/json');res.end(JSON.stringify({error:{message:'Upstream request rejected',code:status}}));final={input:0,output:0,cached:0,total:0};return;
   }
   if(!upstream.ok){
    await readBounded(upstream,1_048_576);
    status=upstream.status;final={input:0,output:0,cached:0,total:0};
    res.status(status).json({error:{message:'Upstream request rejected',code:status}});return;
   }
   status=upstream.status;res.status(status);
   const responseConnection=(upstream.headers.get('connection')??'').split(',').map(x=>x.trim());
   for(const [name,value]of upstream.headers)if(!strip.has(name)&&!responseConnection.includes(name)&&!['content-encoding','content-security-policy','strict-transport-security','x-frame-options'].includes(name))res.setHeader(name,value);
   res.setHeader('x-accel-buffering','no');
   res.setHeader('x-agyp-upstream-model',routedModel||'(control)');
   const reader=new UsageReader((upstream.headers.get('content-type')??'').includes('text/event-stream'));started=true;
   try{if(upstream.body)for await(const chunk of upstream.body){reader.feed(chunk);if(!res.write(chunk))await Promise.race([once(res,'drain'),once(res,'close').then(()=>{throw new Error('Client disconnected');})]);}
   reader.end();final=reader.value;
   if(!generation||status>=400)final??={input:0,output:0,cached:0,total:0};
   res.end();return;
   }finally{reader.end();final??=reader.value;}
  }
  status=lastStatus;
  // Do not forward Google error strings that may contain account details.
  res.status(status).json({error:{code:status,message:tried.size?'No eligible account remains for the exact requested model':'No eligible account for the exact requested model'}});
  final={input:0,output:0,cached:0,total:0};
 }catch(e){if(!started&&!abort.signal.aborted){res.status(502).json({error:{message:'Upstream connection failed'}});}else if(!res.writableEnded)res.destroy();}
 finally{clearTimeout(timer);res.off('close',disconnect);
  // Missing usage after a generation may have spent tokens. Charge its reservation, not zero.
  store.finish(reservation,final??{input,output,cached:0,total:input+output},status);
 }
}
async function readBounded(r:globalThis.Response,max:number){const chunks:Uint8Array[]=[];let n=0;if(r.body)for await(const c of r.body){n+=c.length;if(n>max)break;chunks.push(c);}return Buffer.concat(chunks);}
