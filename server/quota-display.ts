// Presentation only. Never feed these synthetic fractions into Pool routing,
// provider eligibility, generation admission, or recorded usage accounting.
import {Store,nextReset,type Key} from './store.js';
import {family} from './pool.js';
export type DisplayQuota={fraction:number;capped:boolean;reset?:string};
export function displayQuota(store:Store,key:Key):DisplayQuota{
 const used=store.used(key),ratios:number[]=[];
 for(const [cap,spent] of [[key.allowance,used.total],[key.inputCap,used.input],[key.outputCap,used.output]] as const)
  if(cap!==null)ratios.push(cap<=0?0:Math.min(1,Math.max(0,(cap-spent)/cap)));
 const reset=nextReset(key.period);
 return {fraction:ratios.length?Math.min(...ratios):1,capped:ratios.length>0,...(reset===null?{}:{reset:new Date(reset).toISOString()})};
}
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
// Keep provider identifiers and capability metadata, but not credentials/identity.
function label(v:unknown){return typeof v==='string'&&!/[\r\n@]/.test(v)&&v.length<=200?v:undefined;}
const quotaFields=new Set(['remainingAmount','remaining_amount','remainingFraction','remaining_fraction','resetTime','reset_time']);
function without(value:Record<string,unknown>,fields:Iterable<string>){const omit=new Set(fields);return metadata(Object.fromEntries(Object.entries(value).filter(([k])=>!omit.has(k)))) as Record<string,unknown>;}
function groupFraction(name:string,q:DisplayQuota){
 if(!q.capped)return 1;
 // Argon must be classified before the broader Gemini family.
 if(/argon|claude|gpt/i.test(name))return 0;
 return /^gemini models$/i.test(name.trim())?q.fraction:0;
}
export function mapQuotaSummary(value:unknown,q:DisplayQuota){
 if(!object(value)||!Array.isArray(value.groups))throw new Error('Invalid quota summary');
 return {...without(value,['groups','buckets']),groups:value.groups.map(g=>{
  if(!object(g)||typeof g.displayName!=='string'||!Array.isArray(g.buckets))throw new Error('Invalid quota group');
  const fraction=groupFraction(g.displayName,q);
  return {...without(g,['buckets']),buckets:g.buckets.map(b=>{
   if(!object(b))throw new Error('Invalid quota bucket');
   // remainingFraction and remainingAmount are mutually exclusive protobuf arms.
   // Fractions have known units, provider remainingAmount does not. Never emit both.
   return {...without(b,quotaFields),remainingFraction:fraction,...(q.reset?{resetTime:q.reset}:{})};
  })};
 })};
}

export function quotaDisplayAction(method:string,path:string){
 // Apply to every admitted method so an unlimited-key alternate verb cannot
 // expose an unmodified successful quota reply. Path admission stays unchanged.
 if(!['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'].includes(method))return undefined;
 const action=/^\/v1internal:(retrieveUserQuotaSummary|retrieveUserQuota|fetchAvailableModels)(?:\?[^#]*)?$/.exec(path)?.[1];
 return action as 'retrieveUserQuotaSummary'|'retrieveUserQuota'|'fetchAvailableModels'|undefined;
}
function modelFraction(model:string,q:DisplayQuota){return !q.capped?1:family(model)==='gemini'?q.fraction:0;}
export function mapLegacyQuota(value:unknown,q:DisplayQuota){
 if(!object(value)||!Array.isArray(value.buckets))throw new Error('Invalid quota response');
 return {...without(value,['buckets']),buckets:value.buckets.map(b=>{
  if(!object(b))throw new Error('Invalid quota bucket');
  return {...without(b,quotaFields),remainingFraction:modelFraction(typeof b.modelId==='string'?b.modelId:'',q),...(q.reset?{resetTime:q.reset}:{})};
 })};
}
// Only discovery metadata passes this filter, never generation response bytes.
// It strips identity/credential fields, preserving provider capability metadata.
function metadata(v:unknown):unknown{
 if(typeof v==='string')return /@/.test(v)?undefined:v;
 if(Array.isArray(v))return v.map(metadata).filter(v=>v!==undefined);
 if(object(v))return Object.fromEntries(Object.entries(v).filter(([k])=>!/(?:email|account|credential|access.?token|refresh.?token|secret|authorization)/i.test(k)).map(([k,v])=>[k,metadata(v)]).filter(([,v])=>v!==undefined));
 return v;
}
export function mapAvailableModels(value:unknown,q:DisplayQuota){
 if(!object(value)||!object(value.models))throw new Error('Invalid models response');
 const models:Record<string,unknown>={};
 for(const [id,details]of Object.entries(value.models)){
  if(!object(details)||!label(id))throw new Error('Invalid model details');
  const {quotaInfo,...rest}=details;
  if(quotaInfo!==undefined&&!object(quotaInfo))throw new Error('Invalid model quota');
  // Keep model capability/default metadata. Existing absent quotaInfo is not an
  // entitlement gap and must not be turned into a fabricated model record.
  Object.defineProperty(models,id,{enumerable:true,writable:true,configurable:true,value:{...metadata(rest) as Record<string,unknown>,...(quotaInfo===undefined?{}:{quotaInfo:{...without(quotaInfo,quotaFields),remainingFraction:modelFraction(id,q),...(q.reset?{resetTime:q.reset}:{})}})}});
 }
 const root=without(value,['models']);
 return {...root,models};
}
export function mapQuotaDisplay(action:NonNullable<ReturnType<typeof quotaDisplayAction>>,value:unknown,q:DisplayQuota){
 return action==='retrieveUserQuotaSummary'?mapQuotaSummary(value,q):action==='retrieveUserQuota'?mapLegacyQuota(value,q):mapAvailableModels(value,q);
}
