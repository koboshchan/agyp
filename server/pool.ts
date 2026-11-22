import {OAuth2Client} from 'google-auth-library';
import {Store,type Account} from './store.js';

export type Bucket={family:string;label:string;remaining:number;reset:number;disabled:boolean;models?:string[];shared?:boolean};
export const UA='antigravity/hub/2.23.0 linux/amd64';
export function family(model:string){const m=model.toLowerCase();return m.includes('argon')?'argon':/claude|gpt|3p/.test(m)?'claude':/gemini|gemma/.test(m)?'gemini':'unknown';}
export function requiresUltra(model:string){return /carbon/.test(model.toLowerCase())||(/argon/.test(model.toLowerCase())&&!/trial/.test(model.toLowerCase()));}
function reset(v:any){if(typeof v==='string'){const d=Date.parse(v);if(Number.isFinite(d))return d;}if(typeof v==='number')return v<1e12?v*1000:v;if(v&&v.seconds)return Number(v.seconds)*1000;return 0;}
export function parseQuota(p:any):Bucket[]{
 const out:Bucket[]=[];
 for(const g of p.groups??[{displayName:'',buckets:p.buckets??[]}]){
  for(const b of g.buckets??[]){
   const label=[g.displayName??g.display_name,b.displayName??b.display_name,b.bucketId??b.bucket_id??b.model_id,b.window].filter(Boolean).join(' · ');
   const remaining=Number(b.remainingFraction??b.remaining_fraction??0);
   const explicit=b.modelId??b.model_id;
   const models=Array.isArray(b.models??b.modelIds??b.model_ids??g.modelIds??g.model_ids)?(b.models??b.modelIds??b.model_ids??g.modelIds??g.model_ids).filter((m:any)=>typeof m==='string'):typeof explicit==='string'?[explicit]:undefined;
   out.push({family:family(label+' '+(models??[]).join(' ')),label,remaining:Number.isFinite(remaining)?Math.min(1,Math.max(0,remaining)):0,reset:reset(b.resetTime??b.reset_time),disabled:!!b.disabled,models,shared:!models});
  }
 }
 return out;
}
export class Pool {
 active:Record<string,string>={}; refreshes=new Map<string,Promise<string>>(); polls=new Map<string,Promise<void>>();
 constructor(public store:Store,public base:string,public clientId:string,public clientSecret:string){}
 oauth(redirect?:string){if(!this.clientId||!this.clientSecret)throw Object.assign(new Error('OAuth client not configured'),{status:503});return new OAuth2Client(this.clientId,this.clientSecret,redirect);}
 async access(id:string):Promise<string>{
  const a=this.store.accounts().find(a=>a.id===id);if(!a)throw new Error('Account removed');
  if(a.access_token&&a.token_expiry>Date.now()+120_000)return a.access_token;
  const pending=this.refreshes.get(id);if(pending)return pending;
  const task=(async()=>{try{
   const c=this.oauth();c.setCredentials({refresh_token:a.refresh_token});
   const {credentials}=await c.refreshAccessToken();const current=this.store.accounts().find(x=>x.id===id);if(!current)throw new Error('Account removed');
   current.access_token=credentials.access_token??'';current.token_expiry=credentials.expiry_date??Date.now()+3600_000;
   if(credentials.refresh_token)current.refresh_token=credentials.refresh_token;
   this.store.putAccount(current);return current.access_token;
  }catch(e){const current=this.store.accounts().find(x=>x.id===id);if(current){current.status=current.status==='disabled'?'disabled':'auth_error';this.store.putAccount(current);}throw e;}
  finally{this.refreshes.delete(id);}})();this.refreshes.set(id,task);return task;
 }
 async poll(id:string){
  const pending=this.polls.get(id);if(pending)return pending;
  const task=this.pollOnce(id).catch(e=>{const a=this.store.accounts().find(a=>a.id===id);if(a){a.shared=false;this.store.putAccount(a);}throw e;}).finally(()=>this.polls.delete(id));this.polls.set(id,task);return task;
 }
 async pollOnce(id:string){
  const token=await this.access(id);let r=await fetch(this.base+'/v1internal:retrieveUserQuotaSummary',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json','user-agent':UA},body:'{}',redirect:'error',signal:AbortSignal.timeout(30_000)});
  if(r.status===404||r.status===400||r.status===501){await r.body?.cancel();r=await fetch(this.base+'/v1internal:retrieveUserQuota',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json','user-agent':UA},body:'{"project":""}',redirect:'error',signal:AbortSignal.timeout(30_000)});}
  const a=this.store.accounts().find(a=>a.id===id);if(!a){await r.body?.cancel();return;}
  if(!r.ok){await r.body?.cancel();if(r.status===403)a.blocked=true;if(r.status===401&&a.status!=='disabled')a.status='auth_error';this.store.putAccount(a);throw new Error('Quota poll HTTP '+r.status);}
  const p=await r.json() as any;a.buckets=parseQuota(p);a.shared=a.buckets.some(b=>b.family==='gemini')&&!a.buckets.some(b=>b.family==='argon');a.updated=Date.now();a.blocked=false;
  // Match authoritative switcher topology inference; never infer from a failed/local poll.
  if(typeof p.sharedGeminiPool==='boolean'||typeof p.shared_gemini_pool==='boolean')a.shared=!!(p.sharedGeminiPool??p.shared_gemini_pool);
  if(a.status!=='disabled')a.status='ready';
  this.store.putAccount(a);
 }
 eligible(a:Account,model:string){
  const f=family(model),now=Date.now();
  if(a.status!=='ready'||a.blocked||(a.cooldowns[f]??0)>now||(a.denied[model]??0)>now)return false;
  if(requiresUltra(model)&&!a.shared)return false;
  const q=a.buckets.filter(b=>b.family===(requiresUltra(model)?'gemini':f)&&(!b.models?.length||b.models.includes(model.replace(/^models\//,''))));
  if(f==='unknown')return true;
  return q.length>0&&q.every(b=>!b.disabled&&(b.remaining>0||(b.reset>0&&b.reset<=now)));
 }
 select(model:string,excluded=new Set<string>()){
  const list=this.store.accounts().filter(a=>!excluded.has(a.id)&&this.eligible(a,model)),f=family(model);
  const a=list.find(a=>a.id===this.active[f])??list.sort((a,b)=>b.buckets.filter(q=>q.family===f).reduce((s,q)=>s+q.remaining,0)-a.buckets.filter(q=>q.family===f).reduce((s,q)=>s+q.remaining,0))[0];
  if(a)this.active[f]=a.id;return a;
 }
 failed(id:string,model:string,status:number,text:string){
  const a=this.store.accounts().find(a=>a.id===id);if(!a)return false;let retry=false;const now=Date.now(),f=family(model);
  if(status===429){a.cooldowns[f]=Math.max(now+300_000,...a.buckets.filter(b=>(b.family===(requiresUltra(model)?'gemini':f))&&(!b.models?.length||b.models.includes(model))&&b.remaining<=0).map(b=>b.reset));retry=true;}
  else if(status===403&&/subscription_required|subscription required/i.test(text)){a.denied[model]=now+1800_000;retry=true;}
  else if(status===403&&/quota|resource_exhausted/i.test(text)){a.blocked=true;retry=true;}
  else if(status===401){if(a.status!=='disabled')a.status='auth_error';retry=true;}
  this.store.putAccount(a);return retry;
 }
 safe(){return this.store.accounts().map(({id,email,status,shared,blocked,buckets,updated,cooldowns,denied})=>({id,email,status,shared,blocked,buckets,updated,cooldowns,denied}));}
}
