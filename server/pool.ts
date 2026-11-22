import {OAuth2Client} from 'google-auth-library';
import {Store,type Account} from './store.js';
import {authRevoked,detectVerification,modelKey,safeVerificationURL,subscriptionRequired,type Verification} from './google.js';

export type Bucket={family:string;label:string;remaining:number;reset:number;disabled:boolean;bucketId?:string;models?:string[];shared?:boolean};
type PoolAccount=Account & {verification?:Verification;cooldownObserved?:Record<string,number>;blockedObserved?:number};
export const UA='antigravity/hub/2.23.0 '+({win32:'windows',sunos:'solaris'}[process.platform as string]??process.platform)+'/'+({x64:'amd64',ia32:'386',ppc64:'ppc64le'}[process.arch as string]??process.arch);
export function family(model:string){
 const m=modelKey(model);
 if(m==='carbon'||m.startsWith('carbon-')||m.includes('gemini-4-carbon')||m==='argon'||m.startsWith('argon-')||m.includes('gemini-4-argon'))return 'argon';
 if(/claude|gpt|sonnet|opus|haiku|anthropic|openai|3p/.test(m)||/^o[134]($|[-_])/.test(m))return 'claude';
 return /gemini|gemma|flash|pro|ultra/.test(m)||m==='hydrogen'||m==='helium'?'gemini':'unknown';
}
function bucketFamily(label:string){const m=label.toLowerCase();return m.includes('argon')?'argon':/claude|gpt|3p/.test(m)?'claude':/gemini|gemma/.test(m)?'gemini':'unknown';}
export function requiresUltra(model:string){const m=modelKey(model);return m==='carbon'||m.startsWith('carbon-')||m.includes('gemini-4-carbon')||(family(m)==='argon'&&!m.includes('trial'));}
function reset(v:any){if(typeof v==='string'){const d=Date.parse(v);if(Number.isFinite(d))return d;}if(typeof v==='number')return v<1e12?v*1000:v;if(v&&v.seconds)return Number(v.seconds)*1000;return 0;}
export function parseQuota(p:any):Bucket[]{
 if(!p||typeof p!=='object'||Array.isArray(p))throw new Error('Invalid quota response');
 const out:Bucket[]=[],grouped=Array.isArray(p.groups)&&p.groups.length>0,seen=new Set<string>();
 for(const g of grouped?p.groups:[{displayName:'',buckets:p.buckets??[]}]){
  for(const b of g.buckets??[]){
   const bucketId=b.bucketId||b.bucket_id||b.model_id||'';
   if(!grouped&&(!bucketId||seen.has(bucketId)))continue;
   seen.add(bucketId);
   const label=[g.displayName??g.display_name,b.displayName??b.display_name,bucketId,b.window].filter(Boolean).join(' · ');
   // Google sometimes emits a zero camelCase field alongside a positive snake_case one.
   const remaining=Number(b.remainingFraction||b.remaining_fraction||0);
   const explicit=b.modelId??b.model_id;
   const modelList=b.models??b.modelIds??b.model_ids??g.modelIds??g.model_ids;
   const models=Array.isArray(modelList)?modelList.filter((m:any)=>typeof m==='string'):typeof explicit==='string'?[explicit]:undefined;
   out.push({family:bucketFamily(label),label,bucketId,remaining:Number.isFinite(remaining)?Math.min(1,Math.max(0,remaining)):0,reset:reset(b.resetTime??b.reset_time),disabled:!!b.disabled,models,shared:!models});
  }
 }
 return out;
}
const usable=(b:Bucket,now:number)=>!b.disabled&&(b.remaining>0||(b.reset>0&&b.reset<=now));
function quota(buckets:Bucket[],f:string,now:number){const q=buckets.filter(b=>b.family===f);return {known:q.length>0,available:q.every(b=>usable(b,now))};}
export class Pool {
 active:Record<string,string>={}; refreshes=new Map<string,Promise<string>>(); polls=new Map<string,Promise<void>>();
 constructor(public store:Store,public base:string,public clientId:string,public clientSecret:string){}
 private account(id:string){return this.store.accounts().find(a=>a.id===id) as PoolAccount|undefined;}
 oauth(redirect?:string){if(!this.clientId||!this.clientSecret)throw Object.assign(new Error('OAuth client not configured'),{status:503});return new OAuth2Client(this.clientId,this.clientSecret,redirect);}
 async access(id:string,force=false):Promise<string>{
  const a=this.account(id);if(!a)throw new Error('Account removed');
  // Even an unforced caller must join a forced refresh already in flight.
  const pending=this.refreshes.get(id);if(pending)return pending;
  if(!force&&a.access_token&&a.token_expiry>Date.now()+60_000)return a.access_token;
  // Defer work so even synchronously thrown OAuth setup errors run after map insertion.
  const task=Promise.resolve().then(async()=>{try{
   const c=this.oauth();c.setCredentials({refresh_token:a.refresh_token});
   const {credentials}=await c.refreshAccessToken();const current=this.account(id);if(!current)throw new Error('Account removed');
   if(!credentials.access_token)throw new Error('OAuth refresh returned no access token');
   current.access_token=credentials.access_token;current.token_expiry=credentials.expiry_date??Date.now()+3600_000;
   if(credentials.refresh_token)current.refresh_token=credentials.refresh_token;
   this.store.putAccount(current);return current.access_token;
  }catch(e){const current=this.account(id);if(current&&authRevoked(e)&&current.status!=='disabled'){current.status='auth_error';this.store.putAccount(current);}throw e;}
  finally{this.refreshes.delete(id);}});this.refreshes.set(id,task);return task;
 }
 async poll(id:string){
  const pending=this.polls.get(id);if(pending)return pending;
  const task=Promise.resolve().then(()=>this.pollOnce(id)).catch(e=>{const a=this.account(id);if(a){a.shared=false;this.store.putAccount(a);}throw e;}).finally(()=>this.polls.delete(id));this.polls.set(id,task);return task;
 }
 private async quotaResponse(path:string,token:string,body:string){
  const r=await fetch(this.base+path,{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json','user-agent':UA},body,redirect:'error',signal:AbortSignal.timeout(30_000)});
  // Same 1MiB bound as the switcher, before JSON or verification parsing.
  let text='';const reader=r.body?.getReader();let size=0;const chunks:Uint8Array[]=[];
  if(reader)try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>1024*1024)throw new Error('Quota response exceeds maximum size');chunks.push(value);}text=Buffer.concat(chunks).toString('utf8');}finally{await reader.cancel();}
  return {status:r.status,ok:r.ok,text};
 }
 async pollOnce(id:string){
  const initial=this.account(id);if(!initial||initial.status==='disabled')return;
  const started=Date.now(),oldCooldowns={...initial.cooldowns},oldBlocked=initial.blocked;
  let token=await this.access(id),path='/v1internal:retrieveUserQuotaSummary',body='{}';
  let r=await this.quotaResponse(path,token,body);
  const inspect=()=>{
   const verification=detectVerification(r.text);if(!verification)return;
   const a=this.account(id);if(a){a.verification=verification;this.store.putAccount(a);}
   throw new Error('Google account needs verification');
  };
  inspect();
  // One forced refresh and retry for a direct quota 401, never an OAuth loop.
  if(r.status===401){token=await this.access(id,true);r=await this.quotaResponse(path,token,body);inspect();}
  // The upstream switcher falls back only on 404, not arbitrary 400/501 errors.
  if(r.status===404){path='/v1internal:retrieveUserQuota';body='{"project":""}';r=await this.quotaResponse(path,token,body);inspect();}
  const a=this.account(id);if(!a)return;
  if(!r.ok){
   if(r.status===403){a.blocked=true;a.blockedObserved=Date.now();}
   if(r.status===401&&a.status!=='disabled')a.status='auth_error';
   this.store.putAccount(a);throw new Error('Quota poll HTTP '+r.status);
  }
  const buckets=parseQuota(JSON.parse(r.text));
  a.buckets=buckets;a.updated=Date.now();
  // Only an authoritative direct success establishes Ultra topology.
  a.shared=buckets.some(b=>b.family==='gemini')&&!buckets.some(b=>b.family==='argon');
  if(a.verification&&a.verification.observedAt<started)delete a.verification;
  if(oldBlocked&&a.blocked&&(a.blockedObserved??0)<started){a.blocked=false;delete a.blockedObserved;}
  for(const f of ['argon','gemini','claude']){
   const q=quota(buckets,f,started);
   if(q.known&&q.available&&a.cooldowns[f]===oldCooldowns[f]&&(a.cooldownObserved?.[f]??0)<started){delete a.cooldowns[f];if(a.cooldownObserved)delete a.cooldownObserved[f];}
  }
  // Successful quota is not proof that a separately revoked login recovered.
  if(a.status==='exhausted'&&buckets.length&&buckets.every(b=>usable(b,started)))a.status='ready';
  this.store.putAccount(a);
 }
 private quotaFamily(a:PoolAccount,model:string){const f=family(model);return f==='argon'&&a.shared?'gemini':f;}
 eligible(account:Account,model:string){
  const a=account as PoolAccount,f=this.quotaFamily(a,model),now=Date.now();
  if((a.status!=='ready'&&a.status!=='exhausted')||a.blocked||a.verification||(a.cooldowns[f]??0)>now||(a.denied[modelKey(model)]??0)>now)return false;
  if(requiresUltra(model)&&!a.shared)return false;
  if(f==='unknown')return a.status==='ready';
  // Quotas are provider-family windows, not exact-model grants. Subscription
  // rejection is kept separately in denied, including aliases normalized above.
  const q=quota(a.buckets,f,now);
  return q.available&&(a.status==='ready'||q.known)&&(!requiresUltra(model)||q.known);
 }
 route(model:string,excluded=new Set<string>()):{account:Account;model:string}|undefined{
  const accounts=this.store.accounts().filter(a=>!excluded.has(a.id));
  const choose=(list:Account[],upstream=model)=>{
   const a=list.find(a=>a.id===this.active[family(model)])??list[0];
   if(a){this.active[family(model)]=a.id;return {account:a,model:upstream};}
  };
  const key=modelKey(model),trial='gemini-4-argon-trial';
  if(key===trial){
   const ultra=accounts.filter(a=>a.shared&&this.eligible(a,model)&&this.eligible(a,'gemini-4-argon-low'));
   if(ultra.length)return choose(ultra,'gemini-4-argon-low');
   const advertised=accounts.filter(a=>this.eligible(a,model)&&a.buckets.some(b=>b.bucketId==='gemini-argon-wtu-weekly'));
   if(advertised.length)return choose(advertised);
  }
  const normal=accounts.filter(a=>this.eligible(a,model));
  if(normal.length)return choose(normal);
  if(['gemini-4-argon','gemini-4-argon-low','gemini-4-argon-high'].includes(key)&&!this.store.accounts().some(a=>this.eligible(a,model))){
   // Affirmative Pro weekly trial evidence only; Carbon never degrades to trial.
   const pro=accounts.filter(a=>!a.shared&&this.eligible(a,trial)&&a.buckets.some(b=>b.bucketId==='gemini-argon-wtu-weekly'&&usable(b,Date.now())));
   if(pro.length)return choose(pro,trial);
  }
  delete this.active[family(model)];
 }
 select(model:string,excluded=new Set<string>()){return this.route(model,excluded)?.account;}
 failed(id:string,model:string,status:number,text:string){
  const a=this.account(id);if(!a)return false;let retry=false;const now=Date.now(),f=this.quotaFamily(a,model);
  if((status===400||status===403)&&subscriptionRequired(status,text)){a.denied[modelKey(model)]=now+1800_000;retry=true;}
  // Verification state is independent of manual account disable and auth status.
  if(status===400||status===403){const v=detectVerification(text);if(v){a.verification=v;retry=true;}}
  if(!retry&&(status===429||(status===403&&/RESOURCE_EXHAUSTED|RATE_LIMIT_EXCEEDED|QuotaFailure/.test(text)))){
   a.cooldowns[f]=Math.max(now+300_000,...a.buckets.filter(b=>b.family===f&&b.remaining<=0).map(b=>b.reset));
   (a.cooldownObserved??={})[f]=now;retry=true;
  }else if(!retry&&status===401){if(a.status!=='disabled')a.status='auth_error';retry=true;}
  this.store.putAccount(a);return retry;
 }
 safe(){return (this.store.accounts() as PoolAccount[]).map(({id,email,status,shared,blocked,buckets,updated,cooldowns,denied,verification})=>({id,email,status,shared,blocked,buckets,updated,cooldowns,denied,...(verification?{verification:{url:safeVerificationURL(verification.url),observedAt:verification.observedAt}}:{})}));}
}
