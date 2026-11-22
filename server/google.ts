// Google RPC helpers mirror the switcher's structured verification detector.
export type Verification = {url:string;observedAt:number};
export const modelKey=(model:string)=>model.trim().toLowerCase().replace(/^models\//,'');
export function safeVerificationURL(raw:unknown):string {
 if(typeof raw!=='string'||raw.length>8192)return '';
 try{
  const trimmed=raw.trim(),u=new URL(trimmed);
  // URL.hash loses an empty fragment delimiter; reject it before normalization too.
  if(u.protocol!=='https:'||u.username||u.password||trimmed.includes('#')||(u.port&&u.port!=='443'))return '';
  const host=u.hostname.toLowerCase();
  if(host!=='google.com'&&!host.endsWith('.google.com')&&host!=='antigravity.google')return '';
  return u.href;
 }catch{return '';}
}
function usableEligibility(v:any):boolean {
 const p=v.cloudaicompanionProject;
 const project=typeof p==='string'?!!p.trim():p&&typeof p==='object'&&['id','projectId','name'].some(k=>typeof p[k]==='string'&&!!p[k].trim());
 if(project&&['currentTier','paidTier'].some(k=>v[k]&&typeof v[k]==='object'&&!Array.isArray(v[k])))return true;
 return Array.isArray(v.allowedTiers)&&v.allowedTiers.some((t:any)=>t&&typeof t.id==='string'&&(t.id.trim()==='free-tier'||(t.isDefault===true&&!!t.id.trim())));
}
export function detectVerification(body:string):Verification|undefined {
 if(Buffer.byteLength(body)>1024*1024)return;
 let root:any;try{root=JSON.parse(body);}catch{return;}
 const links=['validation_url','validationUrl','verification_url','verificationUrl','verifyURL','verifyUrl','appeal_url','appealUrl'];
 const text=(v:any,k:string)=>typeof v?.[k]==='string'?v[k]:'';
 function walk(v:any):Verification|undefined {
  if(Array.isArray(v)){for(const item of v){const found=walk(item);if(found)return found;}return;}
  if(!v||typeof v!=='object')return;
  const reason=(text(v,'reason')+text(v,'reasonCode')).toUpperCase();
  let link=links.map(k=>text(v,k)).find(Boolean)??'';
  if(v.metadata&&typeof v.metadata==='object')link=links.map(k=>text(v.metadata,k)).find(Boolean)??link;
  if(/VALIDATION_REQUIRED|VERIFICATION_REQUIRED/.test(reason)||(link&&(!text(v,'@type')||text(v,'@type').endsWith('/google.rpc.ErrorInfo'))))return {url:safeVerificationURL(link),observedAt:Date.now()};
  for(const k of ['error','details','ineligibleTiers','response']){
   if(k==='ineligibleTiers'&&usableEligibility(v))continue;
   const found=walk(v[k]);if(found)return found;
  }
 }
 return walk(root);
}
export function subscriptionRequired(status:number,body:string):boolean {
 // Also accept 400 structured reasons, as some Google frontends use INVALID_ARGUMENT.
 if(status!==400&&status!==403)return false;
 try{return JSON.parse(body)?.error?.details?.some((v:any)=>v?.reason==='SUBSCRIPTION_REQUIRED')===true;}catch{return false;}
}
export function authRevoked(error:unknown):boolean {
 const e=error as any;
 return /invalid_grant|revoked/i.test([e?.message,e?.response?.data?.error,e?.response?.data?.error_description].filter(v=>typeof v==='string').join(' '));
}
