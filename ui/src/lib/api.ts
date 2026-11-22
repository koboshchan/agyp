export type Json=any;
export class ApiError extends Error{status=0}
let csrf:string|undefined;
export const setCsrf=(v?:string)=>{csrf=v};
let onUnauthorized:()=>void=()=>{};
export const setUnauthorizedHandler=(f:()=>void)=>{onUnauthorized=f};
export async function api(path:string,opts:{method?:string;body?:unknown}={}):Promise<Json>{
 const headers:Record<string,string>={};
 if(opts.body!==undefined)headers['Content-Type']='application/json';
 if(opts.method&&opts.method!=='GET'&&csrf)headers['X-CSRF-Token']=csrf;
 const r=await fetch(path,{method:opts.method,headers,credentials:'same-origin',cache:'no-store',body:opts.body===undefined?undefined:JSON.stringify(opts.body)});
 let data:Json={};try{data=await r.json()}catch{/* empty body is valid */}
 if(!r.ok){
  if(r.status===401&&!path.startsWith('/auth/'))onUnauthorized();
  const e=new ApiError(typeof data.error==='string'?data.error:(data.error?.message||data.message||'Request failed ('+r.status+').'));e.status=r.status;throw e;
 }
 return data;
}
const hex=(b:ArrayBuffer)=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('');
export async function signIn(raw:string){
 let token=raw.trim();const m=/^agyp_([a-f0-9]{16}).(.+)$/i.exec(token);
 if(!m){token='';throw new Error('Enter a complete access key, including its agyp_ prefix.');}
 const keyId=m[1];let k:CryptoKey|null;
 try{
  if(!globalThis.crypto?.subtle)throw new Error('A secure HTTPS connection is required to unlock.');
  k=await crypto.subtle.importKey('raw',new TextEncoder().encode(token),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 }finally{token=''}
 const c=await api('/auth/challenge',{method:'POST',body:{keyId}});
 const proof=hex(await crypto.subtle.sign('HMAC',k,new TextEncoder().encode(c.nonce)));k=null;
 await api('/auth/verify',{method:'POST',body:{keyId,nonce:c.nonce,proof,client:'web'}});
}
