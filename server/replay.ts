// Surgical model replacement preserves every other original JSON byte. Input is
// validated JSON; strings are scanned atomically so quoted/nested models are inert.
export function rewriteModel(raw:Buffer,model:string):Buffer {
 const text=raw.toString();let depth=0;
 for(let i=0;i<text.length;i++){
  const c=text[i];if(c==='{'||c==='['){depth++;continue;}if(c==='}'||c===']'){depth--;continue;}if(c!=='"')continue;
  const start=i;for(i++;i<text.length;i++){if(text[i]==='\\'){i++;continue;}if(text[i]==='"')break;}
  if(depth!==1||JSON.parse(text.slice(start,i+1))!=='model')continue;
  let p=i+1;while(/\s/.test(text[p]??'')&&p<text.length)p++;if(text[p++]!==':')continue;
  while(p<text.length&&/\s/.test(text[p]))p++;if(text[p]!=='"')continue;
  let end=p+1;for(;end<text.length;end++){if(text[end]==='\\'){end++;continue;}if(text[end]==='"')break;}
  return Buffer.from(text.slice(0,p)+JSON.stringify(model)+text.slice(end+1));
 }
 return raw;
}
export function rewriteURLModel(path:string,model:string){
 const question=path.indexOf('?'),pathname=question<0?path:path.slice(0,question),query=question<0?'':path.slice(question);
 return pathname.replace(/(\/models\/)[^/:?]+/,(_m,p)=>p+encodeURIComponent(model))+query.replace(/([?&]model=)[^&]*/g,(_m,p)=>p+encodeURIComponent(model));
}
export function signatureError(text:string){return ['Corrupted thought signature','thought_signature','thoughtSignature','Invalid `signature` in `thinking` block'].some(s=>text.includes(s));}
// Reactive port of SanitizeGeminiSignatures / MutateParts, never proactive.
export function repairSignatures(raw:Buffer):Buffer {
 if(!raw.includes('"request"')&&!raw.includes('"contents"'))return raw;
 const doc=JSON.parse(raw.toString());if(!doc||typeof doc!=='object'||Array.isArray(doc))return raw;
 const target=Object.hasOwn(doc,'request')?doc.request:doc;
 if(!target||typeof target!=='object'||!Array.isArray(target.contents))return raw;
 let changed=false;
 for(const turn of target.contents){if(!turn||!Array.isArray(turn.parts))continue;
  const parts=turn.parts.filter((p:any)=>{if(p&&typeof p==='object'&&!Array.isArray(p)&&p.thought===true){changed=true;return false;}return true;});
  for(const p of parts)if(p&&typeof p==='object'&&!Array.isArray(p)&&Object.hasOwn(p,'functionCall')&&p.thoughtSignature!=='skip_thought_signature_validator'){p.thoughtSignature='skip_thought_signature_validator';changed=true;}
  if(!parts.length&&turn.parts.length){parts.push({text:''});changed=true;}
  turn.parts=parts;
 }
 return changed?Buffer.from(JSON.stringify(doc)):raw;
}
