// Limited-key policy is deliberately a prefix DENYLIST, not provider-family
// classification. Unknown models remain allowed. Never rewrite request bytes.
import {modelKey} from './google.js';
import {admissionError} from './diagnostics.js';
export class LimitedModelError extends Error {
 readonly status=403;
 constructor(){super('unsupported for limited key');}
}
export function deniedLimitedModel(model:string){
 const id=modelKey(model);
 return ['gemini-4-argon','claude','gpt'].some(prefix=>id.startsWith(prefix));
}
export function enforceLimitedModel(path:string,body:unknown){
 const models:string[]=[];
 const byPath=/\/models\/([^/:?]+)/.exec(path)?.[1];
 if(byPath)models.push(decodeURIComponent(byPath));
 models.push(...new URL(path,'http://local').searchParams.getAll('model'));
 // Inspect only the known envelope chain, never user text, tool declarations,
 // metadata, or arbitrary payload objects that may legitimately have model keys.
 let envelope=body;
 for(let depth=0;envelope&&typeof envelope==='object'&&!Array.isArray(envelope);depth++){
  if(depth>64)throw admissionError('nested_envelope','Unexpected nested request envelope');
  const value=envelope as Record<string,unknown>;
  if(typeof value.model==='string')models.push(value.model);
  envelope=value.request;
 }
 if(models.some(deniedLimitedModel))throw new LimitedModelError();
 // Preserve the existing model-conflict validator, additionally closing known
 // nested/query-duplicate ambiguity for limited keys without changing unlimited.
 if(new Set(models.filter(Boolean)).size>1)throw admissionError('model_conflict','Conflicting model identifiers');
}
