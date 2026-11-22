// Explicitly injected local test instrumentation. Never enabled by main/app or an
// environment variable. No filesystem/stdout sink, request values or user IDs.
import {randomUUID} from 'node:crypto';
export const admissionReasons=['model_conflict','invalid_json','invalid_root','missing_model','missing_request','mixed_envelope','nested_envelope','noncanonical_config','invalid_config','invalid_output_bound','invalid_bootstrap'] as const;
export type AdmissionReason=typeof admissionReasons[number];
export class AdmissionError extends Error {
 readonly status=400;
 constructor(readonly reason:AdmissionReason,message:string){super(message);}
}
export const admissionError=(reason:AdmissionReason,message:string)=>new AdmissionError(reason,message);
const paths=new Set(['/v1internal:generateContent','/v1internal:streamGenerateContent','/v1internal:loadCodeAssist','/v1internal:countTokens']);
const methods=new Set(['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS']);
// Position-specific field names. In particular, never walk contents/parts/text,
// tool declarations, arbitrary metadata/maps, or user-controlled object keys.
const schema:Record<string,readonly string[]>={
 '':['model','request','generationConfig','generation_config','contents','metadata'],
 request:['generationConfig','generation_config','contents'],
 metadata:['ideType'],
 generationConfig:['maxOutputTokens','candidateCount','thinkingConfig','max_output_tokens','candidate_count','thinking_config'],
 'request.generationConfig':['maxOutputTokens','candidateCount','thinkingConfig','max_output_tokens','candidate_count','thinking_config'],
 'generationConfig.thinkingConfig':['thinkingBudget'],
 'request.generationConfig.thinkingConfig':['thinkingBudget'],
};
function kind(v:unknown):string{return v===null?'null':Array.isArray(v)?'array':typeof v;}
export function admissionShape(raw:Buffer){
 const fields:{field:string;type:string}[]=[];let unknownKeys=0,truncated=false,rootType='invalid_json';
 // Bounded parse and bounded traversal independently. No string/array lengths.
 if(raw.length>16*1024*1024)return {rootType:'omitted',fields,unknownKeys,truncated:true};
 let body:unknown;try{body=JSON.parse(raw.toString());}catch{return {rootType,fields,unknownKeys,truncated};}
 rootType=kind(body);
 function visit(value:unknown,path:string,depth:number){
  if(!value||typeof value!=='object'||Array.isArray(value))return;
  if(depth>3){truncated=true;return;}
  const allowed=schema[path];if(!allowed)return;
  // Iterate only fixed schema keys. Count unknown keys without ever retaining names.
  unknownKeys=Math.min(65535,unknownKeys+Object.keys(value).filter(k=>!allowed.includes(k)).length);
  for(const key of allowed)if(Object.hasOwn(value,key)){
   if(fields.length>=32){truncated=true;return;}
   const field=path?path+'.'+key:key,v=(value as Record<string,unknown>)[key];
   fields.push({field,type:kind(v)});if(schema[field])visit(v,field,depth+1);
  }
 }
 visit(body,'',0);return {rootType,fields,unknownKeys,truncated};
}
export type AdmissionRecord={v:1;correlationId:string;method:string;path:string;reason:AdmissionReason;shape:ReturnType<typeof admissionShape>};
export class LocalAdmissionDiagnostics {
 // At most 32 small immutable serialized records, memory only. Consumers get copies.
 private records:string[]=[];
 record(method:string,path:string,raw:Buffer,reason:AdmissionReason){
  if(!admissionReasons.includes(reason))return;
  const cleanPath=path.split('?')[0];
  const record:AdmissionRecord={v:1,correlationId:randomUUID(),method:methods.has(method)?method:'other',path:paths.has(cleanPath)?cleanPath:'other',reason,shape:admissionShape(raw)};
  const line=JSON.stringify(record);if(Buffer.byteLength(line)>8192)return;
  this.records.push(line);if(this.records.length>32)this.records.shift();return record.correlationId;
 }
 snapshot():AdmissionRecord[]{return this.records.map(s=>JSON.parse(s));}
}
