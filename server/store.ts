import { DatabaseSync } from 'node:sqlite';
import { randomBytes, createHash, timingSafeEqual, createCipheriv, createDecipheriv } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { join } from 'node:path';

export type Key = {id:string; name:string; hash:string; admin:number; revoked:number; expires:number|null; allowance:number|null; inputCap:number|null; outputCap:number|null; period:string; created:number};
export type Account = {id:string; email:string; refresh_token:string; access_token:string; token_expiry:number; status:string; shared:boolean; blocked:boolean; buckets:any[]; cooldowns:Record<string,number>; denied:Record<string,number>; updated:number};
export type Usage = {input:number; output:number; cached:number; total:number};
export const digest=(s:string)=>createHash('sha256').update(s).digest('hex');
export const secret=()=>randomBytes(32).toString('base64url');
export function equal(a:string,b:string){const x=Buffer.from(a,'hex'),y=Buffer.from(b,'hex');return x.length===y.length&&timingSafeEqual(x,y);}
export function windowStart(period:string,now=Date.now()){
 const d=new Date(now); d.setUTCHours(0,0,0,0);
 if(period==='daily')return +d;
 if(period==='weekly'){d.setUTCDate(d.getUTCDate()-((d.getUTCDay()+6)%7));return +d;}
 if(period==='monthly'){d.setUTCDate(1);return +d;} return 0;
}
export function nextReset(period:string,now=Date.now()){
 if(period==='never')return null;
 const d=new Date(windowStart(period,now));
 if(period==='monthly') d.setUTCMonth(d.getUTCMonth()+1); else d.setUTCDate(d.getUTCDate()+(period==='weekly'?7:1));
 return +d;
}
export class Store {
 db:DatabaseSync; master:Buffer; adminToken:string;
 constructor(public dir:string){
  mkdirSync(dir,{recursive:true,mode:0o700}); chmodSync(dir,0o700);
  const path=join(dir,'seal.key');
  if(!existsSync(path))writeFileSync(path,randomBytes(32),{mode:0o600,flag:'wx'});
  this.master=readFileSync(path);chmodSync(path,0o600);
  this.db=new DatabaseSync(join(dir,'agyp.sqlite'));chmodSync(join(dir,'agyp.sqlite'),0o600);
  this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS keys(id TEXT PRIMARY KEY,name TEXT,hash TEXT,admin INTEGER,revoked INTEGER DEFAULT 0,expires INTEGER,allowance INTEGER,inputCap INTEGER,outputCap INTEGER,period TEXT,created INTEGER);
 CREATE TABLE IF NOT EXISTS settings(id TEXT PRIMARY KEY,value TEXT);
 CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY,value TEXT);
 CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,key_id TEXT,csrf TEXT,expires INTEGER);
 CREATE TABLE IF NOT EXISTS usage(id INTEGER PRIMARY KEY,key_id TEXT,model TEXT,input INTEGER,output INTEGER,cached INTEGER,total INTEGER,time INTEGER,status INTEGER);
 CREATE INDEX IF NOT EXISTS usage_key_time ON usage(key_id,time);
 CREATE TABLE IF NOT EXISTS reservations(id TEXT PRIMARY KEY,key_id TEXT,model TEXT,input INTEGER,output INTEGER,time INTEGER);
 CREATE TABLE IF NOT EXISTS oauth(state TEXT PRIMARY KEY,session_hash TEXT,verifier TEXT,redirect TEXT,expires INTEGER);
 `);
  // Crash-interrupted requests remain charged at their admission bound, never silently free.
  this.db.exec(`INSERT INTO usage(key_id,model,input,output,cached,total,time,status) SELECT key_id,model,input,output,0,input+output,time,599 FROM reservations; DELETE FROM reservations;`);
  const sealed=this.db.prepare("SELECT value FROM settings WHERE id='admin'").get() as any;
  if(sealed)this.adminToken=this.open(sealed.value);
  else {const k=this.createKey({name:'Administrator',admin:1});this.adminToken=k.token;this.db.prepare("INSERT INTO settings VALUES('admin',?)").run(this.seal(k.token));}
 }
 seal(s:string){const iv=randomBytes(12),c=createCipheriv('aes-256-gcm',this.master,iv);const data=Buffer.concat([c.update(s,'utf8'),c.final()]);return Buffer.concat([iv,c.getAuthTag(),data]).toString('base64');}
 open(s:string){const b=Buffer.from(s,'base64'),d=createDecipheriv('aes-256-gcm',this.master,b.subarray(0,12));d.setAuthTag(b.subarray(12,28));return Buffer.concat([d.update(b.subarray(28)),d.final()]).toString('utf8');}
 createKey(o:Partial<Key> & {name:string}){
  const id=randomBytes(8).toString('hex'),token='agyp_'+id+'.'+secret();
  this.db.prepare('INSERT INTO keys VALUES(?,?,?,?,0,?,?,?,?,?,?)').run(id,o.name,digest(token),o.admin??0,o.expires??null,o.allowance??null,o.inputCap??null,o.outputCap??null,o.period??'never',Date.now());
  return {token,key:this.key(id)!};
 }
 key(id:string){return this.db.prepare('SELECT * FROM keys WHERE id=?').get(id) as Key|undefined;}
 valid(k:Key|undefined){return !!k&&!k.revoked&&(!k.expires||k.expires>Date.now());}
 auth(token:string){const id=/^agyp_([a-f0-9]{16})\.[\w-]{43}$/.exec(token)?.[1]??''; const k=this.key(id);const ok=equal(digest(token),k?.hash??'0'.repeat(64));return ok&&this.valid(k)?k:undefined;}
 safeKey(k:Key){const {hash,...safe}=k;return {...safe,used:this.used(k),resets:nextReset(k.period)};}
 keys(){return (this.db.prepare('SELECT * FROM keys ORDER BY created').all() as Key[]).map(k=>this.safeKey(k));}
 revoke(id:string){this.db.prepare('UPDATE keys SET revoked=1 WHERE id=? AND admin=0').run(id);this.db.prepare('DELETE FROM sessions WHERE key_id=?').run(id);}
 deleteKey(id:string){this.revoke(id);this.db.prepare("UPDATE keys SET name='Deleted key' WHERE id=? AND admin=0").run(id);}
 used(k:Key){
  return this.db.prepare(`SELECT COALESCE(SUM(input),0) input,COALESCE(SUM(output),0) output,COALESCE(SUM(total),0) total FROM (
 SELECT input,output,total FROM usage WHERE key_id=? AND time>=?
 UNION ALL SELECT input,output,input+output total FROM reservations WHERE key_id=? AND time>=?)`).get(k.id,windowStart(k.period),k.id,windowStart(k.period)) as {input:number;output:number;total:number};
 }
 reserve(k:Key,model:string,input:number,output:number){
  if(!this.valid(this.key(k.id)))throw Object.assign(new Error('Key expired or revoked'),{status:401});
  const used=this.used(k);
  if((k.allowance!==null&&used.total+input+output>k.allowance)||(k.inputCap!==null&&used.input+input>k.inputCap)||(k.outputCap!==null&&used.output+output>k.outputCap))
   throw Object.assign(new Error('Token allowance exhausted or insufficient for this request. Reset: '+(nextReset(k.period)?new Date(nextReset(k.period)!).toISOString():'never')),{status:429});
  const id=secret();this.db.prepare('INSERT INTO reservations VALUES(?,?,?,?,?,?)').run(id,k.id,model,input,output,Date.now());return id;
 }
 finish(id:string,u:Usage,status:number){const r=this.db.prepare('SELECT * FROM reservations WHERE id=?').get(id) as any;if(!r)return;
  this.db.exec('BEGIN IMMEDIATE');try{
   this.db.prepare('INSERT INTO usage(key_id,model,input,output,cached,total,time,status) VALUES(?,?,?,?,?,?,?,?,?)').run(r.key_id,r.model,u.input,u.output,u.cached,u.total,r.time,status);
   this.db.prepare('DELETE FROM reservations WHERE id=?').run(id);this.db.exec('COMMIT');
  }catch(e){this.db.exec('ROLLBACK');throw e;}
 }
 accounts(){return (this.db.prepare('SELECT value FROM accounts').all() as any[]).map(r=>JSON.parse(this.open(r.value)) as Account);}
 putAccount(a:Account){this.db.prepare('INSERT OR REPLACE INTO accounts VALUES(?,?)').run(a.id,this.seal(JSON.stringify(a)));}
 removeAccount(id:string){this.db.prepare('DELETE FROM accounts WHERE id=?').run(id);}
 stats(keyId?:string){
  const where=keyId?' WHERE key_id=?':'',args=keyId?[keyId]:[];
  return {models:this.db.prepare('SELECT key_id,model,SUM(input) input,SUM(output) output,SUM(cached) cached,SUM(input-cached) noncached,SUM(total) total,COUNT(*) requests FROM usage'+where+' GROUP BY key_id,model').all(...args),
  graph:this.db.prepare("SELECT strftime('%Y-%m-%d',time/1000,'unixepoch') day,SUM(input) input,SUM(output) output,SUM(cached) cached FROM usage"+where+' GROUP BY day ORDER BY day DESC LIMIT 90').all(...args).reverse()};
 }
 close(){this.db.close();}
}
