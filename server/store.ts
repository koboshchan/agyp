import { DatabaseSync } from 'node:sqlite';
import { randomBytes, createHash, createHmac, timingSafeEqual, createCipheriv, createDecipheriv } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { join } from 'node:path';

export type Key = {id:string; name:string; token:string; admin:number; revoked:number; expires:number|null; allowance:number|null; inputCap:number|null; outputCap:number|null; period:string; created:number};
export type Account = {id:string; email:string; refresh_token:string; access_token:string; token_expiry:number; status:string; shared:boolean; blocked:boolean; buckets:any[]; cooldowns:Record<string,number>; denied:Record<string,number>; updated:number; verification?:{url:string;observedAt:number}};
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
 CREATE TABLE IF NOT EXISTS keys(id TEXT PRIMARY KEY,name TEXT,token TEXT,admin INTEGER,revoked INTEGER DEFAULT 0,expires INTEGER,allowance INTEGER,inputCap INTEGER,outputCap INTEGER,period TEXT,created INTEGER);
 CREATE TABLE IF NOT EXISTS key_windows(key_id TEXT PRIMARY KEY,anchor INTEGER,accounting_start INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS settings(id TEXT PRIMARY KEY,value TEXT);
 CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY,value TEXT);
 CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,key_id TEXT,csrf TEXT,expires INTEGER);
 CREATE TABLE IF NOT EXISTS usage(id INTEGER PRIMARY KEY,key_id TEXT,model TEXT,input INTEGER,output INTEGER,cached INTEGER,total INTEGER,time INTEGER,status INTEGER);
 CREATE INDEX IF NOT EXISTS usage_key_time ON usage(key_id,time);
 CREATE TABLE IF NOT EXISTS reservations(id TEXT PRIMARY KEY,key_id TEXT,model TEXT,input INTEGER,output INTEGER,time INTEGER);
 CREATE TABLE IF NOT EXISTS challenges(nonce TEXT PRIMARY KEY,key_id TEXT,expires INTEGER);
 CREATE TABLE IF NOT EXISTS oauth(state TEXT PRIMARY KEY,session_hash TEXT,verifier TEXT,redirect TEXT,expires INTEGER);
 `);
  // No fabricated charge for interrupted requests without recorded provider usage.
  this.db.exec('DELETE FROM reservations;');
  const admin=this.db.prepare('SELECT token FROM keys WHERE admin=1').get() as any;
  this.adminToken=admin?.token??this.createKey({name:'Administrator',admin:1}).token;
 }
 seal(s:string){const iv=randomBytes(12),c=createCipheriv('aes-256-gcm',this.master,iv);const data=Buffer.concat([c.update(s,'utf8'),c.final()]);return Buffer.concat([iv,c.getAuthTag(),data]).toString('base64');}
 open(s:string){const b=Buffer.from(s,'base64'),d=createDecipheriv('aes-256-gcm',this.master,b.subarray(0,12));d.setAuthTag(b.subarray(12,28));return Buffer.concat([d.update(b.subarray(28)),d.final()]).toString('utf8');}
 createKey(o:Partial<Key> & {name:string}){
  const id=randomBytes(8).toString('hex'),token='agyp_'+id+'.'+secret();
  this.db.prepare('INSERT INTO keys VALUES(?,?,?,?,0,?,?,?,?,?,?)').run(id,o.name,token,o.admin??0,o.expires??null,o.allowance??null,o.inputCap??null,o.outputCap??null,o.period??'never',Date.now());
  return {token,key:this.key(id)!};
 }
 key(id:string){return this.db.prepare('SELECT * FROM keys WHERE id=?').get(id) as Key|undefined;}
 valid(k:Key|undefined){return !!k&&!k.revoked&&(!k.expires||k.expires>Date.now());}
 challenge(id:string){
  this.db.prepare('DELETE FROM challenges WHERE expires<=?').run(Date.now());
  const nonce=secret(),expires=Date.now()+60_000;
  this.db.prepare('INSERT INTO challenges VALUES(?,?,?)').run(nonce,id,expires);
  return {nonce,expires};
 }
 verify(id:string,nonce:string,proof:string){
  const c=this.db.prepare('DELETE FROM challenges WHERE nonce=? RETURNING *').get(nonce) as any;
  const k=this.key(id),expected=createHmac('sha256',k?.token??this.master).update(nonce).digest('hex');
  const matches=equal(expected,/^[a-f0-9]{64}$/.test(proof)?proof:'0'.repeat(64));
  return matches&&c&&c.key_id===id&&c.expires>Date.now()&&this.valid(k)?k:undefined;
 }
 session(k:Key){
  this.db.prepare('DELETE FROM sessions WHERE expires<=?').run(Date.now());
  const token=secret(),csrf=secret(),expires=Math.min(Date.now()+15*60_000,k.expires??Infinity);
  this.db.prepare('INSERT INTO sessions VALUES(?,?,?,?)').run(digest(token),k.id,csrf,expires);return {token,csrf,expires};
 }
 authSession(token:string){
  const s=this.db.prepare('SELECT * FROM sessions WHERE hash=?').get(digest(token)) as any;
  const k=s?this.key(s.key_id):undefined;return s&&s.expires>Date.now()&&this.valid(k)?{key:k!,csrf:s.csrf as string,expires:s.expires as number}:undefined;
 }
 keyReset(k:Key,now=Date.now()){if(k.period!=='5h')return nextReset(k.period,now);const w=this.db.prepare('SELECT anchor FROM key_windows WHERE key_id=?').get(k.id) as {anchor:number|null}|undefined;return w?.anchor!=null&&now<w.anchor+18_000_000?w.anchor+18_000_000:null;}
 safeKey(k:Key){const {token,...safe}=k;return {...safe,used:this.used(k),resets:this.keyReset(k)};}
 keys(){return (this.db.prepare('SELECT * FROM keys ORDER BY created').all() as Key[]).map(k=>this.safeKey(k));}
 revoke(id:string){this.db.prepare('UPDATE keys SET revoked=1 WHERE id=? AND admin=0').run(id);this.db.prepare('DELETE FROM sessions WHERE key_id=?').run(id);}
 deleteKey(id:string){this.revoke(id);this.db.prepare("UPDATE keys SET name='Deleted key' WHERE id=? AND admin=0").run(id);}
 used(k:Key,now=Date.now()){
  let start=windowStart(k.period,now);
  if(k.period==='5h'){
   const w=this.db.prepare('SELECT anchor,accounting_start FROM key_windows WHERE key_id=?').get(k.id) as {anchor:number|null;accounting_start:number}|undefined;
   if(!w)return {input:0,output:0,total:0};
   if(w.anchor!==null&&now>=w.anchor+18_000_000)return {input:0,output:0,total:0};
   start=w.accounting_start;
  }
  return this.db.prepare(`SELECT COALESCE(SUM(input),0) input,COALESCE(SUM(output),0) output,COALESCE(SUM(total),0) total FROM usage WHERE key_id=? AND time>=?`).get(k.id,start) as {input:number;output:number;total:number};
 }
 reserve(k:Key,model:string,_input:number,_output:number,admit=true){
  // One synchronous SQLite write transaction serializes first-request anchoring
  // and expiry/admission across connections. Control traffic never starts a window.
  this.db.exec('BEGIN IMMEDIATE');try{
   const current=this.key(k.id);if(!this.valid(current))throw Object.assign(new Error('Key expired or revoked'),{status:401});
   const key=current!,now=Date.now();
   if(admit&&key.period==='5h'){
    const w=this.db.prepare('SELECT anchor FROM key_windows WHERE key_id=?').get(key.id) as {anchor:number|null}|undefined;
    if(!w)this.db.prepare('INSERT INTO key_windows VALUES(?,?,?)').run(key.id,now,now);
    else if(w.anchor===null)this.db.prepare('UPDATE key_windows SET anchor=? WHERE key_id=?').run(now,key.id);
    else if(now>=w.anchor+18_000_000)this.db.prepare('UPDATE key_windows SET anchor=?,accounting_start=? WHERE key_id=?').run(now,now,key.id);
   }
   const used=this.used(key,now),reset=this.keyReset(key,now);
   if(admit&&((key.allowance!==null&&used.total>=key.allowance)||(key.inputCap!==null&&used.input>=key.inputCap)||(key.outputCap!==null&&used.output>=key.outputCap)))
    {this.db.exec('COMMIT');throw Object.assign(new Error('Token allowance exhausted. Reset: '+(reset?new Date(reset).toISOString():'never')),{status:429});}
   const id=secret();this.db.prepare('INSERT INTO reservations VALUES(?,?,?,?,?,?)').run(id,key.id,model,0,0,now);
   this.db.exec('COMMIT');return id;
  }catch(e){if(this.db.isTransaction)this.db.exec('ROLLBACK');throw e;}
 }

 finish(id:string,u:Usage,status:number){const r=this.db.prepare('SELECT * FROM reservations WHERE id=?').get(id) as any;if(!r)return;
  this.db.exec('BEGIN IMMEDIATE');try{
   this.db.prepare('INSERT INTO usage(key_id,model,input,output,cached,total,time,status) VALUES(?,?,?,?,?,?,?,?)').run(r.key_id,r.model,u.input,u.output,u.cached,u.total,r.time,status);
   this.db.prepare('DELETE FROM reservations WHERE id=?').run(id);this.db.exec('COMMIT');
  }catch(e){this.db.exec('ROLLBACK');throw e;}
 }
 accounts(){return (this.db.prepare('SELECT value FROM accounts').all() as any[]).map(r=>JSON.parse(this.open(r.value)) as Account);}
 putAccount(a:Account){this.db.prepare('INSERT OR REPLACE INTO accounts VALUES(?,?)').run(a.id,this.seal(JSON.stringify(a)));}
 removeAccount(id:string){this.db.prepare('DELETE FROM accounts WHERE id=?').run(id);}
 stats(keyId?:string){
  const where=keyId?' WHERE key_id=?':'',args=keyId?[keyId]:[];
  const models=this.db.prepare('SELECT key_id,model,SUM(input) input,SUM(output) output,SUM(cached) cached,SUM(input-cached) noncached,SUM(total) total,COUNT(*) requests'+(keyId?'':',k.name key_name,k.revoked key_revoked')+' FROM usage'+(keyId?'':' LEFT JOIN keys k ON k.id=usage.key_id')+where+' GROUP BY key_id,model ORDER BY key_id,model').all(...args);
  const overview=this.db.prepare('SELECT model,SUM(input) input,SUM(output) output,SUM(cached) cached,SUM(input-cached) noncached,SUM(total) total,COUNT(*) requests FROM usage'+where+(keyId?" AND":" WHERE")+" model != '(control)' GROUP BY model ORDER BY model").all(...args);
  const control=this.db.prepare('SELECT COUNT(*) requests,COALESCE(SUM(input),0) input,COALESCE(SUM(output),0) output,COALESCE(SUM(cached),0) cached,COALESCE(SUM(total),0) total FROM usage'+where+(keyId?' AND':' WHERE')+" model = '(control)'").get(...args);
  return {models,overview,control,
  graph:this.db.prepare("SELECT strftime('%Y-%m-%d',time/1000,'unixepoch') day,SUM(input) input,SUM(output) output,SUM(cached) cached FROM usage"+where+' GROUP BY day ORDER BY day DESC LIMIT 90').all(...args).reverse()};
 }
 close(){this.db.close();}
}
