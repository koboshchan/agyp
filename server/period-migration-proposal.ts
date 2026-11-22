// OFFLINE DEPLOYMENT PACKET ONLY. No production imports or automatic execution.
// Caller must separately obtain execution approval and a verified consistent backup.
import {type Store,windowStart} from './store.js';
function oldState(k:any){return {id:k.id,name:k.name,admin:k.admin,revoked:k.revoked,expires:k.expires,allowance:k.allowance,inputCap:k.inputCap,outputCap:k.outputCap,period:k.period,created:k.created};}
const targets=[{name:'makieify',oldCap:10_000_000,newCap:2_000_000}] as const;
export function proposedPeriodMigration(store:Store,now=Date.now()){
 const start=windowStart('daily',now);
 return targets.map(t=>{
  const rows=store.db.prepare('SELECT * FROM keys WHERE name=?').all(t.name) as any[];
  if(rows.length!==1)throw Error('Expected exactly one named migration target: '+t.name);
  const k=rows[0];if((k.expires!==null&&k.expires<=now)||k.admin||k.revoked||k.period!=='daily'||k.allowance!==t.oldCap||k.inputCap!==null||k.outputCap!==null)throw Error('Unexpected old configuration: '+t.name);
  const usage=store.db.prepare('SELECT COUNT(*) requests,COALESCE(SUM(input),0) input,COALESCE(SUM(output),0) output,COALESCE(SUM(cached),0) cached,COALESCE(SUM(total),0) total FROM usage WHERE key_id=? AND time>=?').get(k.id,start);
  return {oldState:oldState(k),id:k.id,name:t.name,oldPeriod:'daily',oldCap:t.oldCap,newPeriod:'5h',newCap:t.newCap,accountingStart:start,cutover:now,anchor:null,usage};
 });
}
export type PeriodMigrationPlan=ReturnType<typeof proposedPeriodMigration>;
// Testable packet primitive, intentionally not exposed through any API or CLI.
// Exact proposal equality protects config, key identity, usage AND UTC-day cutoff.
export function applyApprovedPeriodMigration(store:Store,expected:PeriodMigrationPlan,now=Date.now()){
 store.db.exec('BEGIN IMMEDIATE');try{
  // Retry only when the target already have the exact planned state. Never
  // overwrite an anchor after a first request or silently accept partial state.
  const completed=expected.length===1&&targets.every(t=>expected.some(e=>e.name===t.name&&e.oldCap===t.oldCap&&e.newCap===t.newCap&&e.oldPeriod==='daily'&&e.newPeriod==='5h'&&e.anchor===null&&e.accountingStart===windowStart('daily',e.cutover)))&&expected.every(e=>{
   const k=store.key(e.id),w=store.db.prepare('SELECT * FROM key_windows WHERE key_id=?').get(e.id) as any;
   const named=store.db.prepare('SELECT COUNT(*) n FROM keys WHERE name=?').get(e.name) as any;
   return named.n===1&&k&&JSON.stringify(oldState({...k,period:e.oldPeriod,allowance:e.oldCap}))===JSON.stringify(e.oldState)&&(k.expires===null||k.expires>now)&&k?.name===e.name&&!k.admin&&!k.revoked&&k.period==='5h'&&k.allowance===e.newCap&&k.inputCap===null&&k.outputCap===null&&w?.accounting_start===e.accountingStart;
  });
  if(completed){store.db.exec('COMMIT');return 'already-applied' as const;}
  if(expected.length!==1||expected[0].cutover>now||windowStart('daily',now)!==expected[0].accountingStart)throw Error('Migration cutoff changed; new review required');
  const active=store.key(expected[0].id);if(!active||(active.expires!==null&&active.expires<=now))throw Error('Migration target expired');
  const fresh=proposedPeriodMigration(store,expected[0].cutover);
  if(JSON.stringify(fresh)!==JSON.stringify(expected))throw Error('Migration snapshot changed; new review required');
  for(const e of fresh){
   if(store.db.prepare('SELECT 1 FROM key_windows WHERE key_id=?').get(e.id))throw Error('Unexpected existing period window');
   const result=store.db.prepare("UPDATE keys SET period='5h',allowance=? WHERE id=? AND name=? AND period='daily' AND allowance=? AND admin=0 AND revoked=0 AND inputCap IS NULL AND outputCap IS NULL").run(e.newCap,e.id,e.name,e.oldCap);
   if(result.changes!==1)throw Error('Migration configuration changed');
   store.db.prepare('INSERT INTO key_windows(key_id,anchor,accounting_start) VALUES(?,NULL,?)').run(e.id,e.accountingStart);
  }
  store.db.exec('COMMIT');return 'applied' as const;
 }catch(e){store.db.exec('ROLLBACK');throw e;}
}
