// OFFLINE PACKET PRIMITIVE ONLY. Not imported by production and no CLI entrypoint.
// Execution requires fresh deployment approval, successful deployment verification,
// then the separately authorized postdeploy step. No provider requests are made.
import {type Store} from './store.js';
export function createPostdeployTestKey(store:Store,name:'test-5h-half'|'test-weekly-half',gate:{freshlyApprovedDeployVerified:boolean;postdeployStepApproved:boolean},now=Date.now()){
 if(!gate.freshlyApprovedDeployVerified||!gate.postdeployStepApproved)throw Error('Postdeploy gate closed');
 if(name!=='test-5h-half'&&name!=='test-weekly-half')throw Error('Unapproved test key name');
 store.db.exec('BEGIN IMMEDIATE');try{
  const executionId='postdeploy-test-key:'+name;
  if(store.db.prepare('SELECT 1 FROM settings WHERE id=?').get(executionId)||store.db.prepare('SELECT 1 FROM keys WHERE name=?').get(name))throw Error('Duplicate named key; stop, never create another');
  const result=store.createKey({name,admin:0,allowance:1000000,period:name==='test-5h-half'?'5h':'weekly'});
  // This explicitly TEST synthetic entry is the first accounted request. Its time
  // starts the fixed 5h window once, in the same transaction as key+usage creation.
  if(result.key.period==='5h')store.db.prepare('INSERT INTO key_windows VALUES(?,?,?)').run(result.key.id,now,now);
  store.db.prepare('INSERT INTO usage(key_id,model,input,output,cached,total,time,status) VALUES(?,?,500000,0,0,500000,?,200)').run(result.key.id,'test-synthetic-usage',now);
  store.db.prepare('INSERT INTO settings(id,value) VALUES(?,?)').run(executionId,JSON.stringify({keyId:result.key.id,name,created:now}));
  store.db.exec('COMMIT');return result; // token must be written privately, never logged.
 }catch(e){store.db.exec('ROLLBACK');throw e;}
}
