import {readFileSync} from 'node:fs';
import {Store} from './store.js';
process.umask(0o077);
const path=process.argv[2];
if(!path)throw new Error('Usage: node dist/server/import.js /private/import-accounts.json');
const rows=JSON.parse(readFileSync(path,'utf8'));
if(!Array.isArray(rows))throw new Error('Account array required');
const store=new Store(process.env.DATA_DIR??'./data');
let imported=0,skipped=0;
try{
 for(const r of rows){
  if(typeof r.id!=='string'||typeof r.email!=='string'||typeof r.refresh_token!=='string'||!r.refresh_token){skipped++;continue;}
  if(store.accounts().some(a=>a.id===r.id)){skipped++;continue;}
  const n=Number(r.token_expiry),expiry=Number.isFinite(n)?(n>0&&n<1e12?n*1000:n):Date.parse(r.token_expiry)||0;
  store.putAccount({id:r.id,email:r.email,refresh_token:r.refresh_token,access_token:typeof r.access_token==='string'?r.access_token:'',token_expiry:expiry,status:r.status==='disabled'?'disabled':'ready',shared:false,blocked:false,buckets:[],cooldowns:{},denied:{},updated:0});imported++;
 }
 console.log(JSON.stringify({imported,skipped,total:store.accounts().length}));
}finally{store.close();}
