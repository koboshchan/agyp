import {Store} from './store.js';
import {createApp} from './app.js';

process.umask(0o077);
const port=Number(process.env.PORT??'54873'),origin=process.env.PUBLIC_ORIGIN??'https://agy.kjt.lol';
if(!Number.isInteger(port)||port<1||port>65535)throw new Error('Invalid PORT');
const store=new Store(process.env.DATA_DIR??'./data');
const {app,pool}=createApp(store,{origin,upstream:process.env.UPSTREAM_BASE??'https://daily-cloudcode-pa.googleapis.com',clientId:process.env.GOOGLE_CLIENT_ID??'',clientSecret:process.env.GOOGLE_CLIENT_SECRET??'',oauthRedirect:process.env.OAUTH_REDIRECT_URI,secure:new URL(origin).protocol==='https:',trustedProxy:process.env.TRUSTED_PROXIES?.split(',').map(s=>s.trim()).filter(Boolean)});
const server=app.listen(port,'0.0.0.0',()=>{console.log('agyp listening on port '+port);console.log('Administrator token: '+store.adminToken);});
server.requestTimeout=660_000;server.headersTimeout=30_000;
// One bounded poller, no overlap, no detached processes. No external calls in test mode.
let stopping=false;
async function pollAll(){for(const a of store.accounts()){if(stopping)break;if(a.status==='disabled')continue;await pool.poll(a.id).catch(()=>{});}}
const timer=process.env.DISABLE_POLLER==='1'?undefined:setInterval(()=>{void pollAll();},300_000);
if(timer){timer.unref();void pollAll();}
function shutdown(){if(stopping)return;stopping=true;clearInterval(timer);server.close(()=>{store.close();process.exit(0);});setTimeout(()=>process.exit(1),15_000).unref();}
process.on('SIGTERM',shutdown);process.on('SIGINT',shutdown);
