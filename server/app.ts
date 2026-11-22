import express,{type Request,type Response,type NextFunction} from 'express';
import helmet from 'helmet';
import {rateLimit} from 'express-rate-limit';
import {parse,serialize} from 'cookie';
import {z} from 'zod';
import {randomBytes,createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {Store,digest,secret,type Key} from './store.js';
import {Pool} from './pool.js';
import {proxy} from './proxy.js';

export type Config={origin:string;upstream:string;clientId:string;clientSecret:string;oauthRedirect?:string;secure:boolean;trustedProxy?:string[];loginLimit?:number};
const keySchema=z.object({name:z.string().trim().min(1).max(100),allowance:z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).nullable().default(null),inputCap:z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).nullable().default(null),outputCap:z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).nullable().default(null),period:z.enum(['never','daily','weekly','monthly']).default('never'),expires:z.number().int().min(1).max(8640000000000000).nullable().default(null)}).strict();
export function createApp(store:Store,config:Config){
 const app=express(),pool=new Pool(store,config.upstream,config.clientId,config.clientSecret);
 app.disable('x-powered-by');if(config.trustedProxy?.length)app.set('trust proxy',config.trustedProxy);
 app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'"],imgSrc:["'self'","data:"],connectSrc:["'self'"],objectSrc:["'none'"],baseUri:["'none'"],frameAncestors:["'none'"],formAction:["'self'"],upgradeInsecureRequests:config.secure?[]:null}},strictTransportSecurity:config.secure?{maxAge:31536000,includeSubDomains:false}:false}));
 app.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
 const json=express.json({limit:'32kb'});
 function sameOrigin(req:Request,res:Response,next:NextFunction){const origin=req.headers.origin;if(origin&&origin!==config.origin){res.status(403).json({error:{message:'Origin rejected'}});return;}if(req.headers['sec-fetch-site']==='cross-site'){res.status(403).json({error:{message:'Cross-site request rejected'}});return;}next();}
 const handshakeLimit=rateLimit({windowMs:60_000,limit:config.loginLimit??30,standardHeaders:'draft-8',legacyHeaders:false});
 const globalHandshake=rateLimit({windowMs:60_000,limit:1000,keyGenerator:()=> 'all',standardHeaders:false,legacyHeaders:false});
 app.use('/auth',sameOrigin,handshakeLimit,globalHandshake);
 app.post('/auth/challenge',json,(req,res)=>{
  const p=z.object({keyId:z.string().regex(/^[a-f0-9]{16}$/)}).strict().parse(req.body);
  res.json(store.challenge(p.keyId));
 });
 app.post('/auth/verify',json,(req,res)=>{
  const p=z.object({keyId:z.string().regex(/^[a-f0-9]{16}$/),nonce:z.string().regex(/^[A-Za-z0-9_-]{43}$/),proof:z.string().regex(/^[a-f0-9]{64}$/),client:z.enum(['web','cli'])}).strict().parse(req.body);
  const k=store.verify(p.keyId,p.nonce,p.proof);if(!k){res.status(401).json({error:{message:'Invalid or expired proof'}});return;}
  const s=store.session(k);
  if(p.client==='web'){res.setHeader('Set-Cookie',serialize('agyp_session',s.token,{httpOnly:true,secure:config.secure,sameSite:'strict',path:'/',maxAge:900}));res.json({csrf:s.csrf,expires:s.expires});}
  else res.json({token:s.token,expires:s.expires});
 });
 // The login shell and its static assets are deliberately unauthenticated; all data requires a session.
 app.get('/',(_req,res)=>res.sendFile(resolve('web/index.html')));
 app.get('/app.js',(_req,res)=>res.sendFile(resolve('web/app.js')));
 app.get('/style.css',(_req,res)=>res.sendFile(resolve('web/style.css')));
 app.use('/assets',express.static(resolve('web'),{index:false,dotfiles:'deny',fallthrough:true,redirect:false}));
 app.get('/assets/chart.js',(_req,res)=>res.sendFile(resolve('node_modules/chart.js/dist/chart.umd.js')));
 const auth=(req:Request,res:Response,next:NextFunction)=>{
  const header=req.headers.authorization, bearer=header?.startsWith('Bearer ')?header.slice(7):undefined;
  const cookie=parse(req.headers.cookie??'').agyp_session;const token=bearer??cookie;
  const s=token?store.authSession(token):undefined;
  if(!s){res.status(401).json({error:{message:'Session required'}});return;}
  res.locals.key=s.key;res.locals.csrf=s.csrf;res.locals.sessionExpires=s.expires;res.locals.sessionToken=token;
  if(!['GET','HEAD','OPTIONS'].includes(req.method)&&!bearer){if(req.headers.origin!==config.origin||req.headers['x-csrf-token']!==s.csrf){res.status(403).json({error:{message:'CSRF check failed'}});return;}}
  next();
 };
 app.post('/auth/logout',auth,(_req,res)=>{store.db.prepare('DELETE FROM sessions WHERE hash=?').run(digest(res.locals.sessionToken));res.setHeader('Set-Cookie',serialize('agyp_session','',{httpOnly:true,secure:config.secure,sameSite:'strict',path:'/',maxAge:0}));res.json({ok:true});});
 // OAuth redirects are bound to a still-valid admin session and a single-use state/PKCE verifier.
 async function finishOAuth(code:string,state:string,sessionHash?:string){
  const o=store.db.prepare('DELETE FROM oauth WHERE state=? RETURNING *').get(state) as any;
  if(!o||o.expires<Date.now()||(sessionHash&&sessionHash!==o.session_hash))throw Object.assign(new Error('Expired OAuth state'),{status:400});
  const sess=store.db.prepare('SELECT * FROM sessions WHERE hash=?').get(o.session_hash) as any;
  if(!sess||sess.expires<Date.now()||!store.valid(store.key(sess.key_id))||!store.key(sess.key_id)?.admin)throw Object.assign(new Error('Admin session expired'),{status:401});
  const client=pool.oauth(o.redirect);const {tokens}=await client.getToken({code,codeVerifier:o.verifier,redirect_uri:o.redirect});
  if(!tokens.refresh_token)throw Object.assign(new Error('Google did not return a refresh token. Retry with consent.'),{status:400});
  const profile=await fetch('https://www.googleapis.com/oauth2/v2/userinfo',{headers:{authorization:'Bearer '+tokens.access_token},redirect:'error',signal:AbortSignal.timeout(20000)});
  if(!profile.ok)throw new Error('Google profile failed');const user=await profile.json() as any;
  if(typeof user.email!=='string'||!user.verified_email)throw new Error('Verified Google email required');
  const existing=store.accounts().find(a=>a.email===user.email),id=existing?.id??randomBytes(16).toString('hex');
  store.putAccount({id,email:user.email,refresh_token:tokens.refresh_token,access_token:tokens.access_token??'',token_expiry:tokens.expiry_date??0,status:'ready',shared:false,blocked:false,buckets:[],cooldowns:{},denied:{},updated:0});
  await pool.poll(id).catch(()=>{});return id;
 }
 app.get('/oauth/callback',async(req,res)=>{await finishOAuth(z.string().parse(req.query.code),z.string().parse(req.query.state));res.redirect('/');});
 app.use('/api',sameOrigin,auth,json);
 const admin=(req:Request,res:Response,next:NextFunction)=>{if(!(res.locals.key as Key).admin){res.status(403).json({error:{message:'Administrator required'}});return;}next();};
 app.get('/api/me',(_req,res)=>res.json({key:store.safeKey(res.locals.key),csrf:res.locals.csrf,sessionExpires:res.locals.sessionExpires}));
 app.get('/api/stats',(_req,res)=>res.json(store.stats(res.locals.key.admin?undefined:res.locals.key.id)));
 app.get('/api/keys',admin,(_req,res)=>res.json({keys:store.keys()}));
 app.post('/api/keys',admin,(req,res)=>{const k=store.createKey(keySchema.parse(req.body));res.status(201).json({token:k.token,key:store.safeKey(k.key)});});
 app.post('/api/keys/:id/revoke',admin,(req,res)=>{store.revoke(String(req.params.id));res.json({ok:true});});
 app.delete('/api/keys/:id',admin,(req,res)=>{store.deleteKey(String(req.params.id));res.json({ok:true});});
 app.get('/api/accounts',admin,(_req,res)=>res.json({accounts:pool.safe(),active:pool.active}));
 app.post('/api/accounts/:id/refresh',admin,async(req,res)=>{await pool.poll(String(req.params.id));res.json({ok:true});});
 app.post('/api/accounts/:id/toggle',admin,(req,res)=>{const a=store.accounts().find(a=>a.id===req.params.id);if(!a){res.sendStatus(404);return;}a.status=a.status==='disabled'?'ready':'disabled';store.putAccount(a);res.json({ok:true});});
 app.delete('/api/accounts/:id',admin,(req,res)=>{store.removeAccount(String(req.params.id));res.json({ok:true});});
 app.post('/api/oauth/start',admin,async(_req,res)=>{
  const redirect=config.oauthRedirect??config.origin+'/oauth/callback',client=pool.oauth(redirect),state=secret(),verifier=secret()+secret();
  store.db.prepare('DELETE FROM oauth WHERE expires<=?').run(Date.now());store.db.prepare('INSERT INTO oauth VALUES(?,?,?,?,?)').run(state,digest(res.locals.sessionToken),verifier,redirect,Date.now()+600_000);
  const url=client.generateAuthUrl({access_type:'offline',prompt:'consent',scope:['openid','https://www.googleapis.com/auth/userinfo.email','https://www.googleapis.com/auth/userinfo.profile','https://www.googleapis.com/auth/cloud-platform'],state,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256' as any});
  res.json({url,manual:new URL(redirect).origin!==config.origin});
 });
 app.post('/api/oauth/complete',admin,async(req,res)=>{
  const p=z.object({callbackUrl:z.string().url().max(8192)}).parse(req.body),url=new URL(p.callbackUrl);
  if(url.origin!==new URL(config.oauthRedirect??config.origin).origin)throw Object.assign(new Error('Unexpected OAuth callback origin'),{status:400});
  const id=await finishOAuth(z.string().parse(url.searchParams.get('code')),z.string().parse(url.searchParams.get('state')),digest(res.locals.sessionToken));res.json({ok:true,id});
 });
 app.use((req,res,next)=>{if(!/^\/v1(?:internal|beta)?(?=[:/]|$)/.test(req.path)){res.status(404).json({error:{message:'Not found'}});return;}next();},sameOrigin,auth,express.raw({type:()=>true,limit:'16mb'}),async(req,res)=>{
  // app.use trims the prefix; originalUrl retains the exact upstream path.
  const saved=req.url;req.url=req.originalUrl;
  try{await proxy(req,res,res.locals.key,store,pool);}finally{req.url=saved;}
 });
 app.use((_req,res)=>res.status(404).json({error:{message:'Not found'}}));
 app.use((err:any,_req:Request,res:Response,_next:NextFunction)=>{if(res.headersSent){res.destroy();return;}const status=err instanceof z.ZodError?400:err.status??500;res.status(status).json({error:{message:status>=500?'Request failed':err.message}});});
 return {app,pool};
}
