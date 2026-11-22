// Real Express + SQLite + Chromium integration, with no auth/API interception.
// Run CHROME_BIN=/opt/hako/bin/google-chrome npx tsx test/integration-browser.ts.
import { chromium, expect } from '@playwright/test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, type Server } from 'node:http';
import { createHmac } from 'node:crypto';
import { Store } from '../server/store.js';
import { createApp } from '../server/app.js';

async function listen(server:Server, port=0) {
  await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',()=>{server.off('error',reject);resolve();});});
  const address=server.address();assert.ok(address&&typeof address==='object');return address.port;
}
async function close(server:Server) {server.closeAllConnections();await new Promise<void>((resolve,reject)=>server.close(e=>e?reject(e):resolve()));}
const dir=await mkdtemp(join(tmpdir(),'agyp-browser-'));
const store=new Store(dir);
// Reserve a random port before building Config, so origin matches the actual listener.
const reservation=createServer();const port=await listen(reservation);await close(reservation);
const origin=`http://127.0.0.1:${port}`;
const {app}=createApp(store,{origin,secure:false,upstream:origin,clientId:'integration',clientSecret:'integration',loginLimit:1000});
const server=createServer(app);
let browser:Awaited<ReturnType<typeof chromium.launch>>|undefined;
try {
  await listen(server,port);
  browser=await chromium.launch({executablePath:process.env.CHROME_BIN||undefined,args:['--no-sandbox']});
  for(const device of ['desktop','mobile'] as const) for(const theme of ['light','dark'] as const) {
  store.db.exec('DELETE FROM usage; DELETE FROM sessions;');
  const context=await browser.newContext({viewport:device==='desktop'?{width:1440,height:1000}:{width:390,height:844},colorScheme:theme});const page=await context.newPage();
  const errors:string[]=[];
  const authRequests:{path:string;body:any;wire:string}[]=[];
  page.on('console',m=>{if(m.type()==='error'&&!(m.location().url.endsWith('/favicon.ico')&&m.text().includes('404'))&&!/^Failed to load resource: the server responded with a status of (401|403) \(/.test(m.text()))errors.push(m.text()+' '+m.location().url);});
  await page.addInitScript(()=>{document.addEventListener('securitypolicyviolation',e=>{console.error('CSP violation '+e.violatedDirective+' '+e.blockedURI);});});
  page.on('pageerror',e=>errors.push(e.message));
  page.on('request',req=>{const path=new URL(req.url()).pathname;if(path.startsWith('/auth/'))authRequests.push({path,body:req.postDataJSON(),wire:JSON.stringify({url:req.url(),headers:req.headers(),body:req.postData()})});});
  async function login(token:string) {
    await expect(page.locator('#login')).toBeVisible();
    await page.fill('#token',token);await page.click('#login-form button');
    await expect(page.locator('#dashboard')).toBeVisible();
    await expect(page.locator('#loading')).toBeHidden();
    assert.equal(await page.inputValue('#token'),'');
    const verify=authRequests.filter(r=>r.path==='/auth/verify').at(-1)!;
    const challenge=authRequests.filter(r=>r.path==='/auth/challenge').at(-1)!;
    assert.equal(challenge.body.keyId,token.slice(5).split('.')[0]);
    assert.equal(verify.body.proof,createHmac('sha256',token).update(verify.body.nonce).digest('hex'));
    assert.equal(verify.body.client,'web');
    assert.ok(authRequests.every(r=>!r.wire.includes(token)),'raw permanent key must not appear in auth requests');
  }
  async function api(path:string,method='GET',body?:object,headers:Record<string,string>={}) {
    return page.evaluate(async ({path,method,body,headers})=>{
      const r=await fetch(path,{method,headers:{...(body?{'Content-Type':'application/json'}:{}),...headers},body:body?JSON.stringify(body):undefined});
      return {status:r.status,body:await r.json()};
    },{path,method,body,headers});
  }
  await page.goto(origin);await login(store.adminToken);
  async function noOverflow() { assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`${device}/${theme} overflow`); }
  await noOverflow();
  for(const view of ['accounts','keys','overview']) { await page.locator(`[data-view=${view}]:visible`).first().click();await noOverflow(); }

  const cookie=(await context.cookies()).find(c=>c.name==='agyp_session');
  assert.ok(cookie?.httpOnly);assert.equal(cookie.sameSite,'Strict');
  assert.equal((await api('/api/keys')).status,200);
  assert.equal((await api('/api/accounts')).status,200);
  // Valid cookie without CSRF proof must not authorize mutations.
  const count=store.keys().length;
  assert.equal((await api('/api/keys','POST',{name:'csrf forbidden'})).status,403);
  assert.equal(store.keys().length,count);
  assert.equal((await api('/auth/logout','POST',{})).status,403);
  const me=await api('/api/me');
  const cross=await context.request.post(origin+'/api/keys',{headers:{Origin:'https://attacker.invalid','X-CSRF-Token':me.body.csrf},data:{name:'cross origin forbidden'}});
  assert.equal(cross.status(),403);assert.equal(store.keys().length,count);
  await page.locator('[data-view=keys]:visible').first().click();await page.click('#add-key');
  await page.fill('#key-name','Integration personal');await page.fill('#key-allowance','120000');
  await page.fill('#key-input','80000');await page.fill('#key-output','40000');await page.selectOption('#key-period','weekly');
  await page.fill('#key-expiry','2099-01-02T12:30');
  await page.click('#key-form button[type=submit]');await expect(page.locator('#secret-dialog')).toBeVisible();
  const token=await page.inputValue('#new-secret');assert.ok(/^agyp_[a-f0-9]{16}\./.test(token),'UI returns a real key');
  const key=store.key(token.slice(5).split('.')[0])!;
  assert.equal(key.admin,0);assert.equal(key.allowance,120000);assert.equal(key.inputCap,80000);assert.equal(key.outputCap,40000);assert.equal(key.period,'weekly');assert.ok(key.expires!>Date.now());
  await page.locator('#secret-dialog').getByRole('button',{name:'Close',exact:true}).click();assert.equal(await page.inputValue('#new-secret'),'');
  // Seed usage through the real Store accounting path, not a mocked stats response.
  const model='<img src=x onerror=alert(1)>';
  store.finish(store.reserve(key,model,120,30),{input:120,output:30,cached:20,total:150},200);
  const admin=store.keys().find(k=>k.admin)!;
  store.finish(store.reserve(store.key(admin.id)!,'admin-only-model',900,90),{input:900,output:90,cached:0,total:990},200);
  await page.locator(device==='mobile'?'#mobile-logout':'#logout').click();await expect(page.locator('#login')).toBeVisible();
  assert.equal((await api('/api/me')).status,401);
  assert.equal((await context.cookies()).some(c=>c.name==='agyp_session'),false);
  await login(token);
  assert.equal(await page.locator('.admin-only:visible').count(),0);
  await expect(page.locator('#accounts-view')).toBeHidden();await expect(page.locator('#keys-view')).toBeHidden();
  assert.equal((await api('/api/accounts')).status,403);assert.equal((await api('/api/keys')).status,403);
  const userMe=await api('/api/me');assert.equal(userMe.body.key.id,key.id);assert.equal(userMe.body.key.token,undefined);
  const forbidden=await api('/api/keys','POST',{name:'privilege escalation'},{'X-CSRF-Token':userMe.body.csrf});assert.equal(forbidden.status,403);
  const stats=await api('/api/stats');assert.equal(stats.status,200);assert.equal(stats.body.models.length,1);
  assert.equal(stats.body.models[0].key_id,key.id);assert.equal(stats.body.models[0].cached,20);assert.equal(stats.body.models[0].total,150);
  assert.equal(stats.body.graph.length,1);assert.equal(stats.body.graph[0].input,120);
  await expect.poll(()=>page.locator('#chart svg').count()).toBeGreaterThanOrEqual(1);
  const fills=await page.locator('#chart .recharts-bar-rectangle path').evaluateAll(nodes=>nodes.map(n=>getComputedStyle(n).fill));
  assert.ok(fills.length>0 && fills.every(c=>c!=='rgb(0, 0, 0)'&&c!=='none'),'chart bars must resolve external CSS colors under production CSP');
  assert.equal(await page.locator('#models img').count(),0);assert.ok((await page.locator('#models').innerText()).includes(model));
  assert.ok(!(await page.locator('#models').innerText()).includes('admin-only-model'));
  await expect(page.locator('#models th').first()).toContainText('Model');
  assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
  await noOverflow();
  await page.reload();await expect(page.locator('#dashboard')).toBeVisible();await expect(page.locator('#loading')).toBeHidden();
  await page.setViewportSize({width:390,height:844});await expect(page.locator('#mobile-logout')).toBeVisible();
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);

  await page.click('#mobile-logout');await expect(page.locator('#login')).toBeVisible();assert.equal((await api('/api/me')).status,401);
  assert.equal(await page.locator('#chart svg').count(),0);
  assert.ok(authRequests.every(r=>!r.wire.includes(token)&&!r.wire.includes(store.adminToken)),'no raw permanent keys in auth network data');
  // Expire a real persisted session and verify reload cannot restore its data.
  await login(token);
  store.db.prepare('UPDATE sessions SET expires=? WHERE key_id=?').run(Date.now()-1,key.id);
  assert.equal((await api('/api/me')).status,401);
  await page.click('#refresh');await expect(page.locator('#login')).toBeVisible();
  assert.equal(await page.locator('#chart svg').count(),0);
  assert.deepEqual(errors,[]);
  await context.close();
  }

  console.log('PASS actual Express/SQLite/Chromium integration: HMAC, admin key creation, caps/period/expiry, cookie/logout, role isolation, real usage graph, XSS-safe model, CSRF/origin denial, key secrecy, mobile, zero JS errors');
} finally {
  await browser?.close();if(server.listening)await close(server);store.close();await rm(dir,{recursive:true,force:true});
}
