// Standalone mocked UI contract test. Run npm run test:browser.
// Optional CHROME_BIN points to an installed Chromium executable.
import { chromium, expect } from '@playwright/test';
import { createServer } from 'node:http';
import express from 'express';
import { createHmac } from 'node:crypto';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';

// Serve only the public build tree. Express handles bundled assets/MIME, rejects
// dotfiles and prevents traversal outside this root. Never serve the repo root.
const app = express();
app.get('/', (_req,res) => res.sendFile(resolve('web/index.html')));
// Vite base is /assets/ while its output directory is web. Match production's
// mount exactly so hashed imports resolve without exposing source or secrets.
app.use('/assets', express.static(resolve('web'), { index: false, dotfiles: 'deny', redirect: false }));
app.use((_req,res) => { res.sendStatus(404); });
const server = createServer(app);
await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || undefined, args:['--no-sandbox'] });
try {
  for (const device of ['desktop', 'mobile'] as const) for (const theme of ['light', 'dark'] as const) {
  const context = await browser.newContext({ viewport: device === 'desktop' ? {width:1440,height:1000} : {width:390,height:844}, colorScheme:theme });
  const page = await context.newPage();
  const suffix = `${device}-${theme}`;
  const screenshot = async (view:string) => {
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false, `${view} must not overflow on ${suffix}`);
    await page.mouse.move(0,0);
    // Check accessible names on the actual visible interactive surface, including
    // icon-only controls. Apple touch targets use the 44 CSS pixel minimum.
    for (const control of await page.locator('button:visible').all()) {
      await expect(control).toHaveAccessibleName(/.+/);
      if (device === 'mobile') {
        const box=await control.boundingBox();
        assert.ok(box && box.height>=44 && box.width>=44, `touch target too small on ${view}: ${await control.getAttribute('aria-label') || await control.innerText()}`);
      }
    }
    // Screenshots only use the fixture responses below, never the live service.
    await page.screenshot({path:`/tmp/agyp-redesign-${view}-${suffix}.png`,fullPage:true});
  };

  const errors: string[] = [];
  page.on('console',m=>{if(m.type()==='error'&&!/^Failed to load resource: the server responded with a status of (401|403) \(/.test(m.text()))errors.push(m.text());});
  await page.addInitScript(()=>{document.addEventListener('securitypolicyviolation',e=>{console.error('CSP violation '+e.violatedDirective+' '+e.blockedURI);});});
  page.on('pageerror', e => errors.push(e.message));
  let auth = false, admin = true, manualDone = false, expiry = 900000;
  const token = 'agyp_0123456789abcdef.test-secret';
  let revoked = false, deleted = false, removed = false, toggled = false, refreshed = false;
  let accountStatus='ready';
  let pendingPath='', releasePending:(()=>void)|undefined, pendingSeen:(()=>void)|undefined;
  let completedPending:(()=>void)|undefined;
  const pendingDone=()=>new Promise<void>(r=>completedPending=r);
  const key = { id:'0123456789abcdef', name:'Workstation', admin:true, allowance:1000000, inputCap:null, outputCap:500000, period:'daily', expires:null, used:{input:20000,output:5000,total:25000}, resets:Date.now()+86400000 };
  await page.route('**/auth/**', async route => {
    const path = new URL(route.request().url()).pathname;
    const body = route.request().postDataJSON();
    assert.ok(!JSON.stringify(body).includes(token), 'raw key must not leave the browser');
    let result: object = {};
    if (path === '/auth/challenge') { assert.equal(body.keyId,key.id); result={nonce:'test-nonce',expires:Date.now()+60000}; }
    else if (path === '/auth/verify') {
      assert.equal(body.proof,createHmac('sha256',token).update('test-nonce').digest('hex'));
      assert.equal(body.client,'web'); auth=true; result={csrf:'csrf-test',expires:Date.now()+900000};
    } else auth=false;
    await route.fulfill({json:result});
  });
  await page.route('**/api/**', async route => {
    const req=route.request(), path=new URL(req.url()).pathname;
    if (!auth) { await route.fulfill({status:401,json:{error:'Unauthenticated'}}); return; }
    if (path===pendingPath) { pendingSeen?.(); await new Promise<void>(r=>releasePending=r); pendingPath=''; }
    if (req.method() !== 'GET') assert.equal(req.headers()['x-csrf-token'],'csrf-test');
    let body: object={};
    if (path==='/api/me') body={key:{...key,admin},csrf:'csrf-test',sessionExpires:Date.now()+expiry};
    else if(path==='/api/stats') body={models:[{key_id:key.id,model:'<img src=x onerror=alert(1)>',input:20000,output:5000,cached:10000,noncached:10000,total:25000,requests:4}],graph:[{day:'2026-11-21',input:20000,output:5000,cached:10000}]};
    else if(path==='/api/keys') body=req.method()==='POST'?{key,token:'agyp_1123456789abcdef.new-secret'}:{keys:[key]};
    else if(path==='/api/keys/'+key.id+'/revoke') { revoked=true; }
    else if(path==='/api/keys/'+key.id && req.method()==='DELETE') { deleted=true; }
    else if(path==='/api/accounts/acct/toggle') { toggled=true; accountStatus=accountStatus==='ready'?'disabled':'ready'; }
    else if(path==='/api/accounts/acct/refresh') { refreshed=true; }
    else if(path==='/api/accounts/acct' && req.method()==='DELETE') { removed=true; }
    else if(path==='/api/accounts') body={accounts:[{id:'acct',email:'hello@example.com',shared:true,status:accountStatus,buckets:[]}],active:{}};
    else if(path==='/api/oauth/start') body={url:'https://accounts.google.com/o/oauth2/auth?test=1',manual:true};
    else if(path==='/api/oauth/complete') { assert.equal(req.postDataJSON().callbackUrl,'http://localhost:54321/?code=abc&state=xyz');manualDone=true; }
    await route.fulfill({json:body});
    if(releasePending && path!==pendingPath) { completedPending?.();completedPending=undefined; }
  });
  const address=server.address(); assert.ok(address && typeof address==='object');
  await page.goto('http://127.0.0.1:'+address.port);
  async function login() {
    await page.locator('#login').waitFor({state:'visible'});
    await page.fill('#token',token); await page.click('#login-form button');
    await page.locator('#dashboard').waitFor({state:'visible'});
  }
  await expect(page.locator('#token')).toHaveAccessibleName(/.+/);
  await page.locator('#token').focus();
  await expect(page.locator('#token')).toBeFocused();
  await screenshot('login');
  await login();
  assert.equal(await page.inputValue('#token'),'');
  assert.equal(await page.locator('#models img').count(),0);
  assert.ok(await page.locator('#chart svg').count()>=1);
  await screenshot('admin-overview');
  await page.locator('[data-view=keys]:visible').first().click();await screenshot('admin-keys');await page.click('#add-key');await page.fill('#key-name','New key');
  await page.click('#key-form button[type=submit]');await page.locator('#secret-dialog').waitFor({state:'visible'});
  assert.match(await page.inputValue('#new-secret'),/new-secret/);
  await page.locator('#secret-dialog').getByRole('button',{name:'Close',exact:true}).click();assert.equal(await page.inputValue('#new-secret'),'');
  await page.locator('[data-view=accounts]:visible').first().click();await screenshot('admin-accounts');await page.click('#add-account');
  await page.locator('#oauth-dialog').waitFor({state:'visible'});
  await page.fill('#oauth-callback','http://localhost:54321/?code=abc&state=xyz');
  await page.click('#oauth-form button[type=submit]');await page.locator('#oauth-dialog').waitFor({state:'hidden'});
  assert.ok(manualDone);assert.equal(await page.inputValue('#oauth-callback'),'');
  // Test confirmation cancellation as well as acceptance, whether implemented
  // with a browser confirm or an accessible React dialog.
  async function confirmAction(button:ReturnType<typeof page.getByRole>, accept:boolean) {
    let native = false;
    const handler = async (dialog:import('@playwright/test').Dialog) => { native=true; assert.match(dialog.message(), /remove|revoke|delete/i); await (accept ? dialog.accept() : dialog.dismiss()); };
    page.once('dialog', handler);
    await button.click();
    if (!native) {
      const dialog=page.getByRole('alertdialog').or(page.getByRole('dialog')).filter({visible:true});
      await expect(dialog).toBeVisible();
      await dialog.getByRole('button',{name:accept?/^(revoke|delete|remove|confirm)( key| account)?$/i:/cancel/i}).click();
    }
    page.off('dialog',handler);
  }
  await page.getByRole('button',{name:'Refresh quotas',exact:true}).click();
  await expect.poll(()=>refreshed).toBe(true);
  await page.getByRole('button',{name:/Pause sharing|Enable sharing/}).click();
  await expect.poll(()=>toggled).toBe(true);
  await expect(page.getByRole('button',{name:'Enable sharing',exact:true})).toBeVisible();
  const remove=page.getByRole('button',{name:'Remove',exact:true});
  await confirmAction(remove,false);assert.equal(removed,false);
  await confirmAction(remove,true);await expect.poll(()=>removed).toBe(true);
  await page.locator('[data-view=keys]:visible').first().click();
  const revoke=page.getByRole('button',{name:/^Revoke Workstation$/}).first();
  await confirmAction(revoke,false);assert.equal(revoked,false);
  await confirmAction(revoke,true);await expect.poll(()=>revoked).toBe(true);
  const del=page.getByRole('button',{name:/^Delete Workstation$/}).first();
  await confirmAction(del,false);assert.equal(deleted,false);
  await confirmAction(del,true);await expect.poll(()=>deleted).toBe(true);
  await page.setViewportSize({width:390,height:844});
  assert.ok(await page.locator('#mobile-logout').isVisible());
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false);
  await page.click('#mobile-logout');admin=false;await login();
  assert.equal(await page.locator('.admin-only:visible').count(),0);
  await expect(page.locator('#models th').first()).toContainText('Model');
  await page.setViewportSize(device==='desktop'?{width:1440,height:1000}:{width:390,height:844});
  await screenshot('user');
  await expect(page.locator('#accounts-view')).toBeHidden();await expect(page.locator('#keys-view')).toBeHidden();
  assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
  await page.emulateMedia({reducedMotion:'reduce',contrast:'more'});
  await page.locator('#refresh').click();
  await expect(page.locator('#loading')).toBeHidden();
  const moving=await page.evaluate(()=>document.getAnimations().filter(a=>{
    const effect=a.effect;const timing=effect?.getComputedTiming();
    return a.playState==='running' && Number(timing?.duration)>200;
  }).length);
  assert.equal(moving,0,'reduced motion must not leave long-running animations');
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  // A response admitted while authenticated must never repopulate the UI after
  // the local session deadline, even if the server replies with a stale success.
  for(const path of ['/api/me','/api/stats']) {
    expiry=1200;await page.click('#refresh');await expect(page.locator('#loading')).toBeHidden();
    pendingPath=path;
    const seen=new Promise<void>(r=>pendingSeen=r);
    const done=pendingDone();
    await page.click('#refresh');await seen;
    await expect(page.locator('#login')).toBeVisible();
    releasePending?.();await done;
    await expect(page.locator('#loading')).toBeHidden();
    await expect(page.locator('#dashboard')).toBeHidden();
    assert.equal(await page.locator('#chart svg').count(),0);
    assert.equal(await page.inputValue('#token'),'');
    expiry=900000;await login();
  }
  expiry=250;await page.click('#refresh');await page.locator('#login').waitFor({state:'visible'});
  assert.equal(await page.locator('#chart svg').count(),0);
  // A late key-creation response must not reopen the one-time secret after lock.
  admin=true;expiry=900000;await login();
  await page.locator('[data-view=keys]:visible').first().click();
  expiry=2500;await page.click('#refresh');await expect(page.locator('#loading')).toBeHidden();
  await page.click('#add-key');await page.fill('#key-name','Late fixture');
  pendingPath='/api/keys';const seenPost=new Promise<void>(r=>pendingSeen=r);const postDone=pendingDone();
  await page.click('#key-form button[type=submit]');await seenPost;
  await expect(page.locator('#login')).toBeVisible();releasePending?.();await postDone;
  await expect(page.locator('#secret-dialog')).toBeHidden();
  assert.equal(await page.inputValue('#new-secret'),'');
  await expect(page.locator('#dashboard')).toBeHidden();
  assert.deepEqual(errors,[]);
  await context.close();
  }
  console.log('PASS browser UI contract: HMAC, key secrecy, CSRF, roles, safe rendering, charts, one-time secret, manual OAuth, mobile, logout, expiry');
} finally {
  await browser.close();
  await new Promise<void>(r=>server.close(()=>r()));
}
