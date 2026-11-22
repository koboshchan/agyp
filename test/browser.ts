// Standalone mocked UI contract test. Run npm run test:browser.
// Optional CHROME_BIN points to an installed Chromium executable.
import { chromium } from '@playwright/test';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createHmac } from 'node:crypto';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';

const server = createServer(async (req, res) => {
  const paths: Record<string,string> = { '/':'index.html', '/app.js':'app.js', '/style.css':'style.css' };
  const file = paths[req.url || ''];
  if (!file) { res.writeHead(404).end(); return; }
  res.setHeader('Content-Type', file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html');
  res.end(await readFile(resolve('web', file)));
});
await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || undefined, args:['--no-sandbox'] });
try {
  const page = await browser.newPage();
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  let auth = false, admin = true, manualDone = false, expiry = 900000;
  const token = 'agyp_0123456789abcdef.test-secret';
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
    if (req.method() !== 'GET') assert.equal(req.headers()['x-csrf-token'],'csrf-test');
    let body: object={};
    if (path==='/api/me') body={key:{...key,admin},csrf:'csrf-test',sessionExpires:Date.now()+expiry};
    else if(path==='/api/stats') body={models:[{key_id:key.id,model:'<img src=x onerror=alert(1)>',input:20000,output:5000,cached:10000,noncached:10000,total:25000,requests:4}],graph:[{day:'2026-11-21',input:20000,output:5000,cached:10000}]};
    else if(path==='/api/keys') body=req.method()==='POST'?{key,token:'agyp_1123456789abcdef.new-secret'}:{keys:[key]};
    else if(path==='/api/accounts') body={accounts:[{id:'acct',email:'hello@example.com',shared:true,status:'ready',buckets:[]}],active:{}};
    else if(path==='/api/oauth/start') body={url:'https://accounts.google.com/o/oauth2/auth?test=1',manual:true};
    else if(path==='/api/oauth/complete') { assert.equal(req.postDataJSON().callbackUrl,'http://localhost:54321/?code=abc&state=xyz');manualDone=true; }
    await route.fulfill({json:body});
  });
  const address=server.address(); assert.ok(address && typeof address==='object');
  await page.goto('http://127.0.0.1:'+address.port);
  async function login() {
    await page.locator('#login').waitFor({state:'visible'});
    await page.fill('#token',token); await page.click('#login-form button');
    await page.locator('#dashboard').waitFor({state:'visible'});
  }
  await login();
  assert.equal(await page.inputValue('#token'),'');
  assert.equal(await page.locator('#models img').count(),0);
  assert.equal(await page.locator('#chart svg').count(),1);
  await page.click('[data-view=keys]');await page.click('#add-key');await page.fill('#key-name','New key');
  await page.click('#key-form button[type=submit]');await page.locator('#secret-dialog').waitFor({state:'visible'});
  assert.match(await page.inputValue('#new-secret'),/new-secret/);
  await page.locator('#secret-dialog .close-dialog').click();assert.equal(await page.inputValue('#new-secret'),'');
  await page.click('[data-view=accounts]');await page.click('#add-account');
  await page.locator('#oauth-dialog').waitFor({state:'visible'});
  await page.fill('#oauth-callback','http://localhost:54321/?code=abc&state=xyz');
  await page.click('#oauth-form button[type=submit]');await page.locator('#oauth-dialog').waitFor({state:'hidden'});
  assert.ok(manualDone);assert.equal(await page.inputValue('#oauth-callback'),'');
  await page.setViewportSize({width:390,height:844});
  assert.ok(await page.locator('#mobile-logout').isVisible());
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false);
  await page.click('#mobile-logout');admin=false;await login();
  assert.equal(await page.locator('.admin-only:visible').count(),0);
  assert.equal(await page.locator('#models th').first().textContent(),'Model');
  assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
  expiry=250;await page.click('#refresh');await page.locator('#login').waitFor({state:'visible'});
  assert.equal(await page.locator('#chart svg').count(),0);
  assert.deepEqual(errors,[]);
  console.log('PASS browser UI contract: HMAC, key secrecy, CSRF, roles, safe rendering, charts, one-time secret, manual OAuth, mobile, logout, expiry');
} finally {
  await browser.close();
  await new Promise<void>(r=>server.close(()=>r()));
}
