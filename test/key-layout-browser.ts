// Local fixture-only regression. Never connects to the live service.
import {chromium,expect} from '@playwright/test';
import express from 'express';
import {createServer} from 'node:http';
import {resolve} from 'node:path';
import {mkdirSync,writeFileSync} from 'node:fs';
import assert from 'node:assert/strict';

const dir=process.env.LAYOUT_PROOF_DIR||'/tmp/agyp-key-layout';
mkdirSync(dir,{recursive:true});
const app=express();
app.get('/',(_req,res)=>res.sendFile(resolve('web/index.html')));
app.use('/assets',express.static(resolve('web'),{index:false,dotfiles:'deny',redirect:false}));
app.use((_req,res)=>res.sendStatus(404));
const server=createServer(app);
await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
const browser=await chromium.launch({executablePath:process.env.CHROME_BIN||undefined,args:['--no-sandbox']});
const metrics:unknown[]=[];
try{
 for(const width of [1440,1024,390])for(const theme of ['light','dark']as const){
  const context=await browser.newContext({viewport:{width,height:960},colorScheme:theme});
  const page=await context.newPage();
  const keys=Array.from({length:6},(_,i)=>({id:i.toString(16).padStart(16,'0'),name:i===0?'Desktop':i===1?'Long-project-name-'.repeat(7):'Fixture '+i,admin:false,allowance:2000000,inputCap:1000000,outputCap:500000,period:'5h',expires:Date.now()+86400000,used:{input:42000,output:8000,total:50000},revoked:i===5?1:0}));
  const model=(id:string)=>({key_id:id,model:'fixture-model-'+id,input:42000,output:8000,cached:10000,noncached:32000,total:50000,requests:5});
  let writes=0;
  await page.route('**/*',async route=>{
   const url=new URL(route.request().url());
   assert.equal(url.hostname,'127.0.0.1','no external network');
   if(!url.pathname.startsWith('/api/'))return route.continue();
   assert.equal(route.request().method(),'GET','layout actions must never write');
   if(route.request().method()!=='GET')writes++;
   const body=url.pathname==='/api/me'?{key:{...keys[0],admin:true},csrf:'fixture-csrf',sessionExpires:Date.now()+900000}:url.pathname==='/api/stats'?{overview:keys.map(k=>model(k.id)),models:keys.map(k=>model(k.id)),control:{requests:9,total:0},graph:[]}:url.pathname==='/api/keys'?{keys}:{accounts:[],active:{}};
   await route.fulfill({json:body});
  });
  const address=server.address();assert.ok(address&&typeof address==='object');
  await page.goto('http://127.0.0.1:'+address.port);
  await page.locator('#dashboard').waitFor();
  await page.locator('[data-view=keys]:visible').first().click();
  await page.evaluate(async()=>{await Promise.all(document.getAnimations().filter(a=>a.effect?.getComputedTiming().iterations!==Infinity).map(a=>a.finished.catch(()=>{})));});
  const grid=page.locator('#keys');
  const deleteButton=grid.getByRole('button',{name:'Delete Desktop',exact:true});
  await deleteButton.scrollIntoViewIfNeeded();
  const measure=()=>deleteButton.evaluate(el=>{
   const b=el.getBoundingClientRect(),cell=el.closest('td')!.getBoundingClientRect(),card=el.closest('[data-slot=card]')!.getBoundingClientRect();
   let clipped=b.left<cell.left-1||b.right>cell.right+1;
   for(let a=el.parentElement;a;a=a.parentElement){const s=getComputedStyle(a),r=a.getBoundingClientRect();if(/hidden|auto|scroll|clip/.test(s.overflowX)&&(b.left<r.left-1||b.right>r.right+1))clipped=true;}
   return {button:{left:b.left,right:b.right,width:b.width,height:b.height},cell:{left:cell.left,right:cell.right},card:{left:card.left,right:card.right},clipped,pageOverflow:document.documentElement.scrollWidth>innerWidth};
  });
  await grid.getByRole('region').evaluate(el=>{el.scrollLeft=el.scrollWidth;}).catch(()=>{});
  const measurement=await measure();metrics.push({width,theme,...measurement});
  await page.screenshot({path:dir+'/keys-'+width+'-'+theme+'.png',fullPage:true});
  if(!process.env.LAYOUT_BASELINE){
   assert.equal(measurement.clipped,false,'Delete must fit cell and scroll viewport');
   assert.ok(measurement.button.left>=measurement.card.left&&measurement.button.right<=measurement.card.right,'Delete inside card');
   await expect(grid.getByRole('region')).toHaveAccessibleName(/Access keys, scroll horizontally/);
   await grid.getByRole('region').focus();await expect(grid.getByRole('region')).toBeFocused();
   assert.equal(measurement.pageOverflow,false,'no page horizontal overflow');
   for(const key of keys.slice(0,5)){
    const usage=grid.getByRole('button',{name:'Usage for '+key.name,exact:true});
    await usage.scrollIntoViewIfNeeded();await expect(usage).toHaveAccessibleName('Usage for '+key.name);
    await usage.focus();await page.keyboard.press('Enter');
    const dialog=page.getByRole('dialog');
    await expect(dialog).toContainText('fixture-model-'+key.id);
    for(const other of keys.filter(k=>k.id!==key.id))await expect(dialog).not.toContainText('fixture-model-'+other.id);
    await page.keyboard.press('Escape');await expect(dialog).toBeHidden();
    const del=grid.getByRole('button',{name:'Delete '+key.name,exact:true});
    await del.scrollIntoViewIfNeeded();await del.click();
    const confirm=page.getByRole('alertdialog');
    await expect(confirm).toContainText(key.name);
    await confirm.getByRole('button',{name:'Cancel',exact:true}).click();await expect(confirm).toBeHidden();
    const box=await del.boundingBox();assert.ok(box&&box.width>=44&&(width>=768||box.height>=44));
   }
   await page.locator('#deleted-keys summary').click();
   const archived=page.locator('#deleted-keys').getByRole('button',{name:'Delete '+keys[5].name,exact:true});
   await archived.scrollIntoViewIfNeeded();await archived.click();
   await page.getByRole('alertdialog').getByRole('button',{name:'Cancel',exact:true}).click();
   assert.equal(writes,0);
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  }
  await context.close();
 }
 writeFileSync(dir+'/metrics.json',JSON.stringify(metrics,null,2));
 console.log(JSON.stringify({pass:!process.env.LAYOUT_BASELINE,metrics}));
}finally{await browser.close();await new Promise<void>(r=>server.close(()=>r()));}
