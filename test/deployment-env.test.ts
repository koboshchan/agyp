import{test}from'node:test';import assert from'node:assert/strict';
import{checkDeploymentEnvironment as check}from'../scripts/check-deployment-env.mjs';
const fixture=()=>({baseline:['PATH=/bin','NODE_VERSION=old','PORT=1','SECRET=private=a','EXTRA=custom'],baselineImage:['PATH=/bin','NODE_VERSION=old','PORT=0'],pinnedImage:['PATH=/bin','NODE_VERSION=new','PORT=0'],compose:['PORT=1','SECRET=private=a'],runtime:['EXTRA=custom','SECRET=private=a','PORT=1','NODE_VERSION=new','PATH=/bin']});
test('deployment environment follows exact pinned defaults, preserving explicit and additional application overrides',()=>{
 const r=check(fixture());assert.deepEqual(r.changedInheritedNames,['NODE_VERSION']);assert.deepEqual(r.otherApplicationOverrideNames,['EXTRA']);assert(r.pathPreserved);assert(!JSON.stringify(r).includes('private=a'));
 const f=fixture();f.runtime.reverse();assert.deepEqual(check(f),r);
});
test('deployment environment rejects duplicate keys in every input without emitting values',()=>{
 for(const name of ['baseline','baselineImage','pinnedImage','compose','runtime']as const){const f=fixture();f[name].push(f[name][0]);assert.throws(()=>check(f),/Duplicate environment key/);}
});
test('deployment environment rejects secret, extra override, pinned default, added, removed and PATH drift',()=>{
 for(const [name,value]of [['SECRET','leaked'],['EXTRA','changed'],['NODE_VERSION','wrong'],['PATH','/other']]){
  const f=fixture();f.runtime=f.runtime.map(x=>x.startsWith(name+'=')?name+'='+value:x);assert.throws(()=>check(f),e=>e instanceof Error&&!e.message.includes('leaked'));
 }
 const added=fixture();added.runtime.push('NEW_APP=unexpected');assert.throws(()=>check(added),/Runtime environment mismatch NEW_APP/);
 const removed=fixture();removed.runtime=removed.runtime.filter(x=>!x.startsWith('EXTRA='));assert.throws(()=>check(removed),/Runtime environment mismatch EXTRA/);
 const compose=fixture();compose.compose[1]='SECRET=changed';assert.throws(()=>check(compose),/Application override drift SECRET/);
 const path=fixture();path.pinnedImage[0]='PATH=/changed';path.runtime[path.runtime.length-1]='PATH=/changed';assert.throws(()=>check(path),/PATH drift/);
});
test('deployment checker rejects invalid names and missing inherited baseline keys without blanket exemptions',()=>{
 const invalid=fixture();invalid.runtime.push('bad name=private');assert.throws(()=>check(invalid),/Invalid environment name/);
 const removed=fixture();removed.pinnedImage=removed.pinnedImage.filter(x=>!x.startsWith('NODE_VERSION='));removed.runtime=removed.runtime.filter(x=>!x.startsWith('NODE_VERSION='));assert.throws(()=>check(removed),/Removed baseline environment key NODE_VERSION/);
 const malformed=fixture();malformed.runtime.push('bad');assert.throws(()=>check(malformed),/Invalid environment entry/);
});
