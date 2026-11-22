// Consume private Docker/Compose snapshots in memory. Never return values or hashes.
// Explicit Compose settings and all other detectable application overrides must
// remain exact. Only inherited image defaults may follow the reviewed pinned image.
export function checkDeploymentEnvironment({baseline,baselineImage,pinnedImage,compose,runtime}){
 function env(list){
  const map=new Map();
  for(const entry of list){
   if(typeof entry!=='string'||entry.indexOf('=')<1)throw Error('Invalid environment entry');
   const i=entry.indexOf('='),name=entry.slice(0,i);
   if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))throw Error('Invalid environment name');
   if(map.has(name))throw Error('Duplicate environment key '+name);
   map.set(name,entry.slice(i+1));
  }
  return map;
 }
 const old=env(baseline),oldDefaults=env(baselineImage),defaults=env(pinnedImage),explicit=env(compose),actual=env(runtime);
 const overrides=new Map(explicit);
 for(const [name,value]of explicit)if(!old.has(name)||old.get(name)!==value)throw Error('Application override drift '+name);
 for(const [name,value]of old)if(!oldDefaults.has(name)||oldDefaults.get(name)!==value)overrides.set(name,value);
 const expected=new Map([...defaults,...overrides]);
 // PATH affects executable selection and must never silently follow base changes.
 if(old.has('PATH')&&expected.get('PATH')!==old.get('PATH'))throw Error('PATH drift');
 const differences=[];
 for(const name of new Set([...expected.keys(),...actual.keys()])){
  if(!expected.has(name)||!actual.has(name)||expected.get(name)!==actual.get(name))throw Error('Runtime environment mismatch '+name);
  if(old.get(name)!==actual.get(name)||!old.has(name))differences.push(name);
 }
 for(const name of old.keys())if(!actual.has(name))throw Error('Removed baseline environment key '+name);
 return {duplicateChecksPassed:true,explicitApplicationNames:[...explicit.keys()].sort(),otherApplicationOverrideNames:[...overrides.keys()].filter(k=>!explicit.has(k)).sort(),inheritedDefaultNames:[...defaults.keys()].filter(k=>!overrides.has(k)).sort(),changedInheritedNames:differences.sort(),strictApplicationOverridesMatch:true,strictPinnedDefaultsMatch:true,pathPreserved:true};
}
