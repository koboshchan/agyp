'use strict';
const $ = (id) => document.getElementById(id);
const state = { me: null, stats: {}, keys: [], accounts: [], active: {}, view: 'overview', timer: null };
const fmt = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 });
const number = (n) => fmt.format(Number(n) || 0);
const full = (n) => new Intl.NumberFormat('en').format(Number(n) || 0);
const date = (n) => n ? new Date(n).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : 'Never';
function el(tag, text, cls) { const node = document.createElement(tag); if (text != null) node.textContent = String(text); if (cls) node.className = cls; return node; }
function clear(node) { node.replaceChildren(); return node; }
function notice(text, error = false) { $('notice').textContent = text; $('notice').className = 'notice' + (error ? ' error' : ''); $('notice').hidden = false; clearTimeout(notice.timer); notice.timer = setTimeout(() => { $('notice').hidden = true; }, error ? 9000 : 5000); }
function lock(message) {
  clearTimeout(state.timer); state.me = null; state.stats = {}; state.keys = []; state.accounts = []; state.active = {};
  $('dashboard').hidden = true; $('login').hidden = false; $('token').value = ''; $('new-secret').value = '';
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  for (const id of ['metrics','models','accounts','keys','chart','allowance']) clear($(id));
  if (message) notice(message, true);
}
async function api(path, options = {}) {
  const headers = { ...options.headers };
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (options.method && options.method !== 'GET' && state.me?.csrf) headers['X-CSRF-Token'] = state.me.csrf;
  const response = await fetch(path, { ...options, headers, credentials: 'same-origin', cache: 'no-store', body: options.body === undefined ? undefined : JSON.stringify(options.body) });
  let data = {}; try { data = await response.json(); } catch { /* Empty response is valid for deletion. */ }
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith('/auth/')) lock('Your session ended. Enter your key to unlock again.');
    const error = new Error(typeof data.error === 'string' ? data.error : (data.error?.message || data.message || 'Request failed (' + response.status + ').')); error.status = response.status; throw error;
  }
  return data;
}
async function action(button, fn) {
  if (button.disabled) return; button.disabled = true;
  try { await fn(); } catch (error) { notice(error.message || 'Something went wrong. Please try again.', true); }
  finally { button.disabled = false; }
}
$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.submitter;
  await action(button, async () => {
    let token = $('token').value.trim(); $('token').value = '';
    const match = /^agyp_([a-f0-9]{16})\.(.+)$/i.exec(token);
    if (!match) { token = ''; throw new Error('Enter a complete access key, including its agyp_ prefix.'); }
    const keyId = match[1];
    let signingKey;
    try {
      if (!globalThis.crypto?.subtle) throw new Error('A secure HTTPS connection is required to unlock.');
      signingKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(token), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    } finally { token = ''; match[0] = ''; match[2] = ''; match.input = ''; }
    const challenge = await api('/auth/challenge', { method: 'POST', body: { keyId } });
    const signed = await crypto.subtle.sign('HMAC', signingKey, new TextEncoder().encode(challenge.nonce));
    signingKey = null;
    const proof = Array.from(new Uint8Array(signed), (b) => b.toString(16).padStart(2, '0')).join('');
    await api('/auth/verify', { method: 'POST', body: { keyId, nonce: challenge.nonce, proof, client: 'web' } });
    await load();
  });
});
async function load() {
  $('loading').hidden = false;
  try {
    const me = await api('/api/me');
    state.me = me;
    clearTimeout(state.timer);
    const expires = Number(me.sessionExpires);
    if (Number.isFinite(expires) && expires > 0) {
      if (expires <= Date.now()) { lock('Your session ended. Enter your key again.'); return; }
      state.timer = setTimeout(() => lock('Your session ended. Enter your key again.'), Math.min(expires - Date.now(), 2147483647));
    }
    $('login').hidden = true; $('dashboard').hidden = false;
    document.querySelectorAll('.admin-only').forEach((n) => { n.hidden = !me.key.admin; });
    if (!me.key.admin) state.view = 'overview';
    $('welcome').textContent = (me.key.name || 'Your workspace') + (me.key.admin ? ' · Administrator workspace' : ' · Your personal usage');
    $('session-label').textContent = expires ? 'Session ends ' + new Date(expires).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Private browser session';
    const requests = [api('/api/stats')];
    if (me.key.admin) requests.push(api('/api/keys'), api('/api/accounts'));
    const results = await Promise.allSettled(requests);
    if (!state.me) return;
    if (results[0].status === 'fulfilled') state.stats = results[0].value; else state.stats = {};
    if (me.key.admin) {
      state.keys = results[1].status === 'fulfilled' ? (results[1].value.keys || []) : [];
      state.accounts = results[2].status === 'fulfilled' ? (results[2].value.accounts || []) : [];
      state.active = results[2].status === 'fulfilled' ? (results[2].value.active || {}) : {};
    }
    render(); switchView(state.view);
    const failures = results.filter((r) => r.status === 'rejected');
    if (failures.length) notice('Some data could not be loaded. ' + failures[0].reason.message, true);
  } finally { $('loading').hidden = true; }
}
function switchView(view) {
  if (view !== 'overview' && !state.me?.key.admin) return;
  state.view = view;
  for (const name of ['overview','accounts','keys']) $(name + '-view').hidden = name !== view;
  document.querySelectorAll('[data-view]').forEach((n) => n.classList.toggle('active', n.dataset.view === view));
  $('breadcrumb').textContent = view.toUpperCase();
  $('page-title').textContent = { overview: 'Good to be in control.', accounts: 'One place. Every account.', keys: 'Access, on your terms.' }[view];
}
document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => switchView(button.dataset.view)));
$('refresh').addEventListener('click', (event) => action(event.currentTarget, load));
for (const id of ['logout','mobile-logout']) $(id).addEventListener('click', (event) => action(event.currentTarget, async () => { await api('/auth/logout', { method: 'POST', body: {} }); lock(); }));
function table(headers, rows, empty) {
  if (!rows.length) return el('div', empty, 'empty');
  const t = el('table'), head = el('thead'), hr = el('tr'), body = el('tbody');
  headers.forEach((h) => hr.append(el('th', h))); head.append(hr); t.append(head);
  rows.forEach((row) => { const tr = el('tr'); row.forEach((v) => { const td = el('td'); td.append(v instanceof Node ? v : document.createTextNode(String(v))); tr.append(td); }); body.append(tr); });
  t.append(body); return t;
}
function detail(root, label, value) { const line = el('div', null, 'detail-line'); line.append(el('span', label), el('strong', value)); root.append(line); }
function progress(root, used, cap) {
  const bar = el('div', null, 'progress'), fill = el('div', null, 'progress-fill');
  fill.style.width = cap == null ? '0%' : Math.max(0, Math.min(100, cap > 0 ? used / cap * 100 : 100)) + '%';
  bar.setAttribute('role', 'meter'); bar.setAttribute('aria-label', 'Allowance used');
  bar.setAttribute('aria-valuemin', '0'); bar.setAttribute('aria-valuemax', String(cap ?? Math.max(used, 1))); bar.setAttribute('aria-valuenow', String(Math.min(used, cap ?? used)));
  bar.append(fill); root.append(bar);
}
function render() {
  const key = state.me.key, rows = state.stats.models || [];
  const sum = (name) => rows.reduce((a, b) => a + (Number(b[name]) || 0), 0);
  const metrics = clear($('metrics'));
  const total = sum('total') || sum('input') + sum('output');
  [['Total tokens',total,'Across the selected workspace'],['Input tokens',sum('input'),'Prompts & context'],['Output tokens',sum('output'),'Generated responses'],['Cached tokens',sum('cached'),'Included in input tokens']].forEach(([label, value, foot]) => {
    const card = el('article', null, 'metric'); card.append(el('div',label,'metric-label'),el('div',number(value),'metric-value'),el('div',foot,'metric-foot')); card.title = full(value); metrics.append(card);
  });
  const allowance = clear($('allowance'));
  const used = Number(key.used?.total) || 0;
  allowance.append(el('div',key.allowance == null ? 'Unlimited' : number(Math.max(0,key.allowance-used)),'allowance-value'),el('p',key.allowance == null ? 'No total token ceiling.' : 'tokens remaining','muted'));
  progress(allowance, used, key.allowance);
  detail(allowance,'Used', full(used) + (key.allowance == null ? '' : ' / ' + full(key.allowance)));
  detail(allowance,'Input cap',key.inputCap == null ? 'Unlimited' : full(key.used?.input) + ' / ' + full(key.inputCap));
  detail(allowance,'Output cap',key.outputCap == null ? 'Unlimited' : full(key.used?.output) + ' / ' + full(key.outputCap));
  detail(allowance,'Period',key.period || 'never'); detail(allowance,'Next reset',date(key.resets)); detail(allowance,'Key expires',date(key.expires));
  clear($('models')).append(table([...(key.admin ? ['Key'] : []),'Model','Input','Output','Cached','Non-cached','Total','Requests'], rows.map((r) => [...(key.admin ? [r.key_id] : []),r.model,full(r.input),full(r.output),full(r.cached),full(r.noncached),full(r.total),full(r.requests)]), 'No requests yet. Your first request will appear here.'));
  drawChart(state.stats.graph || []);
  if (key.admin) { renderKeys(); renderAccounts(); }
}
function drawChart(data) {
  const root = clear($('chart'));
  if (!data.length) { root.append(el('div','A little quiet here. Activity appears after your first request.','empty')); return; }
  const svgNS = 'http://www.w3.org/2000/svg';
  function svg(tag, attrs) { const n = document.createElementNS(svgNS, tag); Object.entries(attrs).forEach(([k,v]) => n.setAttribute(k,String(v))); return n; }
  const chart = svg('svg',{viewBox:'0 0 650 215',role:'img','aria-label':'Daily input, output, and cached token usage'});
  const title = svg('title',{}); title.textContent = 'Daily token usage. ' + data.map((d) => d.day + ': ' + full(d.input) + ' input, ' + full(d.output) + ' output, ' + full(d.cached) + ' cached.').join(' '); chart.append(title);
  const max = Math.max(1, ...data.map((d) => (Number(d.input)||0)+(Number(d.output)||0)));
  for(let i=0;i<4;i++) { const y=15+i*53; chart.append(svg('line',{x1:46,y1:y,x2:646,y2:y,stroke:'#edf0e5','stroke-dasharray':'3 5'})); const label=svg('text',{x:0,y:y+4,fill:'#6e7b62','font-size':9}); label.textContent=number(max*(1-i/3)); chart.append(label); }
  const step=590/data.length, width=Math.min(24,step*.58);
  data.forEach((d,i) => {
    const x=49+i*step+(step-width)/2, input=Math.max(0,Number(d.input)||0), output=Math.max(0,Number(d.output)||0), cached=Math.min(input,Math.max(0,Number(d.cached)||0));
    let y=174;
    for (const [value,color] of [[input-cached,'#496c4a'],[cached,'#dce7c9'],[output,'#b2c579']]) {
      const height=value/max*159; y-=height;
      const rect=svg('rect',{x,y,width,height,rx:2,fill:color}); const tip=svg('title',{}); tip.textContent=d.day+' · '+full(value)+' tokens'; rect.append(tip); chart.append(rect);
    }
    if (i % Math.max(1,Math.ceil(data.length/7)) === 0 || i===data.length-1) {
      const label=svg('text',{x:x+width/2,y:204,'text-anchor':'middle',fill:'#6e7b62','font-size':9}); label.textContent=String(d.day).slice(5); chart.append(label);
    }
  });
  root.append(chart);
}
function control(text, fn, cls) { const b=el('button',text,cls); b.type='button'; b.addEventListener('click',()=>action(b,()=>fn(b))); return b; }
function renderKeys() {
  clear($('keys')).append(table(['Name','Allowance','Input / output cap','Period','Used','Expires','Status',''],state.keys.map((key)=>{
    const buttons=el('div');
    if (!key.revoked) buttons.append(control('Revoke',async()=>{if(!confirm('Revoke “'+key.name+'”? It will no longer authenticate.'))return;await api('/api/keys/'+encodeURIComponent(key.id)+'/revoke',{method:'POST',body:{}});await load();},'danger'));
    buttons.append(control('Delete',async()=>{if(!confirm('Permanently delete “'+key.name+'”? This cannot be undone.'))return;await api('/api/keys/'+encodeURIComponent(key.id),{method:'DELETE'});await load();},'danger'));
    return [key.name || key.id,key.allowance==null?'Unlimited':full(key.allowance),(key.inputCap==null?'∞':full(key.inputCap))+' / '+(key.outputCap==null?'∞':full(key.outputCap)),key.period||'never',full(key.used?.total),date(key.expires),el('span',key.revoked?'Revoked':key.expires&&key.expires<Date.now()?'Expired':'Active','pill'+(key.revoked?' bad':'')),buttons];
  }),'No access keys yet.'));
}
function renderAccounts() {
  const root=clear($('accounts'));
  if(!state.accounts.length){root.append(el('div','No connected accounts yet. Connect Google to get started.','empty'));return;}
  for(const account of state.accounts){
    const card=el('article',null,'card'), heading=el('div',null,'card-heading');
    heading.append(el('h2',account.email || account.id,'account-email'),el('span',account.status || (account.blocked?'Blocked':'Connected'),'pill'+(account.blocked?' bad':'')));card.append(heading);
    detail(card,'Sharing',account.shared?'Enabled':'Paused');
    const active=Object.entries(state.active).filter(([,id])=>id===account.id).map(([family])=>family);
    if(active.length)detail(card,'Active for',active.join(', '));
    for(const bucket of account.buckets||[]){
      const block=el('div',null,'bucket');detail(block,bucket.label || bucket.family,typeof bucket.remaining==='number'?full(bucket.remaining)+' remaining':String(bucket.remaining??'Unknown'));detail(block,'Resets',date(bucket.reset));card.append(block);
    }
    if(!(account.buckets||[]).length)card.append(el('p','No quota information available yet.','muted'));
    detail(card,'Updated',date(account.updated));
    if(account.cooldowns && Object.keys(account.cooldowns).length) detail(card,'Cooldowns',typeof account.cooldowns==='object'?JSON.stringify(account.cooldowns):account.cooldowns);
    if(account.denied && Object.keys(account.denied).length) detail(card,'Unavailable',typeof account.denied==='object'?JSON.stringify(account.denied):account.denied);
    const buttons=el('div',null,'account-actions');
    buttons.append(control('Refresh quotas',async()=>{await api('/api/accounts/'+encodeURIComponent(account.id)+'/refresh',{method:'POST',body:{}});await load();}),
      control(account.shared?'Pause sharing':'Enable sharing',async()=>{await api('/api/accounts/'+encodeURIComponent(account.id)+'/toggle',{method:'POST',body:{}});await load();}),
      control('Remove',async()=>{if(!confirm('Remove '+(account.email||'this account')+' from the proxy?'))return;await api('/api/accounts/'+encodeURIComponent(account.id),{method:'DELETE'});await load();},'danger'));
    card.append(buttons);root.append(card);
  }
}
$('add-key').addEventListener('click',()=>{$('key-form').reset();$('key-dialog').showModal();});
document.querySelectorAll('.close-dialog').forEach((button)=>button.addEventListener('click',()=>{const dialog=button.closest('dialog');if(dialog.id==='secret-dialog')$('new-secret').value='';if(dialog.id==='oauth-dialog')$('oauth-callback').value='';dialog.close();}));
$('secret-dialog').addEventListener('close',()=>{$('new-secret').value='';});
function optionalNumber(id){const value=$(id).value;return value===''?null:Number(value);}
$('key-form').addEventListener('submit',(event)=>{
  event.preventDefault();
  action(event.submitter,async()=>{
    const result=await api('/api/keys',{method:'POST',body:{name:$('key-name').value.trim(),allowance:optionalNumber('key-allowance'),inputCap:optionalNumber('key-input'),outputCap:optionalNumber('key-output'),period:$('key-period').value,expires:$('key-expiry').value?new Date($('key-expiry').value).getTime():null}});
    $('key-dialog').close();$('new-secret').value=result.token;$('secret-dialog').showModal();await load();
  });
});
$('copy-secret').addEventListener('click',(event)=>action(event.currentTarget,async()=>{try{await navigator.clipboard.writeText($('new-secret').value);notice('Key copied. Keep it somewhere safe.');}catch{$('new-secret').focus();$('new-secret').select();notice('Select and copy the key manually.');}}));
$('add-account').addEventListener('click',(event)=>action(event.currentTarget,async()=>{
  const popup=window.open('about:blank','agyp-google','popup,width=560,height=760');
  try{
    const result=await api('/api/oauth/start',{method:'POST',body:{}});
    const url=new URL(result.url);
    if(url.protocol!=='https:'||url.hostname!=='accounts.google.com')throw new Error('The server returned an unexpected sign-in address.');
    if(popup){popup.opener=null;popup.location.href=url.href;}else window.location.assign(url.href);
    if(result.manual){ $('oauth-form').reset(); $('oauth-dialog').showModal(); } else notice('Complete Google sign-in, then refresh your accounts.');
  }catch(error){if(popup)popup.close();throw error;}
}));
$('oauth-dialog').addEventListener('close',()=>{$('oauth-callback').value='';});
$('oauth-form').addEventListener('submit',(event)=>{event.preventDefault();action(event.submitter,async()=>{let callbackUrl=$('oauth-callback').value.trim();const url=new URL(callbackUrl);if(!['localhost','127.0.0.1','[::1]'].includes(url.hostname)||!['http:','https:'].includes(url.protocol))throw new Error('Paste the full localhost address from the Google redirect.');await api('/api/oauth/complete',{method:'POST',body:{callbackUrl}});callbackUrl='';$('oauth-callback').value='';$('oauth-dialog').close();notice('Google account connected.');await load();});});
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&state.me&&Number(state.me.sessionExpires)<=Date.now())lock('Your session ended. Enter your key again.');});
load().catch((error)=>{if(!state.me)lock();if(error.status!==401)notice(error.message,true);});
