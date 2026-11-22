import {useCallback,useEffect,useMemo,useRef,useState,type FormEvent,type ReactNode} from 'react';
import {useTable,type ColumnDef} from '@tanstack/react-table';
import {Bar,BarChart,CartesianGrid,XAxis,YAxis} from 'recharts';
import {Activity,KeyRound,Lock,Plus,RefreshCw,Server,Pause,Play,Trash2} from 'lucide-react';
import {api,signIn,setCsrf,setUnauthorizedHandler} from '@/lib/api';
import {accountFamilies,quotaWindow,quotaLevel,relativeReset,type QuotaBucket} from '@/lib/accounts';
import {Button} from '@/components/ui/button';
import {Input} from '@/components/ui/input';
import {Label} from '@/components/ui/label';
import {Card,CardContent,CardHeader,CardTitle,CardDescription} from '@/components/ui/card';
import {Dialog,DialogContent,DialogHeader,DialogTitle,DialogDescription} from '@/components/ui/dialog';
import {AlertDialog,AlertDialogContent,AlertDialogHeader,AlertDialogTitle,AlertDialogDescription,AlertDialogFooter,AlertDialogCancel,AlertDialogAction} from '@/components/ui/alert-dialog';
import {ChartContainer,ChartTooltip,ChartTooltipContent,ChartLegend,ChartLegendContent,type ChartConfig} from '@/components/ui/chart';
import {Badge} from '@/components/reui/badge';
import {DataGrid,DataGridContainer,dataGridFeatures,type DataGridFeatures} from '@/components/reui/data-grid/data-grid';
import {DataGridTable} from '@/components/reui/data-grid/data-grid-table';
import {DataGridPagination} from '@/components/reui/data-grid/data-grid-pagination';

type Any=any;
const compact=new Intl.NumberFormat('en',{notation:'compact',maximumFractionDigits:1});
const num=(n:unknown)=>compact.format(Number(n)||0);
const full=(n:unknown)=>new Intl.NumberFormat('en').format(Number(n)||0);
const when=(n?:number|null)=>n?new Date(n).toLocaleString([],{dateStyle:'medium',timeStyle:'short'}):'Never';
type View='overview'|'accounts'|'keys';
const TITLES:Record<View,string>={overview:'Overview',accounts:'Accounts',keys:'Access keys'};
const lockMsg='Your session ended. Enter your key to unlock again.';

function Meter({used,cap}:{used:number;cap:number|null}){
 const pct=cap==null?0:Math.max(0,Math.min(100,cap>0?used/cap*100:100));
 return <div role="meter" aria-label="Allowance used" aria-valuemin={0} aria-valuemax={cap??Math.max(used,1)} aria-valuenow={Math.min(used,cap??used)} className="h-1.5 w-full overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full bg-primary transition-[width] duration-300" style={{width:pct+'%'}}/></div>;
}
function Row({k,v}:{k:string;v:ReactNode}){return <div className="flex items-baseline justify-between gap-4 py-1.5 text-sm"><span className="text-muted-foreground">{k}</span><strong className="text-right font-medium tabular-nums">{v}</strong></div>;}
function Grid<T extends object>({data,columns,empty,id}:{data:T[];columns:ColumnDef<DataGridFeatures,T>[];empty:string;id?:string}){
 const table=useTable({features:dataGridFeatures,data,columns,initialState:{pagination:{pageIndex:0,pageSize:20}}});
 if(!data.length)return <div id={id} className="px-6 py-12 text-center text-sm text-muted-foreground">{empty}</div>;
 return <div id={id}><DataGrid table={table} recordCount={data.length} tableLayout={{headerBackground:false,rowBorder:true,cellBorder:false,dense:false}}><DataGridContainer><DataGridTable/></DataGridContainer>{data.length>20&&<DataGridPagination/>}</DataGrid></div>;
}

function QuotaCell({buckets}:{buckets:QuotaBucket[]}){
 if(!buckets.length)return <span className="text-xs text-muted-foreground">Not available</span>;
 return <div className="account-quota">{buckets.map((b,i)=>{
  const known=typeof b.remaining==='number'&&Number.isFinite(b.remaining);
  const value=known?Math.max(0,Math.min(100,b.remaining!*100)):0;
  return <div key={i} className="account-quota-line" title={b.label}>
   <span className="account-window">{quotaWindow(b.label)}</span>
   <span className="account-capacity"><span className="account-track" role="meter" aria-label={(b.label||b.family)+' remaining'} aria-valuemin={0} aria-valuemax={100} aria-valuenow={known?value:undefined} aria-valuetext={b.disabled?'Disabled':known?Math.round(value)+'% remaining':'Unknown'}><span className={'account-fill quota-'+quotaLevel(b.remaining)} style={{width:value+'%'}}/></span><strong>{b.disabled?'Off':known?Math.round(value)+'%':'N/A'}</strong></span>
   <span className="account-reset" title={b.reset?when(b.reset):undefined}>{relativeReset(b.reset)}</span>
  </div>;
 })}</div>;
}

export default function App(){
 const [me,setMe]=useState<Any>(null);
 const [stats,setStats]=useState<Any>({});
 const [keys,setKeys]=useState<Any[]>([]);
 const [accounts,setAccounts]=useState<Any[]>([]);
 const [active,setActive]=useState<Record<string,string>>({});
 const [view,setView]=useState<View>('overview');
 const [loading,setLoading]=useState(true);
 const [busy,setBusy]=useState(false);
 const [note,setNote]=useState<{text:string;error:boolean}|null>(null);
 const [keyOpen,setKeyOpen]=useState(false);
 const [secretOpen,setSecretOpen]=useState(false);
 const [oauthOpen,setOauthOpen]=useState(false);
 const [confirm,setConfirm]=useState<{title:string;body:string;label:string;run:()=>Promise<void>}|null>(null);
 const tokenRef=useRef<HTMLInputElement>(null),secretRef=useRef<HTMLTextAreaElement>(null),oauthRef=useRef<HTMLInputElement>(null);
 const sessionTimer=useRef<number|undefined>(undefined),noteTimer=useRef<number|undefined>(undefined);
 const gen=useRef(0);const meRef=useRef<Any>(null);meRef.current=me;

 const notify=useCallback((text:string,error=false)=>{setNote({text,error});clearTimeout(noteTimer.current);noteTimer.current=window.setTimeout(()=>setNote(null),error?9000:5000);},[]);
 const lock=useCallback((message?:string)=>{
  const had=!!meRef.current;gen.current++;clearTimeout(noteTimer.current);setNote(null);clearTimeout(sessionTimer.current);setCsrf(undefined);meRef.current=null;
  setMe(null);setStats({});setKeys([]);setAccounts([]);setActive({});setKeyOpen(false);setSecretOpen(false);setOauthOpen(false);setConfirm(null);
  if(tokenRef.current)tokenRef.current.value='';if(secretRef.current)secretRef.current.value='';if(oauthRef.current)oauthRef.current.value='';
  if(message&&had)notify(message,true);
 },[notify]);
 useEffect(()=>setUnauthorizedHandler(()=>lock(lockMsg)),[lock]);

 useEffect(()=>{ // theme follows the system, nothing stored
  const q=matchMedia('(prefers-color-scheme: dark)'),f=()=>document.documentElement.classList.toggle('dark',q.matches);f();q.addEventListener('change',f);return()=>q.removeEventListener('change',f);
 },[]);

 const load=useCallback(async()=>{
  setLoading(true);const g=gen.current;
  try{
   const m=await api('/api/me');if(g!==gen.current)return;setCsrf(m.csrf);meRef.current=m;setMe(m);
   clearTimeout(sessionTimer.current);const exp=Number(m.sessionExpires);
   if(Number.isFinite(exp)&&exp>0){if(exp<=Date.now()){lock(lockMsg);return;}sessionTimer.current=window.setTimeout(()=>lock(lockMsg),Math.min(exp-Date.now(),2147483647));}
   const reqs:Promise<Any>[]=[api('/api/stats')];if(m.key.admin)reqs.push(api('/api/keys'),api('/api/accounts'));
   const r=await Promise.allSettled(reqs);if(g!==gen.current||!meRef.current)return;
   setStats(r[0].status==='fulfilled'?r[0].value:{});
   if(m.key.admin){setKeys(r[1].status==='fulfilled'?r[1].value.keys||[]:[]);const a=r[2].status==='fulfilled'?r[2].value:null;setAccounts(a?.accounts||[]);setActive(a?.active||{});}
   else setView('overview');
   const bad=r.find(x=>x.status==='rejected') as PromiseRejectedResult|undefined;if(bad)notify('Some data could not be loaded. '+bad.reason.message,true);
  }finally{setLoading(false)}
 },[lock,notify]);
 useEffect(()=>{load().catch((e:Any)=>{if(!meRef.current)lock();if(e.status!==401)notify(e.message,true)});},[]);// eslint-disable-line
 useEffect(()=>{const f=()=>{if(!document.hidden&&meRef.current&&Number(meRef.current.sessionExpires)<=Date.now())lock(lockMsg)};document.addEventListener('visibilitychange',f);return()=>document.removeEventListener('visibilitychange',f)},[lock]);

 const act=async(fn:()=>Promise<void>)=>{if(busy)return;setBusy(true);try{await fn()}catch(e:Any){notify(e.message||'Something went wrong. Please try again.',true)}finally{setBusy(false)}};
 const ask=(title:string,body:string,label:string,run:()=>Promise<void>)=>setConfirm({title,body,label,run});

 const onLogin=(e:FormEvent)=>{e.preventDefault();act(async()=>{const v=tokenRef.current?.value??'';if(tokenRef.current)tokenRef.current.value='';await signIn(v);clearTimeout(noteTimer.current);setNote(null);await load();});};
 const logout=()=>act(async()=>{await api('/auth/logout',{method:'POST',body:{}});lock();});
 const admin=!!me?.key?.admin;

 // ---- derived
 const rows:Any[]=stats.models||[];
 const sum=(n:string)=>rows.reduce((a,b)=>a+(Number(b[n])||0),0);
 const total=sum('total')||sum('input')+sum('output');
 const graph:Any[]=stats.graph||[];
 const key=me?.key;const used=Number(key?.used?.total)||0;

 const modelCols=useMemo<ColumnDef<DataGridFeatures,Any>[]>(()=>[
  ...(admin?[{accessorKey:'key_id',header:'Key',size:140} as Any]:[]),
  {accessorKey:'model',header:'Model',size:220},
  ...(['input','output','cached','noncached','total','requests'] as const).map(k=>({accessorKey:k,header:k==='noncached'?'Non-cached':k[0].toUpperCase()+k.slice(1),cell:(c:Any)=>full(c.getValue()),meta:{cellClassName:'tabular-nums text-right',headerClassName:'text-right'},size:110})),
 ] as Any,[admin]);
 const keyCols=useMemo<ColumnDef<DataGridFeatures,Any>[]>(()=>[
  {id:'name',header:'Name',size:180,accessorFn:(k:Any)=>k.name||k.id},
  {id:'allowance',header:'Allowance',size:110,accessorFn:(k:Any)=>k.allowance==null?'Unlimited':full(k.allowance)},
  {id:'caps',header:'Input / output cap',size:150,accessorFn:(k:Any)=>(k.inputCap==null?'∞':full(k.inputCap))+' / '+(k.outputCap==null?'∞':full(k.outputCap))},
  {id:'period',header:'Period',size:90,accessorFn:(k:Any)=>k.period||'never'},
  {id:'used',header:'Used',size:100,accessorFn:(k:Any)=>full(k.used?.total)},
  {id:'expires',header:'Expires',size:160,accessorFn:(k:Any)=>when(k.expires)},
  {id:'status',header:'Status',size:100,cell:({row}:Any)=>{const k=row.original;const s=k.revoked?'Revoked':k.expires&&k.expires<Date.now()?'Expired':'Active';return <Badge variant={s==='Active'?'success-light':'destructive-light'}>{s}</Badge>}},
  {id:'actions',header:()=><span className="sr-only">Actions</span>,size:190,cell:({row}:Any)=>{const k=row.original;const n=k.name||k.id;return <div className="flex gap-1">
   {!k.revoked&&<Button variant="ghost" size="sm" className="text-destructive" aria-label={'Revoke '+n} onClick={()=>ask('Revoke “'+n+'”?','It will no longer authenticate.','Revoke',async()=>{await api('/api/keys/'+encodeURIComponent(k.id)+'/revoke',{method:'POST',body:{}});await load();})}>Revoke</Button>}
   <Button variant="ghost" size="sm" className="text-destructive" aria-label={'Delete '+n} onClick={()=>ask('Delete “'+n+'”?','This permanently deletes the key and cannot be undone.','Delete',async()=>{await api('/api/keys/'+encodeURIComponent(k.id),{method:'DELETE'});await load();})}>Delete</Button></div>}},
 ] as Any,[load]);// eslint-disable-line

 const submitKey=(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();const f=e.currentTarget,g=(n:string)=>(f.elements.namedItem(n) as HTMLInputElement).value;const o=(n:string)=>g(n)===''?null:Number(g(n));
  act(async()=>{const ep=gen.current;const r=await api('/api/keys',{method:'POST',body:{name:g('name').trim(),allowance:o('allowance'),inputCap:o('inputCap'),outputCap:o('outputCap'),period:g('period'),expires:g('expires')?new Date(g('expires')).getTime():null}});
   if(ep!==gen.current){f.reset();return;}
   f.reset();setKeyOpen(false);if(secretRef.current)secretRef.current.value=r.token;setSecretOpen(true);await load();});};
 const closeSecret=(o:boolean)=>{setSecretOpen(o);if(!o&&secretRef.current)secretRef.current.value='';};
 const closeOauth=(o:boolean)=>{setOauthOpen(o);if(!o&&oauthRef.current)oauthRef.current.value='';};
 const copySecret=()=>act(async()=>{try{await navigator.clipboard.writeText(secretRef.current?.value??'');notify('Key copied. Keep it somewhere safe.');}catch{secretRef.current?.focus();secretRef.current?.select();notify('Select and copy the key manually.');}});
const addAccount=()=>act(async()=>{
  const g=gen.current;const popup=window.open('about:blank','agyp-google','popup,width=560,height=760');
  try{const r=await api('/api/oauth/start',{method:'POST',body:{}});if(g!==gen.current){popup?.close();return;}const u=new URL(r.url);
   if(u.protocol!=='https:'||u.hostname!=='accounts.google.com')throw new Error('The server returned an unexpected sign-in address.');
   if(popup){popup.opener=null;popup.location.href=u.href;}else window.location.assign(u.href);
   if(r.manual)setOauthOpen(true);else notify('Complete Google sign-in, then refresh your accounts.');
  }catch(e){popup?.close();if(g!==gen.current)return;throw e;}});
 const submitOauth=(e:FormEvent)=>{e.preventDefault();act(async()=>{const g=gen.current;const cb=(oauthRef.current?.value??'').trim();const u=new URL(cb);
  if(!['localhost','127.0.0.1','[::1]'].includes(u.hostname)||!['http:','https:'].includes(u.protocol))throw new Error('Paste the full localhost address from the Google redirect.');
  await api('/api/oauth/complete',{method:'POST',body:{callbackUrl:cb}});if(g!==gen.current)return;closeOauth(false);notify('Google account connected.');await load();});};

 const chartConfig={fresh:{label:'Input'},cached:{label:'Cached input'},output:{label:'Output'}} satisfies ChartConfig;
 const chartData=graph.map(d=>{const i=Math.max(0,Number(d.input)||0),c=Math.min(i,Math.max(0,Number(d.cached)||0));return{day:String(d.day).slice(5),fresh:i-c,cached:c,output:Math.max(0,Number(d.output)||0)};});

 const nav:[View,string,ReactNode][]=[['overview','Overview',<Activity key="a" className="size-4"/>],['accounts','Accounts',<Server key="b" className="size-4"/>],['keys','Access keys',<KeyRound key="c" className="size-4"/>]];

 return <>
  <section id="login" hidden={!!me} className="min-h-dvh place-items-center px-5 py-10 [&:not([hidden])]:grid">
   <div className="w-full max-w-sm">
    <div className="mx-auto mb-8 grid size-14 place-items-center rounded-2xl bg-foreground text-2xl font-semibold text-background" aria-hidden="true">a</div>
    <h1 className="text-center text-3xl">Sign in to agyp</h1>
    <p className="mt-2 text-center text-muted-foreground">Enter your access key to continue.</p>
    <form id="login-form" onSubmit={onLogin} className="mt-8 space-y-3 rounded-2xl bg-card p-5 shadow-sm ring-1 ring-border">
     <Label htmlFor="token">Access key</Label>
     <Input id="token" ref={tokenRef} type="password" placeholder="agyp_…" autoComplete="off" spellCheck={false} required className="h-11 rounded-xl text-base"/>
     <Button type="submit" disabled={busy} className="h-11 w-full rounded-xl text-base">Continue</Button>
    </form>
    <p className="mt-4 text-center text-xs text-muted-foreground">Your key stays in this tab. Only a signed challenge is sent. Sessions last 15 minutes.</p>
   </div>
  </section>

  {me&&<div id="dashboard" className="min-h-dvh">
   <header className="glass sticky top-0 z-30 border-b">
    <div className="mx-auto flex max-w-6xl items-center justify-between gap-3 px-4 py-2.5 sm:px-6">
     <div className="flex items-center gap-2 font-semibold tracking-tight"><span className="grid size-7 place-items-center rounded-lg bg-foreground text-sm text-background" aria-hidden="true">a</span>agyp</div>
     <nav aria-label="Dashboard" className="flex gap-0.5 rounded-xl bg-muted p-0.5">
      {nav.filter(([v])=>v==='overview'||admin).map(([v,l,i])=><button key={v} data-view={v} aria-pressed={view===v} onClick={()=>setView(v)} className={'inline-flex items-center gap-1.5 rounded-[10px] px-3 py-1.5 text-sm font-medium transition-colors '+(view===v?'bg-card text-foreground shadow-sm':'text-muted-foreground hover:text-foreground')}>{i}<span className="max-sm:sr-only">{l}</span></button>)}
     </nav>
     <div className="flex items-center gap-1">
      <Button id="refresh" variant="ghost" size="sm" disabled={busy} onClick={()=>act(load)} aria-label="Refresh"><RefreshCw className="size-4"/><span className="max-md:sr-only">Refresh</span></Button>
      <Button id="logout" variant="ghost" size="sm" onClick={logout} className="max-md:hidden" aria-label="Lock dashboard"><Lock className="size-4"/>Lock</Button>
      <Button id="mobile-logout" variant="ghost" size="sm" onClick={logout} className="md:hidden" aria-label="Lock dashboard"><Lock className="size-4"/></Button>
     </div>
    </div>
   </header>
   <main className="mx-auto max-w-6xl space-y-6 px-4 py-8 sm:px-6">
    <div><h1 id="page-title" className="text-3xl sm:text-4xl">{TITLES[view]}</h1>
     <p id="welcome" className="mt-1 text-muted-foreground">{(key.name||'Your workspace')+(admin?' · Administrator':' · Your usage')}</p></div>
    {loading&&<div id="loading" role="status" className="text-sm text-muted-foreground">Loading…</div>}

    <section id="overview-view" hidden={view!=='overview'} className="space-y-6">
     <div id="metrics" className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      {([['Total tokens',total],['Input',sum('input')],['Output',sum('output')],['Cached',sum('cached')]] as const).map(([l,v])=><Card key={l} size="sm" title={full(v)} className="rounded-2xl"><CardContent><div className="text-sm text-muted-foreground">{l}</div><div className="mt-1 text-3xl font-semibold tracking-tight tabular-nums">{num(v)}</div></CardContent></Card>)}
     </div>
     <div className="grid gap-6 lg:grid-cols-3">
      <Card className="rounded-2xl lg:col-span-2"><CardHeader><CardTitle>Token activity</CardTitle><CardDescription>Daily usage</CardDescription></CardHeader><CardContent>
       <div id="chart">{chartData.length?<ChartContainer config={chartConfig} className="h-64 w-full" role="img" aria-label="Daily input, output, and cached token usage">
        <BarChart data={chartData} accessibilityLayer><CartesianGrid vertical={false} strokeDasharray="3 4"/><XAxis dataKey="day" tickLine={false} axisLine={false} tickMargin={8}/><YAxis width={44} tickLine={false} axisLine={false} tickFormatter={num}/>
         <ChartTooltip content={<ChartTooltipContent/>}/><ChartLegend content={<ChartLegendContent/>}/>
         <Bar dataKey="fresh" stackId="a" fill="var(--color-fresh)" isAnimationActive={false}/><Bar dataKey="cached" stackId="a" fill="var(--color-cached)" isAnimationActive={false}/><Bar dataKey="output" stackId="a" fill="var(--color-output)" radius={[4,4,0,0]} isAnimationActive={false}/></BarChart></ChartContainer>
        :<p className="py-16 text-center text-sm text-muted-foreground">Activity appears after your first request.</p>}</div></CardContent></Card>
      <Card className="rounded-2xl"><CardHeader><CardTitle>Allowance</CardTitle></CardHeader><CardContent id="allowance">
       <div className="text-3xl font-semibold tracking-tight">{key.allowance==null?'Unlimited':num(Math.max(0,key.allowance-used))}</div>
       <p className="mb-3 text-sm text-muted-foreground">{key.allowance==null?'No total token ceiling.':'tokens remaining'}</p>
       <Meter used={used} cap={key.allowance}/>
       <div className="mt-3 divide-y"><Row k="Used" v={full(used)+(key.allowance==null?'':' / '+full(key.allowance))}/>
        <Row k="Input cap" v={key.inputCap==null?'Unlimited':full(key.used?.input)+' / '+full(key.inputCap)}/>
        <Row k="Output cap" v={key.outputCap==null?'Unlimited':full(key.used?.output)+' / '+full(key.outputCap)}/>
        <Row k="Period" v={key.period||'never'}/><Row k="Next reset" v={when(key.resets)}/><Row k="Key expires" v={when(key.expires)}/></div></CardContent></Card>
     </div>
     <Card className="rounded-2xl"><CardHeader><CardTitle>Usage by model</CardTitle></CardHeader><CardContent className="px-0"><div id="models"><Grid data={rows} columns={modelCols} empty="No requests yet. Your first request will appear here."/></div></CardContent></Card>
    </section>

    {admin&&<section id="accounts-view" hidden={view!=='accounts'} className="space-y-4">
     <div className="flex items-center justify-between gap-3"><p className="text-muted-foreground">Connected accounts and their capacity.</p><Button id="add-account" onClick={addAccount} disabled={busy} className="rounded-full"><Plus className="size-4"/>Connect Google</Button></div>
     <p className="text-xs text-muted-foreground lg:hidden">Scroll sideways for quotas and account actions.</p>
     <div id="accounts" className="account-table-shell">
      {!accounts.length?<p className="py-16 text-center text-sm text-muted-foreground">No connected accounts yet. Connect Google to get started.</p>:<div className="account-table-scroll" role="region" aria-label="Connected accounts, scroll horizontally for quotas and actions" tabIndex={0}>
       <table className="account-table"><caption className="sr-only">Connected accounts, remaining quotas and sharing controls</caption><thead><tr>
        <th scope="col" className="account-identity">Account</th><th scope="col">Status</th>{accountFamilies.map(([f,label])=><th key={f} scope="col">{label}</th>)}<th scope="col" className="account-actions-heading">Actions</th>
       </tr></thead><tbody>{accounts.map(a=>{
        const selected=Object.entries(active).filter(([,id])=>id===a.id).map(([f])=>accountFamilies.find(([id])=>id===f)?.[1]||f);
        const paused=a.status==='disabled',nm=a.email||a.id;
        const status=a.blocked?'Blocked':paused?'Paused':a.status==='ready'?'Ready':a.status==='auth_error'?'Auth error':String(a.status||'Unknown').replace(/_/g,' ').replace(/^./,(c:string)=>c.toUpperCase());
        const extra=(a.buckets||[]).filter((b:Any)=>!accountFamilies.some(([f])=>f===b.family));
        return <tr key={a.id}>
         <th scope="row" className="account-identity"><div className="account-name" title={nm}><span className="account-avatar" aria-hidden="true">{nm[0]?.toUpperCase()}</span><span className="account-email">{nm}</span></div>
          <div className="account-meta" title={when(a.updated)}>Updated {a.updated?new Date(a.updated).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}):'unknown'}</div>
          {(a.shared||selected.length>0)&&<div className="account-meta">{[a.shared?'Shared Gemini pool':'',selected.length?'Active for '+selected.join(', '):''].filter(Boolean).join(' · ')}</div>}
          {(extra.length>0||Object.keys(a.cooldowns||{}).length>0||Object.keys(a.denied||{}).length>0)&&<details className="account-details"><summary>Details</summary>{extra.map((b:Any,i:number)=><div key={i}>{b.label||b.family}: {b.disabled?'Disabled':typeof b.remaining==='number'?Math.round(b.remaining*100)+'% remaining':'Unknown'} · {relativeReset(b.reset)}</div>)}{Object.keys(a.cooldowns||{}).length>0&&<div>Cooldowns: {JSON.stringify(a.cooldowns)}</div>}{Object.keys(a.denied||{}).length>0&&<div>Unavailable: {JSON.stringify(a.denied)}</div>}</details>}
         </th>
         <td><Badge variant={a.blocked||(!paused&&a.status!=='ready')?'destructive-light':paused?'secondary':'success-light'}>{status}</Badge></td>
         {accountFamilies.map(([f])=><td key={f} className={paused?'account-paused':undefined}><QuotaCell buckets={(a.buckets||[]).filter((b:Any)=>b.family===f)}/></td>)}
         <td><div className="account-actions">
          <Button variant="ghost" size="icon" title="Refresh quotas" aria-label="Refresh quotas" disabled={busy} onClick={()=>act(async()=>{await api('/api/accounts/'+encodeURIComponent(a.id)+'/refresh',{method:'POST',body:{}});await load();})}><RefreshCw className="size-4"/></Button>
          <Button variant="ghost" size="icon" title={paused?'Enable sharing':'Pause sharing'} aria-label={paused?'Enable sharing':'Pause sharing'} disabled={busy} onClick={()=>act(async()=>{await api('/api/accounts/'+encodeURIComponent(a.id)+'/toggle',{method:'POST',body:{}});await load();})}>{paused?<Play className="size-4"/>:<Pause className="size-4"/>}</Button>
          <Button variant="ghost" size="icon" title="Remove" aria-label="Remove" className="text-destructive" disabled={busy} onClick={()=>ask('Remove '+nm+'?','It will be removed from the proxy.','Remove',async()=>{await api('/api/accounts/'+encodeURIComponent(a.id),{method:'DELETE'});await load();})}><Trash2 className="size-4"/></Button>
         </div></td>
        </tr>;
       })}</tbody></table>
      </div>}
     </div><p className="text-xs text-muted-foreground">Quotas are last reported values, not account availability. Green ≥50%, amber ≥20%, red below 20%. <span className="lg:hidden">Scroll sideways for all columns.</span></p></section>}

    {admin&&<section id="keys-view" hidden={view!=='keys'} className="space-y-4">
     <div className="flex items-center justify-between gap-3"><p className="text-muted-foreground">A separate key for every person, tool, or project.</p><Button id="add-key" onClick={()=>setKeyOpen(true)} className="rounded-full"><Plus className="size-4"/>Create key</Button></div>
     <Card className="rounded-2xl"><CardContent className="px-0"><div id="keys"><Grid data={keys} columns={keyCols} empty="No access keys yet."/></div></CardContent></Card>
    </section>}
   </main>
  </div>}

  <Dialog open={keyOpen} onOpenChange={setKeyOpen}><DialogContent id="key-dialog" keepMounted className="sm:max-w-md rounded-2xl">
   <form id="key-form" onSubmit={submitKey} className="grid gap-4">
    <DialogHeader><DialogTitle>Create access key</DialogTitle><DialogDescription>Give it a name and just the room it needs.</DialogDescription></DialogHeader>
    <div className="grid gap-1.5"><Label htmlFor="key-name">Name</Label><Input id="key-name" name="name" required maxLength={100} placeholder="My workstation" className="h-10"/></div>
    <div className="grid grid-cols-2 gap-3">
     <div className="grid gap-1.5"><Label htmlFor="key-allowance">Total allowance</Label><Input id="key-allowance" name="allowance" type="number" min={0} step={1} placeholder="Unlimited" className="h-10"/></div>
     <div className="grid gap-1.5"><Label htmlFor="key-period">Resets</Label><select id="key-period" name="period" defaultValue="never" className="h-10 rounded-lg border border-input bg-transparent px-2.5 text-sm"><option value="never">Never</option><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option></select></div>
     <div className="grid gap-1.5"><Label htmlFor="key-input">Input cap</Label><Input id="key-input" name="inputCap" type="number" min={0} step={1} placeholder="Unlimited" className="h-10"/></div>
     <div className="grid gap-1.5"><Label htmlFor="key-output">Output cap</Label><Input id="key-output" name="outputCap" type="number" min={0} step={1} placeholder="Unlimited" className="h-10"/></div>
    </div>
    <div className="grid gap-1.5"><Label htmlFor="key-expiry">Expires <span className="text-muted-foreground">(optional)</span></Label><Input id="key-expiry" name="expires" type="datetime-local" className="h-10"/></div>
    <Button type="submit" disabled={busy} className="h-11 rounded-xl">Create key</Button>
   </form></DialogContent></Dialog>

  <Dialog open={secretOpen} onOpenChange={closeSecret}><DialogContent id="secret-dialog" keepMounted className="sm:max-w-md rounded-2xl">
   <DialogHeader><DialogTitle>Your new key</DialogTitle><DialogDescription>Copy it now. This is the only time it will be shown.</DialogDescription></DialogHeader>
   <Label htmlFor="new-secret">Access key</Label>
   <textarea id="new-secret" ref={secretRef} readOnly rows={3} spellCheck={false} className="w-full resize-none rounded-lg border border-input bg-muted p-3 font-mono text-sm"/>
   <Button id="copy-secret" onClick={copySecret} className="h-11 rounded-xl">Copy key</Button>
   <p className="text-xs text-muted-foreground">Closing this window clears the key from the page.</p></DialogContent></Dialog>

  <Dialog open={oauthOpen} onOpenChange={closeOauth}><DialogContent id="oauth-dialog" keepMounted className="sm:max-w-md rounded-2xl">
   <form id="oauth-form" onSubmit={submitOauth} className="grid gap-4">
    <DialogHeader><DialogTitle>Finish connecting Google</DialogTitle><DialogDescription>Sign in in the Google window. When it redirects to an unreachable localhost page, copy that page’s full address and paste it below. The page not loading is expected.</DialogDescription></DialogHeader>
    <Label htmlFor="oauth-callback">Full localhost callback URL</Label>
    <Input id="oauth-callback" ref={oauthRef} type="url" required autoComplete="off" spellCheck={false} placeholder="http://localhost:…/?code=…&state=…" className="h-10"/>
    <p className="text-xs text-muted-foreground">Used once to finish sign-in. Google tokens never appear here.</p>
    <Button type="submit" disabled={busy} className="h-11 rounded-xl">Complete connection</Button>
   </form></DialogContent></Dialog>

  <AlertDialog open={!!confirm} onOpenChange={o=>{if(!o)setConfirm(null)}}><AlertDialogContent id="confirm-dialog" className="rounded-2xl">
   <AlertDialogHeader><AlertDialogTitle>{confirm?.title}</AlertDialogTitle><AlertDialogDescription>{confirm?.body}</AlertDialogDescription></AlertDialogHeader>
   <AlertDialogFooter><AlertDialogCancel>Cancel</AlertDialogCancel><AlertDialogAction variant="destructive" onClick={()=>{const c=confirm;setConfirm(null);if(c)act(c.run)}}>{confirm?.label}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>

  {note&&<div id="notice" role="status" aria-live="polite" className={'glass fixed bottom-4 left-1/2 z-[60] w-[calc(100%-2rem)] max-w-md -translate-x-1/2 rounded-2xl px-4 py-3 text-sm shadow-lg ring-1 ring-border '+(note.error?'text-destructive':'')}>{note.text}</div>}
 </>;
}
