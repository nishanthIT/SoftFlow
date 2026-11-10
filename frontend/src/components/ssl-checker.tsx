'use client';
import {useEffect,useRef,useState} from 'react';
import {useMutation,useQuery,useQueryClient} from '@tanstack/react-query';
import {ArrowDownUp,Download,FileText,Globe,Loader2,Search,UploadCloud,X} from 'lucide-react';
import {api,date,human,size} from '@/lib/api';
import {Badge,Empty,ErrorBox} from './common';
import {Button} from './ui/button';

type Result={domain:string;status:string;ssl_valid:string;expiry_date:string;days_remaining:number|'';common_name:string;issuer:string;san:string;error:string};
type Scan={id:string;filename:string;status:string;total:number;completed:number;created_at:string;expires_at:string;error?:string;summary:Record<string,number>;results?:Result[]};
const active=(status:string)=>['QUEUED','RUNNING'].includes(status);
export function SSLChecker(){
 const cache=useQueryClient();const [file,setFile]=useState<File|null>(null),[id,setId]=useState(''),[search,setSearch]=useState(''),[status,setStatus]=useState('');
 const [sort,setSort]=useState<keyof Result>('domain'),[ascending,setAscending]=useState(true);
 const fileInput=useRef<HTMLInputElement>(null),dragDepth=useRef(0);
 const [dragging,setDragging]=useState(false),[fileError,setFileError]=useState<Error|null>(null);
 useEffect(()=>{setId(new URLSearchParams(location.search).get('check')||'')},[]);
 function select(identifier:string){setId(identifier);setStatus('');setSearch('');history.replaceState(null,'','/ssl-checker?check='+encodeURIComponent(identifier))}
 const recent=useQuery({queryKey:['ssl-checks'],queryFn:()=>api<Scan[]>('/api/ssl-checks'),refetchInterval:5000});
 const scan=useQuery({queryKey:['ssl-check',id],enabled:!!id,queryFn:()=>api<Scan>('/api/ssl-checks/'+id),refetchInterval:q=>!q.state.data||active(q.state.data.status)?1500:false,refetchIntervalInBackground:true});
 const upload=useMutation({mutationFn:async()=>{if(!file)throw new Error('Choose a text file');if(file.size>256*1024)throw new Error('Text file exceeds 256 KiB');const body=new FormData();body.append('file',file);return api<Scan>('/api/ssl-checks',{method:'POST',body})},onSuccess:data=>{cache.setQueryData(['ssl-check',data.id],data);cache.invalidateQueries({queryKey:['ssl-checks']});select(data.id)}});
 function chooseFiles(files:File[]){
  if(upload.isPending||!files.length)return;
  upload.reset();setFileError(null);setFile(null);
  if(files.length!==1){setFileError(new Error('Choose one .txt file at a time.'));return;}
  const next=files[0];
  if(!next.name.toLowerCase().endsWith('.txt')){setFileError(new Error('Choose a .txt file with one domain per line.'));return;}
  if(next.size===0){setFileError(new Error('The text file is empty. Add one domain per line.'));return;}
  if(next.size>256*1024){setFileError(new Error('Text file exceeds 256 KiB.'));return;}
  setFile(next);
 }
 const data=scan.data;
 const results=(data?.results||[]).filter(row=>(!status||row.status===status)&&Object.values(row).join(' ').toLowerCase().includes(search.toLowerCase())).slice().sort((a,b)=>{const left=a[sort],right=b[sort];return (typeof left==='number'&&typeof right==='number'?left-right:String(left).localeCompare(String(right)))*(ascending?1:-1)});
 function changeSort(key:keyof Result){if(sort===key)setAscending(!ascending);else{setSort(key);setAscending(true)}}
 return <>
  <div className="page-heading"><div><div className="eyebrow">DOMAIN CERTIFICATE HEALTH</div><h1>SSL expiry checker<span className="heading-dot">.</span></h1><p>Upload domains, review certificate expiry and download your Excel report.</p></div><Globe size={28}/></div>
  <section className="panel ssl-upload"><div><h2>Check a domain list</h2><p>One public domain per line in a UTF-8 .txt file. Up to 500 domains, 256 KiB.</p><code>example.org<br/>www.python.org</code><p>Uses real DNS and TLS checks on port 443. No sandbox or login is needed. Wildcards are listed as not tested.</p></div><form onSubmit={e=>{e.preventDefault();if(file&&!upload.isPending)upload.mutate()}}>
   <input ref={fileInput} id="domain-list" className="sr-only" aria-label="Choose domain text file" type="file" accept=".txt,text/plain" disabled={upload.isPending} onChange={e=>{chooseFiles(Array.from(e.target.files||[]));e.target.value=''}}/>
   <div className={`ssl-dropzone${dragging?' dragging':''}`} role="group" aria-label="Domain file upload" aria-disabled={upload.isPending}
    onDragEnter={e=>{e.preventDefault();if(!upload.isPending&&e.dataTransfer.types.includes('Files')){dragDepth.current++;setDragging(true)}}}
    onDragOver={e=>{e.preventDefault();e.dataTransfer.dropEffect=upload.isPending?'none':'copy'}}
    onDragLeave={e=>{e.preventDefault();dragDepth.current=Math.max(0,dragDepth.current-1);if(!dragDepth.current)setDragging(false)}}
    onDrop={e=>{e.preventDefault();e.stopPropagation();dragDepth.current=0;setDragging(false);chooseFiles(Array.from(e.dataTransfer.files))}}>
    <UploadCloud size={32}/><strong>Drag &amp; drop your .txt file here</strong><span>or choose a file from your device</span>
    <Button type="button" variant="outline" disabled={upload.isPending} onClick={()=>fileInput.current?.click()}><UploadCloud size={16}/>Upload TXT file</Button>
    <small>One .txt file · Maximum 256 KiB</small>
   </div>
   {file&&<div className="ssl-selected-file" role="status"><FileText size={22}/><div><strong>{file.name}</strong><small>{size(file.size)} · Ready to check</small></div><button type="button" aria-label="Remove domain file" disabled={upload.isPending} onClick={()=>{setFile(null);setFileError(null);upload.reset()}}><X size={17}/></button></div>}
   <ErrorBox error={fileError||upload.error}/>
   <Button type="submit" disabled={!file||upload.isPending}>{upload.isPending?<Loader2 size={16} className="spin"/>:<Globe size={16}/>}Check certificates</Button>
   <small>Results expire after 7 days. Uploaded text is discarded after parsing.</small>
  </form></section>
  <ErrorBox error={scan.error}/>
  {data&&<section className="panel evidence-panel ssl-results"><div className="section-heading"><div><h2>{data.filename}</h2><p>Created {date(data.created_at)} · Expires {date(data.expires_at)}</p></div><Badge state={data.status}/>{!active(data.status)&&data.completed>0&&<Button asChild><a href={'/api/ssl-checks/'+id+'/report.xlsx'}><Download size={16}/>Download Excel</a></Button>}</div>
   {data.error&&<p role="alert">{data.error}</p>}
   {active(data.status)&&<div role="status"><p><Loader2 size={14} className="spin"/> {data.status==='QUEUED'?'Queued':'Checking certificates'} · {data.completed} / {data.total}</p><progress aria-label="Certificate check progress" value={data.completed} max={data.total}/><small>You can leave this page and reopen the saved check below.</small></div>}
   <div className="evidence-metrics">{[['Checked',data.completed+'/'+data.total],['Expired',data.summary.EXPIRED||0],['Expiring soon',data.summary.EXPIRING_SOON||0],['Valid',data.summary.VALID||0]].map(([name,value])=><div key={name}><small>{name}</small><strong>{value}</strong></div>)}</div>
   <div className="table-toolbar ssl-toolbar"><label>Status <select aria-label="Filter certificate status" value={status} onChange={e=>setStatus(e.target.value)}><option value="">All statuses</option>{Object.keys(data.summary).sort().map(s=><option key={s} value={s}>{human(s)} ({data.summary[s]})</option>)}</select></label><div className="search-field"><Search size={15}/><input aria-label="Search certificate results" placeholder="Search domains or issuer…" value={search} onChange={e=>setSearch(e.target.value)}/></div></div>
   {results.length?<div className="table-scroll"><table className="ssl-table"><thead><tr>{[['domain','DOMAIN'],['status','STATUS'],['expiry_date','EXPIRY (UTC)'],['days_remaining','DAYS LEFT']].map(([key,label])=><th key={key} aria-sort={sort===key?(ascending?'ascending':'descending'):'none'}><button onClick={()=>changeSort(key as keyof Result)}>{label}<ArrowDownUp size={12}/></button></th>)}<th>CERTIFICATE DETAILS</th></tr></thead><tbody>{results.map(row=><tr key={row.domain}><td><strong>{row.domain}</strong><small>SSL valid: {row.ssl_valid}</small></td><td>{human(row.status)}</td><td>{row.expiry_date||'—'}</td><td>{row.days_remaining===''?'—':row.days_remaining}</td><td><details><summary>{row.issuer||'View details'}</summary><p>Common name: {row.common_name||'Unavailable'}</p><p>Alternative names: {row.san||'Unavailable'}</p>{row.error&&<p>{row.error}</p>}</details></td></tr>)}</tbody></table></div>:<Empty title={active(data.status)?'Waiting for results':'No matching results'} description="Completed results appear here. Adjust the search or filter to see other rows."/>}
  </section>}
  <section className="panel evidence-panel"><h2>Recent SSL checks</h2><p>Reopen a saved check and download its Excel report. Retained for 7 days.</p><ErrorBox error={recent.error}/>{recent.data?.length?<div className="table-scroll"><table><thead><tr><th>DOMAIN LIST</th><th>STATUS</th><th>CHECKED</th><th>EXPIRES</th></tr></thead><tbody>{recent.data.map(row=><tr key={row.id}><td><button className="ssl-history-link" onClick={()=>select(row.id)}>{row.filename}</button></td><td><Badge state={row.status}/></td><td>{row.completed}/{row.total}</td><td>{date(row.expires_at)}</td></tr>)}</tbody></table></div>:<p>No checks yet. Upload your domain list above.</p>}</section>
 </>;
}
