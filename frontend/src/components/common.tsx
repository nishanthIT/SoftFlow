'use client';
import {useState} from 'react';
import {Check,Copy,AlertCircle,Loader2,Shield} from 'lucide-react';
import {human} from '@/lib/api';
export function Badge({state}:{state?:string}){const tone=['COMPLETED','LIKELY_BENIGN','CONNECTED','APPROVE'].includes(state||'')?'green':['RUNNING','DETECTED'].includes(state||'')?'blue':['SUSPICIOUS','SUSPECTED','STATIC_INDICATOR_ONLY','RATE_LIMITED','TIMEOUT','COMPLETED_WITH_GAPS','CORE_NOT_READY','NO_ANALYSIS_MACHINE','ISOLATION_REQUIRED','REVIEW_REQUIRED'].includes(state||'')?'amber':['FAILED','LIKELY_MALICIOUS','INVALID_API_KEY','ACCESS_DENIED','REJECT'].includes(state||'')?'red':'gray';return <span className={`badge ${tone}`}><span className="status-dot"/>{human(state)}</span>}
export function CopyValue({value}:{value:string}){const [copied,setCopied]=useState(false);return <span className="copy-value"><code>{value}</code><button aria-label="Copy value" onClick={async()=>{try{await navigator.clipboard.writeText(value);setCopied(true);setTimeout(()=>setCopied(false),1800)}catch{setCopied(false)}}}>{copied?<Check size={13}/>:<Copy size={13}/>}</button></span>}
export function ErrorBox({error}:{error:Error|null}){return error?<div role="alert" className="error-box"><AlertCircle size={17}/>{error.message}</div>:null}
export function Empty({title,description}:{title:string;description:string}){return <div className="empty-state"><Shield size={30}/><h3>{title}</h3><p>{description}</p></div>}
export function Loading(){return <div className="loading"><Loader2 className="spin" size={21}/> Loading workspace data…</div>}
export function JsonEvidence({data}:{data:unknown}){return <pre className="json-evidence">{JSON.stringify(data,null,2)}</pre>}
