export async function api<T=any>(path:string,init?:RequestInit):Promise<T>{
 const r=await fetch(path,{...init});
 if(!r.ok){const d=await r.json().catch(()=>({detail:'Service unavailable'}));throw new Error(typeof d.detail==='string'?d.detail:`Request failed (${r.status})`);} return r.json();
}
export type Engine={name:string;status:string;reason?:string;data:Record<string,any>;started_at?:string;completed_at?:string};
export type Sample={id:string;filename:string;size:number;sha256:string;sha1:string;md5:string;created_at:string;latest_analysis_id?:string;status?:string;verdict?:string};
export type Approval={recommendation:string;analysis_status:string;reasons:string[];findings:unknown[];coverage_gaps:unknown[];criteria:Record<string,unknown>;limitations:string[]};
export type Analysis={approval?:Approval;decisions?:{id:string;created_at:string;data:{decision:string;reason:string}}[];id:string;status:string;final_status?:string;progress:number;sample:Sample;engines:Engine[];created_at:string;completed_at?:string};
export const labels:Record<string,string>={'validation':'File validation','hashing':'File hashing','static':'Static analysis','yara':'YARA rules','virustotal':'VirusTotal','hybrid-analysis':'Hybrid Analysis','sandbox':'Cuckoo / CAPE Sandbox','behavior':'Behavior analysis','network':'Network & DNS','ai':'AI / LLM detection','correlation':'Evidence correlation','verdict':'Security verdict','report':'Final report'};
export const human=(s?:string)=>s?s.replaceAll('_',' ').toLowerCase().replace(/^./,c=>c.toUpperCase()):'Pending';
export const date=(s:string)=>new Date(s).toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
export const size=(n:number)=>n>1048576?`${(n/1048576).toFixed(1)} MB`:`${(n/1024).toFixed(1)} KB`;
