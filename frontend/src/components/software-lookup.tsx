'use client';
import {useState} from 'react';
import {useRouter} from 'next/navigation';
import {api} from '@/lib/api';
import {Button} from './ui/button';
import {ErrorBox} from './common';

export function SoftwareLookup({sampleId,identity}:{sampleId:string;identity:Record<string,any>}){
 const router=useRouter();const [name,setName]=useState(identity.name||''),[version,setVersion]=useState(identity.version||identity.declared_version||'');
 const [busy,setBusy]=useState(false),[error,setError]=useState<Error|null>(null);
 async function submit(event:React.FormEvent){
  event.preventDefault();setBusy(true);setError(null);
  try{
   const result=await api<{analysis_id:string}>('/api/analysis',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sample_id:sampleId,software_identity:{name:name.trim(),version:version.trim()}})});
   router.push('/analysis/'+result.analysis_id);
  }catch(error){setError(error as Error);setBusy(false)}
 }
 return <details className="software-identity-form"><summary>Check or correct software name and version</summary><p>Create a new analysis of this stored file using the supplied product/version. The previous report is preserved.</p><form onSubmit={submit}><div><label>Software name<input value={name} onChange={e=>setName(e.target.value)} required maxLength={160} disabled={busy}/></label><label>Software version<input value={version} onChange={e=>setVersion(e.target.value)} required maxLength={128} disabled={busy}/></label></div><ErrorBox error={error}/><Button disabled={busy||!name.trim()||!version.trim()}>{busy?'Starting…':'Check name and version'}</Button></form></details>;
}
