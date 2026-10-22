'use client';
import {useState} from 'react';
import {useQueryClient} from '@tanstack/react-query';
import {api,Analysis,human,date} from '@/lib/api';
import {Badge,ErrorBox,JsonEvidence} from './common';
import {Button} from './ui/button';

export function ApprovalPanel({analysis}:{analysis:Analysis}) {
  const client=useQueryClient();
  const [decision,setDecision]=useState('REVIEW_REQUIRED');
  const [reason,setReason]=useState('');
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState<Error|null>(null);
  const assessment=analysis.approval;
  return <section className="panel evidence-panel approval-panel">
    <h2>Approval decision</h2>
    <p>Recommendation: <Badge state={assessment?.recommendation||'REVIEW_REQUIRED'}/></p>
    <p>Analysis status: {human(assessment?.analysis_status||analysis.status)}</p>
    <ul>{assessment?.reasons.map((r:string)=><li key={r}>{r}</li>)}</ul>
    <p>No malicious behavior detected does not establish that software has no vulnerabilities. Vulnerability assessment: not performed.</p>
    <details><summary>Decision criteria, findings and limitations</summary><JsonEvidence data={assessment}/></details>
    <h3>Record a workspace decision</h3>
    <form onSubmit={async e=>{
      e.preventDefault();setBusy(true);setError(null);
      try {
        await api(`/api/analysis/${analysis.id}/decision`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({decision,reason})});
        setReason('');await client.invalidateQueries({queryKey:['analysis',analysis.id]});
      } catch(e) {setError(e as Error)} finally {setBusy(false)}
    }}>
      <label>Decision<select aria-label="Decision" value={decision} onChange={e=>setDecision(e.target.value)}>
        <option value="REVIEW_REQUIRED">Review required</option>
        <option value="REJECT">Reject</option>
        <option value="APPROVE" disabled={assessment?.recommendation!=='APPROVE'}>Approve</option>
      </select></label>
      <label>Decision reason<textarea value={reason} onChange={e=>setReason(e.target.value)} required maxLength={2000}/></label>
      <ErrorBox error={error}/><Button disabled={busy||!reason.trim()||(decision==='APPROVE'&&assessment?.recommendation!=='APPROVE')}>{busy?'Saving…':'Record decision'}</Button>
    </form>
    <p>Decisions are attributed to the shared LAN workspace. No individual identity is verified.</p>
    {analysis.decisions?.map(r=><div className="coverage-row" key={r.id}><Badge state={r.data.decision}/><span>{r.data.reason}</span><small>{date(r.created_at)}</small></div>)}
  </section>;
}
