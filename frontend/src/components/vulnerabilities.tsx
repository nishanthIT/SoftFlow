'use client';
import {Badge,JsonEvidence} from './common';
import {human} from '@/lib/api';

function safeReference(value:unknown){try{const url=new URL(String(value));return ['http:','https:'].includes(url.protocol)&&!url.username&&!url.password?url.href:null}catch{return null}}
function range(e:any){
  if(e.affected_range)return e.affected_range;
  if(e.criteria){const c=e.criteria;const limits=[['versionStartIncluding','≥'],['versionStartExcluding','>'],['versionEndIncluding','≤'],['versionEndExcluding','<']].filter(([key])=>c[key]).map(([key,sign])=>`${sign} ${c[key]}`);return limits.join(', ')||c.criteria||'Version conditions in source';}
  if(e.ranges?.length)return e.ranges.map((r:any)=>(r.events||[]).map((v:any)=>Object.entries(v).map(([k,val])=>`${human(k)} ${val}`).join(', ')).join('; ')).filter(Boolean).join('; ');
  if(e.versions?.length)return e.versions.map((v:any)=>typeof v==='string'?v:`${v.version}${v.lessThan?` to < ${v.lessThan}`:v.lessThanOrEqual?` to ≤ ${v.lessThanOrEqual}`:''} (${v.status||'unspecified'})`).join(', ');
  return 'No comparable version range supplied';
}
export function Vulnerabilities({data:d}:{data:Record<string,any>}){
  const identity=d.identity||{};const findings=d.findings||[];
  return <div className="vulnerability-evidence">
    <Badge state={d.status||'UNAVAILABLE'}/>
    {d.conclusion&&<h3>{d.conclusion}</h3>}
    {d.reason&&<p>{d.reason}</p>}
    {identity.name&&<><h3>{identity.name} {identity.version||'(version unverified)'}</h3><p>{identity.vendor||'Publisher not identified'} · {identity.architecture||'Architecture not identified'}</p></>}
    {identity.identity_assurance&&<p>{identity.identity_assurance}</p>}
    {identity.source&&<p>Identity source: {identity.source}</p>}
    {d.summary&&<div className="evidence-metrics">{Object.entries(d.summary).map(([key,value])=><div key={key}><small>{human(key)}</small><strong>{String(value)}</strong></div>)}</div>}
    {d.providers?.length>0&&<div className="table-scroll"><table><thead><tr><th>Intelligence source</th><th>Status</th><th>Coverage</th></tr></thead><tbody>{d.providers.map((p:any)=><tr key={p.provider}><td>{p.provider}</td><td>{human(p.status)}</td><td>{p.reason||p.message||`${p.records??0} source records`}</td></tr>)}</tbody></table></div>}
    {findings.length===0&&<p>{d.status==='COMPLETED'?'No matching advisories were returned by the completed lookups. This does not establish safety.':'No verified vulnerability conclusion is available from these results.'}</p>}
    {findings.map((f:any)=><article className="vulnerability-finding" key={f.id}>
      <h3>{f.id} <Badge state={f.classification}/></h3>
      <p>{f.description}</p>
      <p><strong>Severity:</strong> {f.cvss?.severity||'Not supplied'}{f.cvss?.score!=null?` · CVSS ${f.cvss.score}`:''} · <strong>CISA KEV:</strong> {f.cisa_kev===true?'Listed':f.cisa_kev===false?'Not listed':'Unverified'}</p>
      {f.version_evidence?.length>0&&<div className="table-scroll"><table><thead><tr><th>Version source</th><th>Published version evidence</th><th>Match</th></tr></thead><tbody>{f.version_evidence.map((e:any,index:number)=><tr key={index}><td>{e.source}</td><td>{range(e)}{e.conditional_environment?' · Additional environment conditions':''}</td><td>{human(e.classification)}</td></tr>)}</tbody></table></div>}
      {f.fixed_versions?.length>0&&<p><strong>Published fixed versions:</strong> {f.fixed_versions.join(', ')}</p>}
      {f.remediation&&<p><strong>Remediation:</strong> {f.remediation}</p>}
      {f.references?.length>0&&<ul>{f.references.map((r:any,index:number)=>{const url=safeReference(r.url);return url?<li key={index}><a href={url} target="_blank" rel="noopener noreferrer">{url}</a>{r.public_exploit_reference?' · Public exploit reference (not executed)':''}</li>:null})}</ul>}
      <small>Sources: {f.sources?.join(', ')||'Not supplied'}</small>
      <details><summary>Detailed matching evidence</summary><JsonEvidence data={f.version_evidence}/></details>
    </article>)}
    {d.scope&&<p>{d.scope}</p>}
  </div>;
}
