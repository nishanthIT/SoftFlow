'use client';
import {human,size} from '@/lib/api';
import {JsonEvidence} from './common';

export function NetworkEvidence({name,data:d}:{name:string;data:Record<string,any>}){
  const events=name==='dns'?[...(d.queries||[]),...(d.responses||[])]:d.events||[];
  return <>
    <p>Monitoring: {human(d.monitoring_status||'UNAVAILABLE')} · Traffic: {human(d.traffic_status||'UNKNOWN')}</p>
    <p>Network policy: {human(d.network_policy||'unknown')}{d.network_policy==='blocked'?' · External access is intentionally blocked. Captured attempts may still appear.':''}</p>
    {d.capture_scope&&<p>{d.capture_scope}</p>}
    {d.limitations&&<p>{d.limitations}</p>}
    {events.length>0&&<div className="table-scroll"><table><thead><tr><th>Type</th><th>Domain / destination</th><th>Port</th><th>Observation</th></tr></thead><tbody>{events.map((e:any,index:number)=><tr key={index}><td>{e.type||'DNS response'}</td><td>{e.domain||e.host||e.ip||e.dstip||'Not supplied'}</td><td>{e.port??e.dstport??'—'}</td><td>{e.url||e.data||e.answer?JSON.stringify(e.url||e.data||e.answer):e.method||e.query_type||'See source evidence'}</td></tr>)}</tbody></table></div>}
    {d.events_truncated&&<p>The displayed event list was truncated by the collector. Refer to the capture artifact for additional packets.</p>}
  </>;
}

export function SandboxArtifacts({data:d}:{data:Record<string,any>}){
  const artifacts=d.artifacts||{};
  return <>{artifacts.files?.length>0&&<><h3>Collected artifacts</h3><ul>{artifacts.files.map((f:any,index:number)=><li key={index}>{typeof f.download_url==='string'&&f.download_url.startsWith('/api/analysis/')?<a href={f.download_url} download>{f.name}</a>:f.name} · {size(f.size)} · {f.kind}</li>)}</ul></>}{artifacts.errors?.length>0&&<><h3>Artifact collection gaps</h3><JsonEvidence data={artifacts.errors}/></>}</>;
}
