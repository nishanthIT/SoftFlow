"""Exercise the live local API. No provider mocks; explicit safe-sample sharing only."""
import json,sys,time
from pathlib import Path
import httpx
from dotenv import dotenv_values
root=Path(__file__).resolve().parents[1];v=dotenv_values(root/'.env')
base='http://127.0.0.1:'+v.get('API_PORT','8100')
out=root/'.local/demo';out.mkdir(exist_ok=True)
with httpx.Client(base_url=base,timeout=60) as c:
    r=c.post('/api/auth/login',json={'username':v['ADMIN_USERNAME'],'password':v['ADMIN_PASSWORD']});r.raise_for_status()
    health=c.get('/api/providers/health');health.raise_for_status()
    print('Provider health:',json.dumps(health.json()),flush=True)
    if '--health-only' in sys.argv:sys.exit()
    with (out/'sentinel-demo.exe').open('rb') as f:
        r=c.post('/api/samples',files={'file':('sentinel-demo.exe',f,'application/octet-stream')},data={'external_consent':'true'})
    r.raise_for_status();id=r.json()['analysis_id'];(out/'analysis_id').write_text(id)
    print('Created analysis:',id,flush=True)
    previous=None
    for _ in range(240):
        r=c.get('/api/analysis/'+id);r.raise_for_status();job=r.json()
        stages={e['name']:{'status':e['status'],'reason':e['reason'],'phase':e['data'].get('phase')} for e in job['engines']}
        if stages!=previous:print(json.dumps(stages),flush=True);previous=stages
        if job['status'] in ['COMPLETED','FAILED']:
            for key in ['VIRUSTOTAL_API_KEY','HYBRID_ANALYSIS_API_KEY','CUCKOO_API_TOKEN','AUTH_SECRET','ADMIN_PASSWORD']:
                if v.get(key):assert v[key] not in r.text,key+' leaked in analysis response'
            (out/'report.json').write_text(json.dumps(job,indent=2))
            print('Final job status:',job['status'],flush=True)
            break
        time.sleep(5)
    else:print('Job remains active; inspect UI and persisted checkpoints.',flush=True)
