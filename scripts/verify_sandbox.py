"""Real API -> queue -> worker -> sandbox -> report verification. No mocks.

Default exits nonzero unless sandbox, behavior and network finish successfully.
--allow-unavailable exercises a degraded workflow but still exits 2 if dynamic
execution was not verified. The generated status file distinguishes both.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import httpx
from dotenv import dotenv_values

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-unavailable',action='store_true')
    parser.add_argument('--sample',type=Path,help='Optional harmless Windows executable; never executed on the host')
    parser.add_argument('--timeout',type=int,default=2400)
    args=parser.parse_args()
    values={**dotenv_values(ROOT/'.env'),**os.environ}
    output=ROOT/'.local/verification';output.mkdir(parents=True,exist_ok=True,mode=0o700)
    status={'workflow_verified':False,'sandbox_verified':False,'mocked':False}
    try:
        with httpx.Client(base_url=values.get('VERIFY_API_URL') or 'http://127.0.0.1:'+values.get('API_PORT','8100'),timeout=30) as client:
            r=client.get('/api/providers/health');r.raise_for_status();status['provider_health']=r.json()
            sandbox=next(p for p in r.json()['providers'] if p['id']=='sandbox')
            print('Sandbox readiness:',sandbox['status'],flush=True)
            if not args.allow_unavailable and not sandbox.get('execution_ready'):
                status['error']='Sandbox execution prerequisites are not ready';return 2
            sample=args.sample
            if sample is None:
                compiler=values.get('MINGW_CC') or shutil.which('x86_64-w64-mingw32-gcc')
                if not compiler:raise RuntimeError('Install gcc-mingw-w64-x86-64 or pass --sample with a harmless executable')
                sample=output/'sentinelscan-smoke.exe'
                subprocess.run([compiler,str(ROOT/'sandbox/smoke.c'),'-Os','-s','-o',str(sample),'-lws2_32'],check=True)
            data=sample.read_bytes();sha=hashlib.sha256(data).hexdigest()
            r=client.post('/api/samples',files={'file':(sample.name,data,'application/octet-stream')},data={'external_consent':'false'});r.raise_for_status()
            identifier=r.json()['analysis_id'];status['analysis_id']=identifier
            (output/'analysis_id').write_text(identifier)
            print('Analysis:',identifier,flush=True)
            deadline=time.monotonic()+args.timeout;previous=None
            while time.monotonic()<deadline:
                r=client.get('/api/analysis/'+identifier);r.raise_for_status();job=r.json()
                states={e['name']:e['status'] for e in job['engines']}
                if states!=previous:print(json.dumps(states),flush=True);previous=states
                if job['status'] in ['COMPLETED','FAILED']:break
                time.sleep(2)
            else:raise RuntimeError('Live workflow exceeded verification deadline; inspect persisted analysis')
            r=client.get('/api/analysis/'+identifier+'/report');r.raise_for_status();report=r.json()
            assert report['schema_version']=='2.0'
            assert report['sample']['sha256']==sha and report['sample']['filename']==sample.name
            assert report['final_status']==job['final_status']
            assert len(report['steps'])==len(job['engines'])
            assert report['approval']['reasons'] and report['approval']['limitations']
            if not all(states.get(k)=='COMPLETED' for k in ['sandbox','behavior','network']):
                assert report['approval']['recommendation']=='REVIEW_REQUIRED'
            assert all(s['status'] not in ['RUNNING','QUEUED'] for s in report['steps'])
            for key in ['AUTH_SECRET','ADMIN_PASSWORD','CUCKOO_API_TOKEN','VIRUSTOTAL_API_KEY','HYBRID_ANALYSIS_API_KEY']:
                assert not values.get(key) or values[key] not in r.text,'Secret leaked in export'
            (output/'report.json').write_text(json.dumps(report,indent=2))
            status.update(final_status=report['final_status'],engine_states=states,
                          recommendation=report['approval']['recommendation'],
                          workflow_verified=job['status']=='COMPLETED' and states['report']=='COMPLETED',
                          sandbox_verified=all(states.get(k)=='COMPLETED' for k in ['sandbox','behavior','network']))
            if status['sandbox_verified']:
                sb=next(e['data'] for e in report['engines'] if e['name']=='sandbox')
                assert sb['source']=='cuckoo3' and sb['report']['analysis']['submitted']['sha256']==sha
                status['cuckoo_analysis_id']=sb['task_id']
            print(json.dumps(status,indent=2),flush=True)
            return 0 if status['workflow_verified'] and status['sandbox_verified'] else 2
    except Exception as error:
        status['error']=str(error) if isinstance(error,(RuntimeError,AssertionError)) else type(error).__name__
        print('Verification failed:',status['error'],file=sys.stderr)
        return 1
    finally:
        (output/'status.json').write_text(json.dumps(status,indent=2))


if __name__=='__main__':sys.exit(main())
