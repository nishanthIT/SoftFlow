"""Start/stop/status of the existing application as local processes; no containers."""
import json,os,signal,socket,subprocess,sys,time
import fcntl
from pathlib import Path
from dotenv import dotenv_values
root=Path(__file__).resolve().parents[1];local=root/'.local';run=local/'run';logs=local/'logs'
for p in [local,run,logs]:p.mkdir(parents=True,exist_ok=True,mode=0o700)
values={**{k:v for k,v in dotenv_values(root/'.env').items() if v is not None},**os.environ}
values.setdefault('API_PORT','8100');values.setdefault('FRONTEND_PORT','3100')
values['API_INTERNAL_URL']='http://127.0.0.1:'+values['API_PORT']
env={**os.environ,**values,'PYTHONPATH':str(root/'backend'),'PYTHONUNBUFFERED':'1'}
sys.path.insert(0,str(root/'backend'))
py=str(root/'.venv-local/bin/python');statefile=run/'processes.json'
manager_lock=(run/'manager.lock').open('w')
fcntl.flock(manager_lock,fcntl.LOCK_EX)
state=json.loads(statefile.read_text()) if statefile.exists() else {}
def process_stamp(pid):
    return Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19]

def alive(item):
    try:
        if Path(f"/proc/{item['pid']}/stat").read_text().rsplit(')',1)[1].split()[0]=='Z':return False
        if 'starttime' in item:return process_stamp(item['pid'])==item['starttime']
        return Path(f"/proc/{item['pid']}/cmdline").read_bytes().decode().replace('\0',' ').strip()==item['command']
    except OSError:return False

def start(name,args,cwd=root,process_env=None):
    if name in state and alive(state[name]):return
    with (logs/(name+'.log')).open('ab') as output:
        process=subprocess.Popen(args,cwd=cwd,env=process_env or env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
    time.sleep(.2)
    if process.poll() is not None:raise RuntimeError(f'{name} exited; inspect .local/logs/{name}.log')
    command=Path(f'/proc/{process.pid}/cmdline').read_bytes().decode().replace('\0',' ').strip()
    state[name]={'pid':process.pid,'command':command,'starttime':process_stamp(process.pid)};statefile.write_text(json.dumps(state));statefile.chmod(0o600)

def wait_port(port,seconds=60):
    for _ in range(seconds*2):
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=1):return
        except OSError:time.sleep(.5)
    raise RuntimeError(f'Port {port} did not become ready; inspect .local/logs')

def stop():
    for name,item in reversed(list(state.items())):
        if alive(item):
            os.killpg(item['pid'],signal.SIGTERM);print('Stopped',name)
    for _ in range(40):
        if not any(alive(item) for item in state.values()):break
        time.sleep(.25)
    remaining={name:item for name,item in state.items() if alive(item)}
    statefile.write_text(json.dumps(remaining))
    if remaining:raise RuntimeError('Some processes are still stopping; their ownership records were retained. Run stop again after they exit.')

def start_cuckoo():
    if values.get('CUCKOO_AUTO_START','false').lower()!='true':return
    from cuckoo_local import paths,doctor,isolated_env
    from urllib.parse import urlsplit
    import httpx
    try:
        if values.get('SANDBOX_KIND')!='cuckoo3':raise RuntimeError('Managed startup supports SANDBOX_KIND=cuckoo3')
        url=urlsplit(values.get('CUCKOO_API_URL',''))
        if url.scheme!='http' or url.hostname not in ['127.0.0.1','localhost'] or url.path not in ['', '/']:
            raise RuntimeError('Managed Cuckoo requires a loopback HTTP API root. For a remote service set CUCKOO_AUTO_START=false.')
        venv,cwd,_=paths(values)
        prefix=[str(venv/'bin/cuckoo'),'--cwd',str(cwd)]
        cenv=isolated_env();cenv['PATH']=str(venv/'bin')+os.pathsep+cenv.get('PATH','')
        readiness=doctor(values)
        (run/'cuckoo-doctor.json').write_text(json.dumps(readiness,indent=2))
        # Keep the authenticated API available for diagnostics even when the
        # host has no guest. The absence of a core is never called ready.
        if readiness['ready']:start('cuckoo-core',prefix,process_env=cenv)
        start('cuckoo-api',prefix+['api','--host','127.0.0.1','--port',str(url.port or 80)],process_env=cenv)
        deadline=time.monotonic()+int(values.get('CUCKOO_STARTUP_TIMEOUT','60'))
        last_error=None
        while time.monotonic()<deadline:
            if not alive(state['cuckoo-api']):raise RuntimeError('Cuckoo API exited; inspect cuckoo-api.log')
            if readiness['ready'] and not alive(state['cuckoo-core']):raise RuntimeError('Cuckoo core exited; inspect cuckoo-core.log')
            try:
                endpoint='/submit/platforms' if readiness['ready'] else '/analyses/'
                r=httpx.get(values['CUCKOO_API_URL'].rstrip('/')+endpoint,headers={'Authorization':'Token '+values.get('CUCKOO_API_TOKEN','')},timeout=2)
                r.raise_for_status()
                if not readiness['ready']:break
                if values.get('SANDBOX_OS_VERSION','10') in r.json().get('windows',[]):break
            except (httpx.HTTPError,ValueError) as e:last_error=type(e).__name__
            time.sleep(.5)
        else:raise RuntimeError('Cuckoo readiness deadline exceeded ('+str(last_error)+'); inspect Cuckoo logs')
        if not readiness['ready']:
            failed=', '.join(c['check'] for c in readiness['checks'] if not c['ok'])
            raise RuntimeError('Cuckoo execution unavailable: '+failed+'. Details: .local/run/cuckoo-doctor.json')
        print('Cuckoo API authenticated; matching machine advertised. Run verify_sandbox.py to verify execution.')
    except (RuntimeError,OSError) as error:
        print(str(error),file=sys.stderr)
        if values.get('CUCKOO_REQUIRED','false').lower()=='true':raise

if len(sys.argv)>1 and sys.argv[1]=='stop':stop();sys.exit()
if len(sys.argv)>1 and sys.argv[1]=='status':
    for name,item in state.items():print(name, 'RUNNING' if alive(item) else 'STOPPED')
    sys.exit()
try:
    pg=Path(values['POSTGRES_BIN']) if values.get('POSTGRES_BIN') else next((p for p in sorted(Path('/usr/lib/postgresql').glob('*/bin'),key=lambda p:int(p.parent.name),reverse=True) if (p/'initdb').exists()),None)
    if not pg:raise RuntimeError('PostgreSQL binaries not installed. Install postgresql first.')
    pg_port=int(values.get('LOCAL_POSTGRES_PORT','55432'));redis_port=int(values.get('LOCAL_REDIS_PORT','56379'))
    pgdata=local/'postgres';pw=run/'pg-password'
    if not (pgdata/'PG_VERSION').exists():
        pw.write_text(values['POSTGRES_PASSWORD']);pw.chmod(0o600)
        try:
            subprocess.run([str(pg/'initdb'),'-D',str(pgdata),'--username=sentinel','--pwfile='+str(pw),'--auth-host=scram-sha-256','--auth-local=scram-sha-256'],check=True,stdout=(logs/'initdb.log').open('w'))
        finally:pw.unlink(missing_ok=True)
    start('postgres',[str(pg/'postgres'),'-D',str(pgdata),'-h','127.0.0.1','-p',str(pg_port),'-k',str(run)])
    wait_port(pg_port)
    import psycopg
    with psycopg.connect(host='127.0.0.1',port=pg_port,user='sentinel',password=values['POSTGRES_PASSWORD'],dbname='postgres',autocommit=True) as db:
        if not db.execute("SELECT 1 FROM pg_database WHERE datname='sentinel'").fetchone():db.execute('CREATE DATABASE sentinel')
    redisconf=run/'redis.conf'
    redisconf.write_text(f"bind 127.0.0.1\nport {redis_port}\nprotected-mode yes\nrequirepass {values['REDIS_PASSWORD']}\ndir {local}\nappendonly yes\n")
    redisconf.chmod(0o600)
    start('redis',['redis-server',str(redisconf)]);wait_port(redis_port)
    subprocess.run([py,'-m','alembic','upgrade','head'],cwd=root/'backend',env=env,check=True)
    start_cuckoo()
    start('api',[py,'-m','uvicorn','app.main:app','--host','127.0.0.1','--no-proxy-headers','--port',values['API_PORT']]);wait_port(int(values['API_PORT']))
    start('worker',[py,'-m','celery','-A','app.tasks','worker','--loglevel=WARNING','--concurrency=2'])
    start('scheduler',[py,'-m','celery','-A','app.tasks','beat','--loglevel=WARNING','--schedule='+str(run/'celerybeat')])
    start('frontend',['node',str(root/'frontend/node_modules/next/dist/bin/next'),'dev','--hostname',values.get('FRONTEND_HOST','0.0.0.0'),'--port',values['FRONTEND_PORT']],root/'frontend',process_env={**env,'NEXT_DIST_DIR':'.next-dev'})
    wait_port(int(values['FRONTEND_PORT']))
    import httpx
    r=httpx.get('http://127.0.0.1:'+values['API_PORT']+'/health');r.raise_for_status()
    print('SentinelScan: http://localhost:'+values['FRONTEND_PORT'])
    # Verify HTTP through the same proxy that a LAN browser uses.
    r=httpx.get('http://127.0.0.1:'+values['FRONTEND_PORT']+'/api/settings',timeout=60);r.raise_for_status()
    from app.tasks import celery
    deadline=time.monotonic()+30
    while not celery.control.inspect(timeout=1).ping():
        if time.monotonic()>deadline:raise RuntimeError('Worker did not respond to readiness check')
        time.sleep(1)
    for name,item in state.items():
        if name not in ('cuckoo-core',) and not alive(item):raise RuntimeError(name+' exited during startup')
    if values.get('FRONTEND_HOST','0.0.0.0')=='0.0.0.0':
        devices=json.loads(subprocess.check_output(['ip','-j','-4','address','show','up'],text=True))
        for device in devices:
            if device['ifname']=='lo' or device['ifname'].startswith(('docker','br-','ss-')):continue
            for address in device.get('addr_info',[]):
                if address.get('scope')=='global':print('LAN: http://'+address['local']+':'+values['FRONTEND_PORT'])
    print('Application and worker ready. No application login is required.')
    print('Logs: .local/logs/  |  Stop: ./stop.sh')
except Exception as e:
    # Process errors only; connection URLs/passwords never printed.
    print('Local startup failed ('+type(e).__name__+'). See .local/logs/.',file=sys.stderr)
    if isinstance(e,RuntimeError):print(str(e),file=sys.stderr)
    sys.exit(1)
