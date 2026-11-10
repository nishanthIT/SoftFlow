"""Start/stop/status of the existing application as local processes; no containers."""
import hashlib,json,os,signal,socket,subprocess,sys,time
import fcntl
from pathlib import Path
from dotenv import dotenv_values
root=Path(__file__).resolve().parents[1];local=root/'.local';run=local/'run';logs=local/'logs'
state={};values={};env={}
py=str(root/'.venv-local/bin/python');statefile=run/'processes.json'
manager_lock=None
APP_SERVICES={'frontend','api','worker','ssl-worker','maintenance','scheduler'}

def runtime_signature():
    digest=hashlib.sha256()
    for path in sorted((root/'backend/app').glob('*.py')):
        digest.update(path.name.encode());digest.update(path.read_bytes())
    digest.update((root/'backend/requirements.txt').read_bytes())
    digest.update(values.get('PRESENTATION_MODE','false').encode())
    keys=set(dotenv_values(root/'.env'))|{'APP_ENV','PRESENTATION_MODE','SANDBOX_ENABLED','FRONTEND_RELEASE','API_INTERNAL_URL','API_PORT','FRONTEND_PORT','FRONTEND_HOST'}
    digest.update(json.dumps({key:values.get(key) for key in sorted(keys)},sort_keys=True).encode())
    digest.update(Path(__file__).read_bytes())
    digest.update((root/'scripts/production.py').read_bytes())
    digest.update((root/'scripts/service.py').read_bytes())
    return digest.hexdigest()

def configure_mode(presentation=False,development=False):
    values['PRESENTATION_MODE']='true' if presentation else 'false'
    values['APP_ENV']='development' if development else 'production'
    if presentation:
        values.update(CUCKOO_REQUIRED='false',CUCKOO_AUTO_START='false',SANDBOX_ENABLED='false')
    if values.get('SANDBOX_ENABLED','true').lower()=='false':
        values.update(CUCKOO_REQUIRED='false',CUCKOO_AUTO_START='false')
    env.update(values)

def initialize(*,nonblocking=False):
    global values,env,state,manager_lock
    for p in [local,run,logs]:p.mkdir(parents=True,exist_ok=True,mode=0o700)
    values={**{k:v for k,v in dotenv_values(root/'.env').items() if v is not None},**os.environ}
    values.setdefault('API_PORT','8100');values.setdefault('FRONTEND_PORT','3100')
    values['API_INTERNAL_URL']='http://127.0.0.1:'+values['API_PORT']
    env={**os.environ,**values,'PYTHONPATH':str(root/'backend'),'PYTHONUNBUFFERED':'1'}
    sys.path.insert(0,str(root/'backend'))
    manager_lock=(run/'manager.lock').open('w')
    try:fcntl.flock(manager_lock,fcntl.LOCK_EX|(fcntl.LOCK_NB if nonblocking else 0))
    except BlockingIOError:
        manager_lock.close();raise
    state=json.loads(statefile.read_text()) if statefile.exists() else {}


def message(category,detail):
    line=f'[{category}] {detail}'
    print(line,flush=True)
    with (logs/'startup.log').open('a') as output:output.write(time.strftime('%Y-%m-%dT%H:%M:%S%z')+' '+line+'\n')
    if category in ('RECOVERY','ERROR'):
        with (logs/'recovery.log').open('a') as output:output.write(line+'\n')


def process_stamp(pid):
    return Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19]

def alive(item):
    try:
        if Path(f"/proc/{item['pid']}/stat").read_text().rsplit(')',1)[1].split()[0]=='Z':return False
        if 'starttime' in item:return process_stamp(item['pid'])==item['starttime']
        return Path(f"/proc/{item['pid']}/cmdline").read_bytes().decode().replace('\0',' ').strip()==item['command']
    except OSError:return False

def start(name,args,cwd=root,process_env=None):
    if name in state and alive(state[name]):
        message('STARTUP','Reusing managed '+name+' process');return
    if name in state:message('RECOVERY','Replacing stopped '+name+' process; old PID ownership checked')
    for attempt in range(2):
        with (logs/(name+'.log')).open('ab') as output:
            process=subprocess.Popen(args,cwd=cwd,env=process_env or env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
        time.sleep(.3)
        if process.poll() is not None:
            if attempt==0:
                message('RECOVERY',name+' exited during launch; retrying once after 1 second');time.sleep(1);continue
            raise RuntimeError(f'{name} exited twice; inspect .local/logs/{name}.log')
        command=Path(f'/proc/{process.pid}/cmdline').read_bytes().decode().replace('\0',' ').strip()
        state[name]={'pid':process.pid,'command':command,'starttime':process_stamp(process.pid)}
        if name in APP_SERVICES or name=='supervisor':state[name]['runtime_signature']=runtime_signature()
        statefile.write_text(json.dumps(state));statefile.chmod(0o600)
        return

def wait_port(port,seconds=60):
    for _ in range(seconds*2):
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=1):return
        except OSError:time.sleep(.5)
    raise RuntimeError(f'Port {port} did not become ready; inspect .local/logs')

def save_running_state():
    remaining={name:item for name,item in state.items() if alive(item)}
    temporary=statefile.with_suffix('.tmp')
    temporary.write_text(json.dumps(remaining));temporary.chmod(0o600)
    os.replace(temporary,statefile)
    state.clear();state.update(remaining)


def stop_services(names,timeout):
    selected={name:state[name] for name in names if name in state and alive(state[name])}
    for name,item in selected.items():
        message('STOP','Stopping '+name+' (PID '+str(item['pid'])+')')
        try:
            # TERM only the Celery parent: it drains active work and closes its
            # pool itself. Signalling the whole group also terminates task children.
            # PostgreSQL INT requests a clean fast shutdown, including checkpoint;
            # TERM is smart shutdown and waits indefinitely for idle clients.
            if name in ('worker','ssl-worker','maintenance','postgres'):
                os.kill(item['pid'],signal.SIGINT if name=='postgres' else signal.SIGTERM)
            else:os.killpg(item['pid'],signal.SIGTERM)
        except ProcessLookupError:pass
    deadline=time.monotonic()+timeout;next_notice=time.monotonic()+5
    while pending:={name:item for name,item in selected.items() if alive(item)}:
        if time.monotonic()>=deadline:
            detail=', '.join(name+' (PID '+str(item['pid'])+')' for name,item in pending.items())
            raise RuntimeError(f'Shutdown timed out after {timeout:g}s waiting for {detail}. '
                'Remaining services and their dependencies were left running; ownership records were retained. '
                'Inspect their .local/logs/ files and retry npm stop after active work finishes.')
        if time.monotonic()>=next_notice:
            message('STOP','Waiting for '+', '.join(pending)+' to exit; dependencies are still available')
            next_notice=time.monotonic()+5
        time.sleep(.25)
    for name in selected:message('OK',name+' stopped')
    save_running_state()


def stop():
    try:timeout=float(values.get('LOCAL_SHUTDOWN_TIMEOUT','120'))
    except ValueError:raise RuntimeError('LOCAL_SHUTDOWN_TIMEOUT must be a number of seconds')
    if not 1<=timeout<=7200:raise RuntimeError('LOCAL_SHUTDOWN_TIMEOUT must be between 1 and 7200 seconds')
    known={'proxy','frontend','scheduler','api','worker','ssl-worker','maintenance','cuckoo-api','cuckoo-core','redis','postgres'}
    phases=[['proxy','frontend','scheduler','api'],['worker','ssl-worker','maintenance'],['cuckoo-api','cuckoo-core'],
            [name for name in state if name not in known],['redis'],['postgres']]
    try:
        # Keep sandbox, broker and DB alive until consumers have really exited.
        # A timeout aborts subsequent phases without forcing running tasks to die.
        for names in phases:stop_services(names,timeout)
        message('OK','All managed services stopped')
    finally:save_running_state()

def start_cuckoo(bootstrap=False):
    if values.get('CUCKOO_AUTO_START','false').lower()!='true':
        message('CUCKOO','Using configured external sandbox; readiness will be checked through the application API');return
    message('CUCKOO','Checking pinned installation, virtualization, capture and guest prerequisites')
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
        can_start=readiness['prerequisites_ready'] if bootstrap else readiness['ready']
        # Keep the authenticated API available for diagnostics even when the
        # host has no guest. The absence of a core is never called ready.
        if can_start:start('cuckoo-core',prefix,process_env=cenv)
        start('cuckoo-api',prefix+['api','--host','127.0.0.1','--port',str(url.port or 80)],process_env=cenv)
        deadline=time.monotonic()+int(values.get('CUCKOO_STARTUP_TIMEOUT','60'))
        last_error=None
        while time.monotonic()<deadline:
            if not alive(state['cuckoo-api']):raise RuntimeError('Cuckoo API exited; inspect cuckoo-api.log')
            if can_start and not alive(state['cuckoo-core']):raise RuntimeError('Cuckoo core exited; inspect cuckoo-core.log')
            try:
                endpoint='/submit/platforms' if can_start else '/analyses/'
                r=httpx.get(values['CUCKOO_API_URL'].rstrip('/')+endpoint,headers={'Authorization':'Token '+values.get('CUCKOO_API_TOKEN','')},timeout=2)
                r.raise_for_status()
                if not can_start:break
                if values.get('SANDBOX_OS_VERSION','10') in r.json().get('windows',[]):break
            except (httpx.HTTPError,ValueError) as e:last_error=type(e).__name__
            time.sleep(.5)
        else:raise RuntimeError('Cuckoo readiness deadline exceeded ('+str(last_error)+'); inspect Cuckoo logs')
        if not can_start:
            failed=', '.join(c['check'] for c in readiness['checks'] if not c['ok'] and (not bootstrap or c['check']!='isolation'))
            raise RuntimeError('Cuckoo execution unavailable: '+failed+'. Run npm run setup. Details: .local/run/cuckoo-doctor.json')
        message('OK','Cuckoo API authenticated and matching Windows machine advertised')
        message('NETWORK','Capture prerequisites passed; live traffic still requires a completed smoke test')
        message('BEHAVIOR','Guest monitor installed; guest execution and snapshot restoration require live verification')
        return readiness
    except (RuntimeError,OSError) as error:
        message('ERROR',str(error))
        if bootstrap or values.get('CUCKOO_REQUIRED','true').lower()=='true':raise
        message('DEGRADED','Explicit partial mode: sandbox, behavioral and network coverage are unavailable')

def main():
    try:initialize(nonblocking='cache-gc' in sys.argv[1:])
    except BlockingIOError:
        # A stopping maintenance worker may already be waiting for its cache
        # subprocess. Never wait for the stop manager's lock from that child.
        print('[RETENTION] Cache cleanup deferred: startup/shutdown manager is busy.',flush=True)
        return 2
    if 'stop' in sys.argv[1:]:
        (run/'stopped').touch()
        try:stop();return 0
        except (RuntimeError,OSError) as error:
            message('ERROR',str(error));return 1
    if 'cache-gc' in sys.argv[1:]:
        from cuckoo_cache import managed
        try:message('RETENTION',json.dumps(managed(sys.modules[__name__])));return 0
        except Exception as error:
            message('ERROR','Cuckoo cache cleanup deferred ('+type(error).__name__+')');return 2
    if 'status' in sys.argv[1:]:
        for name,item in state.items():print(name, 'RUNNING' if alive(item) else 'STOPPED')
        return 0
    if '--allow-degraded' in sys.argv:values['CUCKOO_REQUIRED']='false'
    presentation='--presentation' in sys.argv
    development='--dev' in sys.argv
    configure_mode(presentation,development)
    if '--bootstrap-sandbox' in sys.argv:
        start_cuckoo(bootstrap=True);return 0
    try:
        if '--no-supervisor' in sys.argv and (run/'stopped').exists():return 0
        message('STARTUP','Checking Linux environment and configured local dependencies')
        server=None
        if not development:
            from production import frontend_release
            server,signature=frontend_release(values)
            values['FRONTEND_RELEASE']=signature
            env.update(values)
        if '--no-supervisor' not in sys.argv and 'supervisor' in state and alive(state['supervisor']) and state['supervisor'].get('runtime_signature')!=runtime_signature():
            stop_services(['supervisor'],30)
        if any(name in APP_SERVICES and alive(item) and item.get('runtime_signature')!=runtime_signature() for name,item in state.items()):
            message('APP','Code or runtime mode changed; draining managed application services before restart')
            stop_services(['proxy','frontend','scheduler','api'],120)
            stop_services(['worker','ssl-worker','maintenance'],120)
        if not sys.platform.startswith('linux'):raise RuntimeError('Managed local startup requires Linux; use the documented container deployment elsewhere')
        if not (root/'.env').is_file():raise RuntimeError('Configuration is missing. Run npm run setup.')
        for binary in ['redis-server','node','ip']:
            import shutil
            if not shutil.which(binary):raise RuntimeError('Missing '+binary+'. Run npm run setup.')
        message('OK','Linux host commands and application configuration detected')
        message('DATABASE','Starting private PostgreSQL and Redis services')
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
        # Redis otherwise inherits the terminal locale, which IDE terminals may set
        # to an uninstalled locale (for example en_US.UTF-8 on an en_IN host).
        # Celery's broker uses no language-sensitive sorting; C is always available.
        redisconf.write_text(f"bind 127.0.0.1\nport {redis_port}\nprotected-mode yes\nlocale-collate C\nrequirepass {values['REDIS_PASSWORD']}\ndir {local}\nappendonly yes\n")
        redisconf.chmod(0o600)
        start('redis',['redis-server',str(redisconf)]);wait_port(redis_port)
        from redis import Redis
        if not Redis.from_url(values['REDIS_URL'],socket_connect_timeout=5,socket_timeout=5).ping():raise RuntimeError('Redis authentication/readiness failed')
        message('OK','PostgreSQL authenticated and Redis PING succeeded')
        message('DATABASE','Applying pending schema migrations')
        subprocess.run([py,'-m','alembic','upgrade','head'],cwd=root/'backend',env=env,check=True)
        if values.get('SANDBOX_ENABLED','true').lower()=='false':
            message('SANDBOX','Disabled by configuration. Static analysis and reports are available; runtime coverage remains explicitly unavailable.')
        else:start_cuckoo()
        message('APP','Starting backend, analysis worker, maintenance worker and retention scheduler')
        start('api',[py,'-m','uvicorn','app.main:app','--host','127.0.0.1','--no-proxy-headers','--port',values['API_PORT']]);wait_port(int(values['API_PORT']))
        start('worker',[py,'-m','celery','-A','app.tasks','worker','--loglevel=WARNING','--concurrency=2','--max-tasks-per-child=20'])
        start('ssl-worker',[py,'-m','celery','-A','app.tasks','worker','--hostname=ssl@%h','--queues=ssl','--loglevel=INFO','--concurrency=1','--max-tasks-per-child=20'])
        start('maintenance',[py,'-m','celery','-A','app.tasks','worker','--hostname=maintenance@%h','--queues=maintenance','--loglevel=INFO','--concurrency=1','--max-tasks-per-child=20'])
        start('scheduler',[py,'-m','celery','-A','app.tasks','beat','--loglevel=WARNING','--schedule='+str(run/'celerybeat')])
        if development:
            start('frontend',['node',str(root/'frontend/node_modules/next/dist/bin/next'),'dev','--hostname',values.get('FRONTEND_HOST','0.0.0.0'),'--port',values['FRONTEND_PORT']],root/'frontend',process_env={**env,'NEXT_DIST_DIR':'.next-dev'})
        else:
            start('frontend',['node',str(server)],server.parent,process_env={**env,'NODE_ENV':'production','HOSTNAME':values.get('FRONTEND_HOST','0.0.0.0'),'PORT':values['FRONTEND_PORT']})
        wait_port(int(values['FRONTEND_PORT']))
        import httpx
        r=httpx.get('http://127.0.0.1:'+values['API_PORT']+'/health');r.raise_for_status()
        message('OK','Backend health endpoint responded')
        # Check provider readiness with backend-only integration credentials.
        from app.config import settings
        settings.presentation_mode=presentation
        settings.sandbox_enabled=values.get('SANDBOX_ENABLED','true').lower()=='true'
        from app.provider_status import check
        sandbox=check('sandbox')
        if values.get('CUCKOO_REQUIRED','true').lower()=='true' and not sandbox.get('execution_ready'):
            raise RuntimeError('Sandbox execution health failed: '+str(sandbox.get('status','UNKNOWN'))+'. Inspect /api/providers/health and run npm run setup.')
        message('VULNERABILITY','Intelligence lookups are checked per analysis; provider network failures remain visible in partial reports')
        # Verify the same frontend/API route that a LAN browser uses.
        scheme='http'
        r=httpx.get(scheme+'://127.0.0.1:'+values['FRONTEND_PORT']+'/api/settings',timeout=60);r.raise_for_status()
        from app.tasks import celery
        deadline=time.monotonic()+30
        while True:
            queues=celery.control.inspect(timeout=1).active_queues() or {}
            if {'celery','ssl','maintenance'} <= {q['name'] for worker in queues.values() for q in worker}:break
            if time.monotonic()>deadline:raise RuntimeError('Analysis and maintenance workers did not respond to readiness check')
            time.sleep(1)
        for name,item in state.items():
            if name=='supervisor':continue
            if name not in (('cuckoo-core','cuckoo-api') if not settings.sandbox_enabled else ('cuckoo-core',)) and not alive(item):raise RuntimeError(name+' exited during startup')
        if values.get('FRONTEND_HOST','0.0.0.0')=='0.0.0.0':
            devices=json.loads(subprocess.check_output(['ip','-j','-4','address','show','up'],text=True))
            for device in devices:
                if device['ifname']=='lo' or device['ifname'].startswith(('docker','br-','ss-')):continue
                for address in device.get('addr_info',[]):
                    if address.get('scope')=='global':print('LAN: '+scheme+'://'+address['local']+':'+values['FRONTEND_PORT'])
        message('OK','Frontend proxy and analysis/maintenance queues responded')
        message('APP','SentinelScan: '+scheme+'://localhost:'+values['FRONTEND_PORT'])
        message('OK','Retention scheduler running: 7 days; daily sweep, hourly temporary cleanup, minute expiration checks')
        message('STARTUP','Logs: .local/logs/ | Stop: npm stop')
        if not development:
            from production import prune_releases
            prune_releases(values['FRONTEND_RELEASE'])
        (run/'stopped').unlink(missing_ok=True)
        if not development and '--no-supervisor' not in sys.argv:
            with (run/'supervisor.lock').open('a') as supervisor_lock:
                try:fcntl.flock(supervisor_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:message('OK','Existing production supervisor is active')
                else:
                    fcntl.flock(supervisor_lock,fcntl.LOCK_UN)
                    start('supervisor',[py,str(root/'scripts/service.py'),'watch','--existing'])
        return 0
    except Exception as e:
        # Process errors only; connection URLs/passwords never printed.
        message('ERROR','Local startup failed ('+type(e).__name__+'). See .local/logs/.')
        if isinstance(e,RuntimeError):message('DIAGNOSIS',str(e))
        return 1


if __name__=='__main__':sys.exit(main())
