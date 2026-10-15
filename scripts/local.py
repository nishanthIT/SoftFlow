"""Start/stop/status of the existing application as local processes; no containers."""
import json,os,signal,socket,subprocess,sys,time
from pathlib import Path
from dotenv import dotenv_values
root=Path(__file__).resolve().parents[1];local=root/'.local';run=local/'run';logs=local/'logs'
for p in [local,run,logs]:p.mkdir(parents=True,exist_ok=True,mode=0o700)
values={k:v for k,v in dotenv_values(root/'.env').items() if v is not None}
env={**os.environ,**values,'PYTHONPATH':str(root/'backend'),'PYTHONUNBUFFERED':'1'}
py=str(root/'.venv-local/bin/python');statefile=run/'processes.json'
state=json.loads(statefile.read_text()) if statefile.exists() else {}
def process_stamp(pid):
    return Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19]

def alive(item):
    try:
        if 'starttime' in item:return process_stamp(item['pid'])==item['starttime']
        return Path(f"/proc/{item['pid']}/cmdline").read_bytes().decode().replace('\0',' ').strip()==item['command']
    except OSError:return False

def start(name,args,cwd=root):
    if name in state and alive(state[name]):return
    with (logs/(name+'.log')).open('ab') as output:
        process=subprocess.Popen(args,cwd=cwd,env=env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
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
    statefile.write_text('{}')

if len(sys.argv)>1 and sys.argv[1]=='stop':stop();sys.exit()
if len(sys.argv)>1 and sys.argv[1]=='status':
    for name,item in state.items():print(name, 'RUNNING' if alive(item) else 'STOPPED')
    sys.exit()
try:
    pg=next((p for p in sorted(Path('/usr/lib/postgresql').glob('*/bin'),reverse=True) if (p/'initdb').exists()),None)
    if not pg:raise RuntimeError('PostgreSQL binaries not installed. Install postgresql first.')
    pgdata=local/'postgres';pw=run/'pg-password'
    if not (pgdata/'PG_VERSION').exists():
        pw.write_text(values['POSTGRES_PASSWORD']);pw.chmod(0o600)
        try:
            subprocess.run([str(pg/'initdb'),'-D',str(pgdata),'--username=sentinel','--pwfile='+str(pw),'--auth-host=scram-sha-256','--auth-local=scram-sha-256'],check=True,stdout=(logs/'initdb.log').open('w'))
        finally:pw.unlink(missing_ok=True)
    start('postgres',[str(pg/'postgres'),'-D',str(pgdata),'-h','127.0.0.1','-p','55432','-k',str(run)])
    wait_port(55432)
    import psycopg
    with psycopg.connect(host='127.0.0.1',port=55432,user='sentinel',password=values['POSTGRES_PASSWORD'],dbname='postgres',autocommit=True) as db:
        if not db.execute("SELECT 1 FROM pg_database WHERE datname='sentinel'").fetchone():db.execute('CREATE DATABASE sentinel')
    redisconf=run/'redis.conf'
    redisconf.write_text(f"bind 127.0.0.1\nport 56379\nprotected-mode yes\nrequirepass {values['REDIS_PASSWORD']}\ndir {local}\nappendonly yes\n")
    redisconf.chmod(0o600)
    start('redis',['redis-server',str(redisconf)]);wait_port(56379)
    subprocess.run([py,'-m','alembic','upgrade','head'],cwd=root/'backend',env=env,check=True)
    start('api',[py,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',values['API_PORT']]);wait_port(int(values['API_PORT']))
    start('worker',[py,'-m','celery','-A','app.tasks','worker','--loglevel=WARNING','--concurrency=2'])
    start('scheduler',[py,'-m','celery','-A','app.tasks','beat','--loglevel=WARNING','--schedule='+str(run/'celerybeat')])
    start('frontend',['node',str(root/'frontend/node_modules/next/dist/bin/next'),'dev','--hostname','127.0.0.1','--port',values['FRONTEND_PORT']],root/'frontend')
    wait_port(int(values['FRONTEND_PORT']))
    import httpx
    r=httpx.get('http://127.0.0.1:'+values['API_PORT']+'/health');r.raise_for_status()
    print('SentinelScan: http://localhost:'+values['FRONTEND_PORT'])
    print('Health:',r.json());print('Logs: .local/logs/  |  Stop: ./stop.sh')
except Exception as e:
    # Process errors only; connection URLs/passwords never printed.
    print('Local startup failed ('+type(e).__name__+'). See .local/logs/.',file=sys.stderr)
    if isinstance(e,RuntimeError):print(str(e),file=sys.stderr)
    sys.exit(1)
