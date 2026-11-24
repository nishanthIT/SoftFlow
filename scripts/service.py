"""Unprivileged process recovery, PM2 foreground mode, and systemd user service."""
import argparse
from contextlib import contextmanager
import fcntl
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time
from dotenv import dotenv_values

ROOT=Path(__file__).resolve().parents[1]
REQUIRED={'postgres','redis','api','worker','ssl-worker','maintenance','scheduler','frontend'}

def trim_logs(directory,limit=20*1024*1024,keep=5*1024*1024):
    for path in directory.glob('*.log'):
        if path.is_symlink() or not path.is_file() or path.stat().st_size<=limit:continue
        with path.open('r+b') as file:
            file.seek(-keep,os.SEEK_END);tail=file.read()
            file.seek(0);file.write(tail);file.truncate()

def application_environment():
    # PM2 retains the environment from its original launch. Read application keys
    # from the current .env on every start/recovery instead of reusing that cache.
    configuration=set(dotenv_values(ROOT/'.env'))
    return {key:value for key,value in os.environ.items() if key not in configuration}


def run_manager(action, startup_args=(), stop_requested=None, output=None):
    command=[sys.executable,str(ROOT/'scripts/local.py'),action,*startup_args]
    options={'cwd':ROOT,'env':application_environment()}
    if output is not None:options.update(stdout=output,stderr=subprocess.STDOUT)
    if stop_requested is None:
        return subprocess.run(command,**options).returncode
    # Only the startup manager and its build/migration subprocesses share this
    # group. Managed application services start in their own sessions and drain
    # through local.py stop; never let a PM2 signal kill a worker pool or database.
    with subprocess.Popen(command,start_new_session=True,**options) as process:
        while process.poll() is None:
            if stop_requested.wait(.2):
                try:os.killpg(process.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                try:process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    process.wait()
                return 130
        return process.returncode


@contextmanager
def shutdown_signals():
    stopped=threading.Event()
    previous={sig:signal.getsignal(sig) for sig in (signal.SIGINT,signal.SIGTERM)}
    for sig in previous:signal.signal(sig,lambda *_:stopped.set())
    try:yield stopped
    finally:
        for sig,handler in previous.items():signal.signal(sig,handler)


def watch(existing=False, startup_args=(), stop_requested=None):
    if stop_requested is not None:return _watch(existing,startup_args,stop_requested)
    with shutdown_signals() as stopped:return _watch(existing,startup_args,stopped)


def _watch(existing, startup_args, stop_requested):
    from local import alive
    run=ROOT/'.local/run';logs=ROOT/'.local/logs'
    run.mkdir(parents=True,exist_ok=True);logs.mkdir(parents=True,exist_ok=True)
    with (run/'supervisor.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('Another application supervisor is already running')
        logger=logging.getLogger('supervisor');logger.setLevel(logging.INFO)
        handler=RotatingFileHandler(logs/'supervisor.log',maxBytes=5*1024*1024,backupCount=2)
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'));logger.addHandler(handler)
        if not existing:(run/'stopped').unlink(missing_ok=True)
        last_validation=time.monotonic() if existing else 0
        retry_delay=15
        while not stop_requested.is_set() and not (run/'stopped').exists():
            failed=False
            try:
                path=run/'processes.json'
                state=json.loads(path.read_text()) if path.exists() else {}
                missing=[name for name in REQUIRED if name not in state or not alive(state[name])]
                if missing or time.monotonic()-last_validation>=86400 or last_validation==0:
                    logger.info('Checking services or recovering: %s',', '.join(sorted(missing)) or 'scheduled validation')
                    with (logs/'recovery.log').open('ab') as output:
                        # Manager lock serializes with manual startup and shutdown.
                        code=run_manager('start',('--no-supervisor',*startup_args),stop_requested,output)
                    if stop_requested.is_set():break
                    if code:
                        failed=True
                        logger.error('Recovery failed; retrying in %s seconds. See recovery.log',retry_delay)
                    else:last_validation=time.monotonic();retry_delay=15
                trim_logs(logs)
            except Exception as error:
                failed=True
                logger.error('Supervisor check failed: %s',type(error).__name__)
            stop_requested.wait(retry_delay)
            if failed:retry_delay=min(retry_delay*2,300)
            else:retry_delay=15


def foreground(startup_args=()):
    """Long-lived PM2 entry point, with one owner and graceful stop/restart."""
    run=ROOT/'.local/run';run.mkdir(parents=True,exist_ok=True)
    with shutdown_signals() as stopped:
        with (run/'foreground.lock').open('a') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise RuntimeError('A foreground application supervisor is already running')
            code=run_manager('start',('--foreground-start',*startup_args),stopped)
            if not code and not stopped.is_set():
                print('[PM2] Application ready; foreground supervisor is running',flush=True)
                watch(existing=True,startup_args=startup_args,stop_requested=stopped)
            if stopped.is_set():
                print('[PM2] Draining managed application services before exit',flush=True)
                return run_manager('stop')
            return code

def install():
    node=shutil.which('node')
    if not node:raise RuntimeError('Node.js is missing; run npm start to prepare the application first')
    # User services do not load the terminal's Node version manager. Use the
    # same Node/npm pair as installation so recovery reuses the current release.
    runtime_path=str(Path(node).parent)+':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    target=Path.home()/'.config/systemd/user/sentinelscan.service'
    target.parent.mkdir(parents=True,exist_ok=True)
    # Exec arguments accept quotes; WorkingDirectory is a raw path directive.
    quote=lambda value:json.dumps(value.replace('%','%%'))
    target.write_text(f'''[Unit]
Description=SentinelScan production workspace and recovery supervisor
After=network-online.target

[Service]
Type=simple
WorkingDirectory={str(ROOT).replace('%','%%')}
Environment={quote('PATH='+runtime_path)}
ExecStart={quote(sys.executable)} {quote(str(ROOT/'scripts/service.py'))} watch
ExecStop={quote(sys.executable)} {quote(str(ROOT/'scripts/local.py'))} stop
Restart=on-failure
RestartSec=10
TimeoutStopSec=7200
KillMode=process
UMask=0077

[Install]
WantedBy=default.target
''')
    subprocess.run(['systemd-analyze','--user','verify',str(target)],check=True)
    subprocess.run([sys.executable,str(ROOT/'scripts/local.py'),'stop'],cwd=ROOT,check=True)
    subprocess.run(['systemctl','--user','daemon-reload'],check=True)
    subprocess.run(['systemctl','--user','enable','sentinelscan.service'],check=True)
    subprocess.run(['systemctl','--user','restart','sentinelscan.service'],check=True)
    print('Installed user service. Status: systemctl --user status sentinelscan')
    print('For startup before login and after logout, an administrator must enable user lingering.')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['watch','install','run'])
    parser.add_argument('--existing',action='store_true')
    parser.add_argument('--foreground',action='store_true')
    for flag in ('presentation','dev','allow-degraded'):parser.add_argument('--'+flag,action='store_true')
    args=parser.parse_args()
    startup_args=tuple('--'+flag for flag in ('presentation','dev','allow-degraded') if getattr(args,flag.replace('-','_')))
    try:
        if args.action=='install':install()
        elif args.action=='run':sys.exit(foreground(startup_args))
        else:watch(args.existing,startup_args)
    except (RuntimeError,OSError) as error:
        print('[ERROR] '+str(error),file=sys.stderr);sys.exit(1)
