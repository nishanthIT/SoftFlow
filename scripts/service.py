"""Unprivileged process recovery and optional systemd user service."""
import argparse
import fcntl
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import shutil
import subprocess
import sys
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

def watch(existing=False):
    from local import alive
    run=ROOT/'.local/run';logs=ROOT/'.local/logs'
    run.mkdir(parents=True,exist_ok=True);logs.mkdir(parents=True,exist_ok=True)
    with (run/'supervisor.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return
        logger=logging.getLogger('supervisor');logger.setLevel(logging.INFO)
        handler=RotatingFileHandler(logs/'supervisor.log',maxBytes=5*1024*1024,backupCount=2)
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'));logger.addHandler(handler)
        if not existing:(run/'stopped').unlink(missing_ok=True)
        last_validation=time.monotonic() if existing else 0
        while not (run/'stopped').exists():
            try:
                path=run/'processes.json'
                state=json.loads(path.read_text()) if path.exists() else {}
                missing=[name for name in REQUIRED if name not in state or not alive(state[name])]
                if missing or time.monotonic()-last_validation>=86400 or last_validation==0:
                    logger.info('Checking services or recovering: %s',', '.join(sorted(missing)) or 'scheduled validation')
                    with (logs/'recovery.log').open('ab') as output:
                        # Manager lock serializes with manual startup and shutdown.
                        configuration=set(dotenv_values(ROOT/'.env'))
                        runtime_env={key:value for key,value in os.environ.items() if key not in configuration}
                        result=subprocess.run([sys.executable,str(ROOT/'scripts/local.py'),'start','--no-supervisor'],cwd=ROOT,env=runtime_env,stdout=output,stderr=subprocess.STDOUT)
                    if result.returncode:logger.error('Recovery failed; retrying in 15 seconds. See recovery.log')
                    else:last_validation=time.monotonic()
                trim_logs(logs)
            except Exception as error:logger.error('Supervisor check failed: %s',type(error).__name__)
            time.sleep(15)

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
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['watch','install'])
    parser.add_argument('--existing',action='store_true');args=parser.parse_args()
    if args.action=='install':install()
    else:watch(args.existing)
