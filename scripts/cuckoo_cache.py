"""Collect old Cuckoo 3 binary cache only while its managed writers are stopped.

The API deletes analysis directories but leaves its shared binary cache. Symlink
counts cannot prove ownership. Inventory both SQLite targets and every remaining
analysis document before deleting any unreferenced cache entry.
"""
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import time

FINISHED={'finished','fatal_error','no_selected'}


def inventory(cwd):
    if any((cwd/name).is_symlink() for name in ('storage','storage/analyses','storage/binaries','cuckoo.db')):
        raise RuntimeError('Shared or linked Cuckoo storage requires its own retention manager')
    with sqlite3.connect((cwd/'cuckoo.db').as_uri()+'?mode=ro',uri=True) as db:
        rows=db.execute('SELECT id,state FROM analyses').fetchall()
        if any(state not in FINISHED for _,state in rows):raise RuntimeError('Cuckoo has unfinished analyses; binary cache cleanup deferred')
        if db.execute("SELECT id FROM tasks WHERE state NOT IN ('reported','fatal_error') LIMIT 1").fetchone():
            raise RuntimeError('Cuckoo has unfinished execution tasks; cache cleanup deferred')
        protected={row[0] for row in db.execute('SELECT sha256 FROM targets WHERE sha256 IS NOT NULL')}
    folders=list((cwd/'storage/analyses').glob('*/*'))
    if any(folder.is_symlink() or not (folder/'analysis.json').is_file() for folder in folders):
        raise RuntimeError('Incomplete or linked analysis directory; cache cleanup deferred')
    documents=[folder/'analysis.json' for folder in folders]
    found=set()
    def hashes(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if key=='sha256' and isinstance(item,str):protected.add(item.lower())
                else:hashes(item)
        elif isinstance(value,list):
            for item in value:hashes(item)
    for file in documents:
        if file.is_symlink():raise RuntimeError('Unexpected analysis document symlink; cache inventory refused')
        payload=json.loads(file.read_text());found.add(payload['id']);hashes(payload)
        binary=file.parent/'binary'
        if binary.is_symlink():
            target=binary.resolve();base=(cwd/'storage/binaries').resolve()
            if not target.is_relative_to(base):raise RuntimeError('Submitted binary points outside its cache')
            protected.add(target.name)
    if not {identifier for identifier,_ in rows}<=found:raise RuntimeError('Analysis documents are missing; cannot prove cache ownership')
    return protected


def prune(cwd,at=None):
    protected=inventory(cwd);cutoff=(at or time.time())-168*3600
    base=cwd/'storage/binaries';removed=0;freed=0
    # Only the pinned SHA-256 layout; leave unknown namespaces alone.
    for path in base.glob('*/*/*'):
        if path.is_symlink() or path.parent.is_symlink() or path.parent.parent.is_symlink():raise RuntimeError('Unexpected binary cache symlink')
        sha=path.name
        if not path.is_file() or not re.fullmatch(r'[a-f0-9]{64}',sha):continue
        if path.parent.name!=sha[1] or path.parent.parent.name!=sha[0]:continue
        stat=path.stat()
        if sha in protected or stat.st_mtime>cutoff:continue
        path.unlink();removed+=1;freed+=stat.st_size
        for parent in (path.parent,path.parent.parent):
            try:parent.rmdir()
            except OSError:break
    return {'deleted':removed,'bytes_freed':freed}


def managed(manager):
    if manager.values.get('CUCKOO_AUTO_START','false').lower()!='true':return {'skipped':'external sandbox owns its shared cache'}
    from cuckoo_local import paths,isolated_env
    _,cwd,_=paths(manager.values);cwd=cwd.resolve()
    if not (cwd/'cuckoo.db').is_file():return {'skipped':'Cuckoo database does not exist'}
    inventory(cwd) # Do not interrupt an executing guest or scheduler task.
    names=[name for name in ('cuckoo-api','cuckoo-core') if name in manager.state and manager.alive(manager.state[name])]
    groups={manager.state[name]['pid'] for name in names}
    def unmanaged_writers():
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit():continue
            try:
                args=(entry/'cmdline').read_bytes().split(b'\0')
                if any(Path(os.fsdecode(arg)).name in ('cuckoo','qemu-system-x86_64','qemu-system-i386') for arg in args):
                    if os.getpgid(int(entry.name)) not in groups:return True
            except (FileNotFoundError,PermissionError,ProcessLookupError):continue
        return False
    if unmanaged_writers():raise RuntimeError('Unmanaged sandbox or guest process exists; cache cleanup deferred')
    # Persisted argv are not executable authority: reconstruct known commands.
    from urllib.parse import urlsplit
    url=urlsplit(manager.values.get('CUCKOO_API_URL',''))
    if url.scheme!='http' or url.hostname not in ('127.0.0.1','localhost') or url.path not in ('','/'):
        raise RuntimeError('Cache cleanup requires the managed private Cuckoo API')
    venv,_,_=paths(manager.values);prefix=[str(venv/'bin/cuckoo'),'--cwd',str(cwd)]
    cenv=isolated_env();cenv['PATH']=str(venv/'bin')+os.pathsep+cenv.get('PATH','')
    try:
        for name in names:os.killpg(manager.state[name]['pid'],signal.SIGTERM)
        deadline=time.monotonic()+30
        while any(manager.alive(manager.state[name]) for name in names):
            if time.monotonic()>deadline:raise RuntimeError('Sandbox did not stop; cache cleanup deferred')
            time.sleep(.2)
        if unmanaged_writers():raise RuntimeError('Sandbox writers appeared during cleanup; deletion refused')
        return prune(cwd)
    finally:
        for name in reversed(names):
            args=prefix if name=='cuckoo-core' else prefix+['api','--host','127.0.0.1','--port',str(urlsplit(manager.values['CUCKOO_API_URL']).port or 80)]
            manager.start(name,args,process_env=cenv)
        if 'cuckoo-api' in names:
            import httpx
            deadline=time.monotonic()+15
            while True:
                try:
                    response=httpx.get(manager.values['CUCKOO_API_URL'].rstrip('/')+'/analyses/',
                        headers={'Authorization':'Token '+manager.values.get('CUCKOO_API_TOKEN','')},timeout=2)
                    response.raise_for_status();break
                except httpx.HTTPError:
                    if time.monotonic()>deadline:raise RuntimeError('Cuckoo API did not recover after cache maintenance')
                    time.sleep(.5)
