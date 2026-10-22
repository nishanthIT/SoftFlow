"""Prepare the supported Windows guest from pinned CERT-EE tools and media.

All artifacts remain beneath configured project paths. Never changes HOME.
Network setup is a separate, reviewable privileged script.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import httpx
from cuckoo_local import ROOT, VERSIONS, configuration, path, paths, run, isolated_env, import_vms
from dotenv import set_key


ISO_CHUNK_BYTES = 64 * 1024 * 1024
ISO_SPACE_MARGIN_BYTES = 64 * 1024 * 1024


def guest_paths(values):
    return (path(values,'VMCLOAK_VENV','.local/vmcloak-venv'),
            path(values,'VMCLOAK_CWD','.local/vmcloak'),
            path(values,'VMCLOAK_SOURCE','.local/vmcloak-src'),
            path(values,'CUCKOO_WINDOWS_ISO','.local/media/Win10_1703_English_x64.iso'))


def environment(values):
    venv,cwd,_,_=guest_paths(values)
    env=isolated_env();env['VMCLOAK_CWD']=str(cwd)
    # Prefer the installed system QEMU over Android SDK tools with the same names.
    env['PATH']=str(venv/'bin')+os.pathsep+os.defpath
    env['CUCKOO_BRIDGE_HELPER']=values.get('CUCKOO_BRIDGE_HELPER') or '/usr/local/libexec/sentinelscan/qemu-bridge-helper'
    return env


def vmcloak(values,*args):
    venv,_,_,_=guest_paths(values)
    return run([venv/'bin/vmcloak',*args],env=environment(values))


def install(values):
    venv,cwd,source,_=guest_paths(values);cuckoo_venv,_,_=paths(values)
    if not source.exists():run(['git','clone',VERSIONS['vmcloak_repository'],source])
    revision=run(['git','-C',source,'rev-parse','HEAD'],capture_output=True,text=True).stdout.strip()
    if run(['git','-C',source,'status','--porcelain'],capture_output=True,text=True).stdout:
        raise RuntimeError('VMCloak source contains local changes; refusing an unpinned installation')
    if revision!=VERSIONS['vmcloak_revision']:
        run(['git','-C',source,'fetch','origin',VERSIONS['vmcloak_revision']])
        run(['git','-C',source,'checkout','--detach',VERSIONS['vmcloak_revision']])
    if not (venv/'bin/python').exists():run([cuckoo_venv/'bin/python','-m','venv',venv])
    run([venv/'bin/python','-m','pip','install','-r',ROOT/'sandbox/vmcloak-requirements.lock',source])
    run([venv/'bin/python','-m','pip','check'])
    repair(values)


def repair(values):
    venv,cwd,_,_=guest_paths(values)
    # Upstream has no working-directory option. Make that single path
    # configurable in the installed copy, preserving its upstream default.
    code=r'''from importlib import metadata
from pathlib import Path
p=Path(metadata.distribution('VMCloak').locate_file('vmcloak/repository.py'))
s=p.read_text();old='conf_path = os.path.join(os.getenv("HOME"), ".vmcloak")'
new='conf_path = os.environ.get("VMCLOAK_CWD") or os.path.join(os.getenv("HOME"), ".vmcloak")'
if new not in s:
 if old not in s:raise RuntimeError('Unrecognized VMCloak repository layout')
 p.write_text(s.replace(old,new,1))
p=Path(metadata.distribution('VMCloak').locate_file('vmcloak/platforms/qemu.py'))
s=p.read_text()
old='f"type=bridge,br={attr[\'adapter\']},id=net0"'
if 'CUCKOO_BRIDGE_HELPER' not in s:
 if s.count(old)!=2:raise RuntimeError('Unrecognized VMCloak bridge configuration')
 replacement=old+' + (",helper=" + os.environ["CUCKOO_BRIDGE_HELPER"] if os.environ.get("CUCKOO_BRIDGE_HELPER") else "")'
 p.write_text(s.replace(old,replacement))
'''
    run([venv/'bin/python','-c',code])
    cwd.mkdir(parents=True,exist_ok=True,mode=0o700)
    vmcloak(values,'--help')


def host_plan(values):
    result={'uid':os.getuid(),'interface':values.get('CUCKOO_INTERFACE') or 'ss-cuckoo0',
            'network':values.get('CUCKOO_GUEST_NETWORK') or '192.168.30.0/24',
            'resultserver_ip':values.get('CUCKOO_RESULTSERVER_IP') or '192.168.30.1',
            'resultserver_port':int(values.get('CUCKOO_RESULTSERVER_PORT') or '2042')}
    target=ROOT/'.local/run/cuckoo-host-plan.json';target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,indent=2));print(target.read_text())
    for key,value in {'CUCKOO_INTERFACE':result['interface'],'CUCKOO_RESULTSERVER_IP':result['resultserver_ip'],
                      'CUCKOO_TCPDUMP':'/usr/local/libexec/sentinelscan/tcpdump',
                      'CUCKOO_BRIDGE_HELPER':'/usr/local/libexec/sentinelscan/qemu-bridge-helper'}.items():set_key(ROOT/'.env',key,value)


def checksum(filename):
    sha1=hashlib.sha1();sha256=hashlib.sha256()
    with filename.open('rb') as handle:
        while data:=handle.read(4*1024*1024):sha1.update(data);sha256.update(data)
    return sha1.hexdigest(),sha256.hexdigest()


def require_iso_space(directory, required):
    free = shutil.disk_usage(directory).free
    if free < required:
        raise RuntimeError(
            f'Not enough disk space in {directory}: {free / 1024**3:.2f} GiB free; '
            f'{required / 1024**3:.2f} GiB needed for the remaining download, '
            'assembled ISO, and safety margin. Downloaded fragments are preserved. '
            'Free space on this filesystem and rerun download. '
            'Windows extraction and VM disks need additional space.'
        )


def download(values):
    _,_,_,iso=guest_paths(values)
    expected=VERSIONS['windows_iso_sha1'];url=VERSIONS['windows_iso_url']
    iso.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if iso.exists():
        if checksum(iso)[0]!=expected:raise RuntimeError('Existing ISO does not match the pinned checksum; it was not overwritten')
        print('Windows ISO checksum verified; reusing existing media');return
    with httpx.Client(timeout=30,follow_redirects=True) as client:
        response=client.head(url);response.raise_for_status();length=int(response.headers['content-length'])
        if response.headers.get('accept-ranges')!='bytes':raise RuntimeError('ISO server must support byte ranges for resumable download')
    partdir=iso.with_suffix('.parts');partdir.mkdir(exist_ok=True,mode=0o700)
    temporary=iso.with_suffix('.verified-part')
    # This is only a disposable copy of the fragments, never a verified ISO.
    # Reclaim a previous failed assembly before measuring available space.
    temporary.unlink(missing_ok=True)
    chunk=ISO_CHUNK_BYTES
    count=(length+chunk-1)//chunk
    remaining=0
    for index in range(count):
        part=partdir/str(index)
        existing=part.stat().st_size if part.exists() else 0
        size=min(chunk,length-index*chunk)
        if existing>size:raise RuntimeError('Oversized ISO download fragment')
        remaining+=size-existing
    require_iso_space(iso.parent,remaining+length+ISO_SPACE_MARGIN_BYTES)
    def fetch(index):
        start=index*chunk;end=min(length,start+chunk)-1;part=partdir/str(index)
        existing=part.stat().st_size if part.exists() else 0
        if existing==end-start+1:return
        if existing>end-start+1:raise RuntimeError('Oversized ISO download fragment')
        for attempt in range(4):
            existing=part.stat().st_size if part.exists() else 0
            try:
                with httpx.stream('GET',url,headers={'Range':f'bytes={start+existing}-{end}'},timeout=60,follow_redirects=True) as r:
                    if r.status_code!=206 or r.headers.get('content-range')!=f'bytes {start+existing}-{end}/{length}':
                        raise RuntimeError('Server returned an unexpected ISO byte range')
                    with part.open('ab') as output:
                        for data in r.iter_bytes(1024*1024):output.write(data)
                if part.stat().st_size!=end-start+1:raise RuntimeError('Incomplete ISO fragment')
                return
            except httpx.HTTPError:
                if attempt==3:raise
                time.sleep(2)
    with ThreadPoolExecutor(max_workers=4) as pool:
        for number,_ in enumerate(pool.map(fetch,range(count)),1):
            print(f'Windows ISO: {number}/{count} fragments ready',flush=True)
    # Other processes may have used disk space while the download was running.
    require_iso_space(iso.parent,length+ISO_SPACE_MARGIN_BYTES)
    print('Assembling and verifying Windows ISO; downloaded fragments are retained until verification succeeds',flush=True)
    with temporary.open('wb') as output:
        for index in range(count):
            with (partdir/str(index)).open('rb') as part:shutil.copyfileobj(part,output)
    sha1,sha256=checksum(temporary)
    if sha1!=expected:raise RuntimeError('Downloaded ISO checksum mismatch; guest creation refused')
    temporary.replace(iso)
    iso.with_suffix('.json').write_text(json.dumps({'url':url,'sha1':sha1,'sha256':sha256,'bytes':length},indent=2))
    shutil.rmtree(partdir)
    print('Windows media verified:',sha256,flush=True)


def build(values):
    import socket
    _,cwd,_,iso=guest_paths(values)
    interface=values.get('CUCKOO_INTERFACE') or 'ss-cuckoo0'
    helper=environment(values)['CUCKOO_BRIDGE_HELPER']
    if interface not in {n for _,n in socket.if_nameindex()} or not os.access(helper,os.X_OK):
        raise RuntimeError('Guest host setup is missing. Run sudo python3 scripts/prepare_cuckoo_host.py first.')
    if not os.access('/dev/kvm',os.R_OK|os.W_OK):raise RuntimeError('KVM access is required to build a guest')
    if not iso.is_file() or checksum(iso)[0]!=VERSIONS['windows_iso_sha1']:raise RuntimeError('Download and verify the supported Windows ISO first')
    mount=path(values,'CUCKOO_ISO_MOUNT','.local/media/windows')
    if not (mount/'sources/install.wim').exists() and not (mount/'sources/install.esd').exists():
        mount.mkdir(parents=True,exist_ok=True)
        extractor=shutil.which('7z') or shutil.which('7zz')
        if not extractor:raise RuntimeError('Install 7zip/p7zip-full to extract Windows media without root')
        run([extractor,'x','-y','-o'+str(mount),iso],stdout=subprocess.DEVNULL)
    interface=values.get('CUCKOO_INTERFACE') or 'ss-cuckoo0'
    network=values.get('CUCKOO_GUEST_NETWORK') or '192.168.30.0/24'
    gateway=values.get('CUCKOO_RESULTSERVER_IP') or '192.168.30.1'
    name=values.get('CUCKOO_BASE_VM') or 'sentinel-win10-base'
    snapshot=values.get('CUCKOO_SNAPSHOT_VM') or 'sentinel-win10'
    vmcloak(values,'init','--win10x64','--hddsize',values.get('CUCKOO_DISK_GB') or '64',
            '--cpus',values.get('CUCKOO_CPUS') or '2','--ramsize',values.get('CUCKOO_RAM_MB') or '4096',
            '--network',network,'--gateway',gateway,'--dns',gateway,'--dns2',gateway,
            '--vm','qemu','--ip',values.get('CUCKOO_BUILD_IP') or '192.168.30.2',
            '--iso-mount',str(mount),name,interface)
    # Minimal executable-analysis guest. Snapshot automatically installs the
    # supported Threemon patch and finalizes Windows. Office/browser suites
    # are optional and not required by this application's EXE-only workflow.
    vmcloak(values,'snapshot','--count','1',name,snapshot,values.get('CUCKOO_GUEST_IP') or '192.168.30.10')
    import_vms({**values,'CUCKOO_INTERFACE':interface,'CUCKOO_RESULTSERVER_IP':gateway},cwd/'vms/qemu')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['install','repair','download','build','host-plan'])
    args=parser.parse_args()
    try:globals()[args.command.replace('-','_')](configuration())
    except Exception as error:
        print(f'Guest setup failed: {type(error).__name__}: {error}',file=sys.stderr)
        sys.exit(1)
