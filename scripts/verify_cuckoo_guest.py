"""Verify snapshot restoration using only a harmless guest file marker.

Run by provision.py in the pinned Cuckoo environment, after fresh privileged
host verification. Uses the same QEMU restore/stop implementation as Cuckoo.
It never submits user files, changes a snapshot, or writes app credentials.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
import fcntl


def owned_alive(item):
    try:
        fields=Path(f"/proc/{item['pid']}/stat").read_text().rsplit(')',1)[1].split()
        return fields[0]!='Z' and fields[19]==item.get('starttime')
    except (OSError,KeyError):return False


def check_idle():
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():continue
        try:
            args=(entry/'cmdline').read_bytes().split(b'\0')
            if args and Path(os.fsdecode(args[0])).name.startswith('qemu-system'):
                raise RuntimeError('A QEMU guest is running. Stop sandbox analyses and the managed application before provisioning or restoration verification.')
            if any(os.fsdecode(arg).endswith('/bin/cuckoo') or arg==b'cuckoo' for arg in args):
                raise RuntimeError('A Cuckoo service is running. Guest verification requires its writers to be stopped.')
        except (FileNotFoundError,PermissionError,ProcessLookupError):continue


def digest(path):
    value=hashlib.sha256()
    with path.open('rb') as stream:
        while data:=stream.read(4*1024*1024):value.update(data)
    return value.hexdigest()


def wait_agent(session,base,machinery,machine,timeout=180):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        state=machinery.state(machine)
        if state=='paused':machinery.handle_paused(machine)
        if state=='poweroff':raise RuntimeError('Verification guest exited before its agent became ready')
        try:
            response=session.get(base+'/',timeout=2)
            if response.status_code==200 and isinstance(response.json(),dict):return
        except Exception:pass
        time.sleep(1)
    raise RuntimeError('Verification guest agent did not respond within 180 seconds')


def marker_present(session,base,marker):
    # Fixed built-in Windows command. The only interpolation is a locally
    # generated UUID filename; no uploaded bytes or caller commands execute.
    command=f'cmd.exe /c if exist {marker} (echo PRESENT) else (echo ABSENT)'
    result=session.post(base+'/execute',data={'command':command},timeout=30)
    result.raise_for_status();data=result.json()
    if data.get('exit_code')!=0 or data.get('stdout','').strip() not in ('PRESENT','ABSENT'):
        raise RuntimeError('Guest agent could not prove whether the harmless marker exists')
    return data['stdout'].strip()=='PRESENT'


def verify(cwd,plan,output):
    import requests
    import yaml
    from cuckoo.machineries.modules.qemu import QEMU,_QEMUMachine,_read_start_args
    check_idle()
    config=yaml.safe_load((cwd/'conf/machineries/qemu.yaml').read_text())
    if not config.get('machines'):raise RuntimeError('No registered QEMU guest exists')
    network=ipaddress.ip_network(plan['network'])
    proof={'verified':False,'host_plan':plan,'machines':[],'test':'same snapshot restored twice; marker written on first boot absent on second'}
    output.parent.mkdir(parents=True,exist_ok=True)
    try:
        for name,values in config['machines'].items():
            if ipaddress.ip_address(values['ip']) not in network or values['ip']==plan['resultserver_ip']:
                raise RuntimeError('Guest IP is outside the verified isolated network')
            if values.get('interface',config.get('interface'))!=plan['interface']:
                raise RuntimeError('Guest interface differs from the verified isolated bridge')
            machineinfo=Path(values['machineinfo_path'])
            start_args=_read_start_args(machineinfo)
            # QEMU incoming decompression is implemented by upstream through a
            # shell; require plain paths rather than permitting shell expansion.
            import re
            for field in ['qcow2_path','snapshot_path','machineinfo_path']:
                if not re.fullmatch(r'[A-Za-z0-9_./-]+',str(Path(values[field]).resolve())):
                    raise RuntimeError('Pinned QEMU requires shell-safe VM paths (letters, digits, / . _ -)')
            networks=[a for a in start_args if 'type=bridge' in a]
            if len(networks)!=1 or 'br='+plan['interface']+',' not in networks[0]:
                raise RuntimeError('Guest command does not use exactly the verified bridge')
            if start_args.count('-netdev')!=1 or any(a in ('-net','-nic','-fsdev','-virtfs','-chardev') for a in start_args):
                raise RuntimeError('Unexpected guest network or host-sharing option; manual review required')
            snapshot=Path(values['snapshot_path']);disk=Path(values['qcow2_path'])
            before={'snapshot':digest(snapshot),'disk':digest(disk),'machineinfo':digest(machineinfo)}
            with tempfile.TemporaryDirectory(prefix='sentinel-verify-',dir=output.parent) as folder:
                qemu=QEMU(config);qemu.init()
                machine=qemu._make_machine(name,values)
                vm=_QEMUMachine(machine,start_args,folder,Path(folder)/'qmp.sock')
                vm.snapshot_determine_compression();qemu.vms[name]=vm
                base=f'http://{machine.ip}:{machine.agent_port}'
                marker='C:\\sentinel-verify-'+uuid.uuid4().hex+'.txt'
                payload=('sentinel snapshot verification '+uuid.uuid4().hex).encode()
                with requests.Session() as session:
                    session.trust_env=False
                    try:
                        for boot in range(2):
                            qemu.restore_start(machine);wait_agent(session,base,qemu,machine)
                            if marker_present(session,base,marker):raise RuntimeError('Snapshot restoration failed: the verification marker persisted')
                            if boot==0:
                                response=session.post(base+'/store',data={'filepath':marker},files={'file':('marker.txt',payload)},timeout=30)
                                response.raise_for_status()
                                if not marker_present(session,base,marker):raise RuntimeError('First boot did not preserve the verification marker')
                                result=session.post(base+'/retrieve',data={'filepath':marker},timeout=30);result.raise_for_status()
                                if result.content!=payload:raise RuntimeError('Verification marker bytes were not read back correctly')
                            qemu.stop(machine)
                    finally:
                        vm.clean()
                after={'snapshot':digest(snapshot),'disk':digest(disk),'machineinfo':digest(machineinfo)}
                if before!=after:raise RuntimeError('Base snapshot or disk changed during disposable guest verification')
                proof['machines'].append({'name':name,'ip':machine.ip,'restoration_verified':True,'base_files_unchanged':True,'sha256':after})
        proof['verified']=bool(proof['machines'])
        return proof
    finally:
        output.write_text(json.dumps(proof,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cwd',required=True,type=Path)
    parser.add_argument('--plan',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    try:
        # Serialize with all managed starts. Provisioning stops managed services
        # first; reject an independently started core before touching the guest.
        with (args.plan.parent/'manager.lock').open('w') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            statefile=args.plan.parent/'processes.json'
            state=json.loads(statefile.read_text()) if statefile.exists() else {}
            if any(owned_alive(item) for name,item in state.items() if name in ('worker','cuckoo-core','cuckoo-api')):
                raise RuntimeError('Managed services must be stopped before guest restoration verification')
            result=verify(args.cwd,json.loads(args.plan.read_text()),args.output)
            print(json.dumps(result,indent=2))
    except Exception as error:
        raise SystemExit('Guest restoration verification failed: '+(str(error) if isinstance(error,RuntimeError) else type(error).__name__))
