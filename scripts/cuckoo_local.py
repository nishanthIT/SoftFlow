"""Reproducible Cuckoo installation/configuration and read-only prerequisite checks.

Run with the application environment. Never installs into that environment.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile
from dotenv import dotenv_values, set_key

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = json.loads((ROOT / 'sandbox/versions.json').read_text())


def configuration():
    return {**dotenv_values(ROOT / '.env'), **os.environ}


def path(values, key, default):
    value = Path(values.get(key) or default).expanduser()
    return value if value.is_absolute() else ROOT / value


def paths(values):
    return (path(values, 'CUCKOO_VENV', '.local/cuckoo-venv'),
            path(values, 'CUCKOO_CWD', '.local/cuckoo'),
            path(values, 'CUCKOO_SOURCE', '.local/cuckoo3-src'))


def isolated_env():
    # Do not pass application/provider/database credentials to Cuckoo.
    return {key: value for key, value in os.environ.items()
            if key in ('HOME', 'USER', 'LOGNAME', 'PATH', 'LANG', 'LC_ALL', 'TZ', 'SSL_CERT_FILE')}


def run(args, **kwargs):
    env=kwargs.pop('env',isolated_env())
    if Path(args[0]).parent.name=='bin':env['PATH']=str(Path(args[0]).parent)+os.pathsep+env.get('PATH','')
    return subprocess.run([str(x) for x in args], check=True, env=env, **kwargs)


def bootstrap_python():
    """Install a pinned managed interpreter under .local; leave system Python alone."""
    tooling=ROOT/'.local/tools'
    run([sys.executable,'-m','pip','install','--target',tooling,'uv=='+VERSIONS['uv_version']])
    env=isolated_env()
    env.update(UV_PYTHON_INSTALL_DIR=str(ROOT/'.local/python'),UV_CACHE_DIR=str(ROOT/'.local/uv-cache'))
    uv=tooling/'bin/uv'
    run([uv,'python','install',VERSIONS['python_patch'],'--no-bin'],env=env)
    return run([uv,'python','find','--managed-python',VERSIONS['python_patch']],env=env,capture_output=True,text=True).stdout.strip()


def install(values):
    venv, cwd, source = paths(values)
    interpreter = values.get('CUCKOO_PYTHON') or 'python3.10'
    if '/' in interpreter:
        interpreter = str(path(values, 'CUCKOO_PYTHON', interpreter))
    if not shutil.which(interpreter):
        if interpreter=='python3.10' and str(values.get('CUCKOO_BOOTSTRAP_PYTHON','true')).lower()=='true':
            interpreter=bootstrap_python()
        else:raise RuntimeError('Python 3.10 is required. Set CUCKOO_PYTHON to its executable or enable CUCKOO_BOOTSTRAP_PYTHON.')
    version = run([interpreter, '-c', 'import sys; print("%s.%s" % sys.version_info[:2])'], capture_output=True, text=True).stdout.strip()
    if version != VERSIONS['python']:raise RuntimeError('Cuckoo installation requires the documented Python 3.10 baseline')
    if not source.exists():run(['git', 'clone', VERSIONS['repository'], source])
    dirty=run(['git','-C',source,'status','--porcelain'],capture_output=True,text=True).stdout
    if dirty:raise RuntimeError('Cuckoo source has local changes; refusing to install an unpinned source tree')
    revision=run(['git', '-C', source, 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
    if revision != VERSIONS['revision']:
        run(['git', '-C', source, 'fetch', 'origin', VERSIONS['revision']])
        run(['git', '-C', source, 'checkout', '--detach', VERSIONS['revision']])
    if not (venv/'bin/python').exists():run([interpreter, '-m', 'venv', venv])
    installed=run([venv/'bin/python','-c','import sys; print("%s.%s" % sys.version_info[:2])'],capture_output=True,text=True).stdout.strip()
    if installed != VERSIONS['python']:raise RuntimeError('Existing CUCKOO_VENV uses a different Python; choose a new directory')
    run([venv/'bin/python', '-m', 'pip', 'install', '-r', ROOT/'sandbox/requirements.lock',
         *[source/name for name in VERSIONS['packages']]])
    run([venv/'bin/python', '-m', 'pip', 'check'])
    run([venv/'bin/python', ROOT/'scripts/cuckoo_native_fix.py'])
    configure(values)


def configure(values):
    venv, cwd, source = paths(values)
    cuckoo = [venv/'bin/cuckoo', '--cwd', cwd]
    fresh = not cwd.exists()
    if fresh:
        run([*cuckoo, 'createcwd'])
        cwd.chmod(0o700)
        run([*cuckoo, 'getmonitor', source/'monitor.zip'])
        with zipfile.ZipFile(source/'signatures.zip') as archive:
            target=cwd/'signatures/cuckoo'
            for member in archive.infolist():
                if not (target/member.filename).resolve().is_relative_to(target.resolve()):raise RuntimeError('Unsafe signature archive path')
            archive.extractall(target)
        # Configure generated YAML using Cuckoo's own PyYAML dependency.
        code='''import sys,shutil,yaml,os
from pathlib import Path
p=Path(sys.argv[1])
f=p/'conf/machineries/qemu.yaml';d=yaml.safe_load(f.read_text());d['machines']={}
for key,binary in [('qemu_img','qemu-img'),('qemu_system_x86_64','qemu-system-x86_64')]:
 d['binaries'][key]=shutil.which(binary,path=os.defpath) or d['binaries'][key]
f.write_text(yaml.safe_dump(d,sort_keys=False))
f=p/'conf/cuckoo.yaml';d=yaml.safe_load(f.read_text());d['tcpdump']['path']=sys.argv[2] or shutil.which('tcpdump') or d['tcpdump']['path'];d['tcpdump']['enabled']=True
f.write_text(yaml.safe_dump(d,sort_keys=False))
'''
        run([venv/'bin/python','-c',code,cwd,values.get('CUCKOO_TCPDUMP') or ''])
    # Existing configuration, guest images and credentials are never reset.
    run([venv/'bin/cuckoomigrate','--cwd',cwd,'database','all'])
    run([*cuckoo,'api','djangocommand','migrate','--noinput'])
    if not values.get('CUCKOO_API_TOKEN'):
        result=run([*cuckoo,'api','token','--create','sentinelscan'],capture_output=True,text=True)
        import re
        match=re.search(r'Created key ([a-f0-9]+) with ID:',result.stdout)
        if not match:raise RuntimeError('Could not obtain API token; inspect the Cuckoo token owner configuration')
        set_key(ROOT/'.env','CUCKOO_API_TOKEN',match.group(1))
    for key,value in {'SANDBOX_KIND':'cuckoo3','CUCKOO_AUTO_START':'true',
                      'CUCKOO_API_URL':values.get('CUCKOO_API_URL') or 'http://127.0.0.1:8090',
                      'CUCKOO_CWD':values.get('CUCKOO_CWD') or '.local/cuckoo',
                      'CUCKOO_VENV':values.get('CUCKOO_VENV') or '.local/cuckoo-venv'}.items():
        set_key(ROOT/'.env',key,value)
    (ROOT/'.env').chmod(0o600)
    print('Cuckoo packages and API configuration prepared. Guest execution remains subject to doctor and live verification.')


def doctor(values):
    venv,cwd,source=paths(values)
    checks=[]
    def check(name, ok, detail):checks.append({'check':name,'ok':bool(ok),'detail':detail})
    check('python_environment',(venv/'bin/python').exists(),'Separate Cuckoo Python 3.10 environment')
    if (venv/'bin/python').exists():
        code='import sys,importlib.metadata as m; import cuckoo, cuckoo.node, cuckoo.processing, hyperscan, yara, roach, sflock; print("%s.%s" % sys.version_info[:2],m.version("Cuckoo"))'
        p=subprocess.run([str(venv/'bin/python'),'-c',code],capture_output=True,text=True,env=isolated_env())
        check('cuckoo_version',p.returncode==0 and p.stdout.strip()=='3.10 '+VERSIONS['version'],p.stdout.strip() or 'Dependency imports failed; run cuckoo_native_fix.py and pip check in CUCKOO_VENV')
    for binary in ['qemu-system-x86_64','qemu-img','tcpdump','genisoimage']:
        check(binary,shutil.which(binary,path=os.defpath),f'{binary} must be installed as a host system binary')
    capture=values.get('CUCKOO_TCPDUMP') or shutil.which('tcpdump',path=os.defpath)
    cap=subprocess.run(['getcap',capture],capture_output=True,text=True).stdout if capture and shutil.which('getcap') else ''
    check('packet_capture_permissions',capture and os.access(capture,os.X_OK) and 'cap_net_raw' in cap and 'cap_net_admin' in cap,'Run sudo python3 scripts/prepare_cuckoo_host.py to prepare the private capture helper')
    check('kvm',os.access('/dev/kvm',os.R_OK|os.W_OK),'KVM device must be accessible to the service user')
    check('configuration',(cwd/'conf/cuckoo.yaml').is_file(),'Run setup-cuckoo.sh first')
    check('monitor',any((cwd/'monitor').glob('**/threemon.sys')) and any((cwd/'monitor').glob('**/tmstage.exe')),'Cuckoo guest monitor payload must be installed with getmonitor')
    if (venv/'bin/python').exists() and (cwd/'conf/cuckoo.yaml').exists():
        code='''import json,sys,yaml,socket
from pathlib import Path
p=Path(sys.argv[1]);d=yaml.safe_load((p/'conf/machineries/qemu.yaml').read_text());c=yaml.safe_load((p/'conf/cuckoo.yaml').read_text())
machines=d.get('machines',{});issues=[]
for key,binary in d.get('binaries',{}).items():
 if not Path(binary).is_file():issues.append('Missing configured binary '+key)
 if '.android-sdk' in binary:issues.append('Android emulator '+key+' selected; run cuckoo_local.py host-config')
if d.get('interface') not in dict((n,i) for i,n in socket.if_nameindex()):issues.append('Configured QEMU bridge is unavailable')
for name,m in machines.items():
 for key in ['qcow2_path','snapshot_path','machineinfo_path']:
  if not m.get(key) or not Path(m[key]).is_file():issues.append(name+': missing '+key)
 if m.get('interface') not in dict((n,i) for i,n in socket.if_nameindex()):issues.append(name+': network interface unavailable')
try:
 s=socket.socket();s.bind((c['resultserver']['listen_ip'],0));s.close()
except OSError:issues.append('Resultserver listen IP is not configured on this host')
print(json.dumps({'machines':list(machines),'issues':issues,'tcpdump':c['tcpdump']['enabled']}))
'''
        p=subprocess.run([str(venv/'bin/python'),'-c',code,str(cwd)],capture_output=True,text=True,env=isolated_env())
        if p.returncode:check('machine_config',False,'Cannot parse Cuckoo machine configuration')
        else:
            d=json.loads(p.stdout);check('machines',bool(d['machines']) and not d['issues'],d)
            check('packet_capture_enabled',d['tcpdump'],'Cuckoo tcpdump collection must be enabled')
    check('isolation',str(values.get('SANDBOX_ISOLATION_CONFIRMED','false')).lower()=='true','Requires verified guest isolation and clean snapshot restoration')
    return {'ready':all(c['ok'] for c in checks),'version':VERSIONS['version'],'checks':checks}


def host_config(values):
    """Apply explicit host settings, backing up the previous YAML once."""
    venv,cwd,_=paths(values)
    code='''import sys,yaml,shutil,os
from pathlib import Path
p=Path(sys.argv[1])
for name in ['machineries/qemu.yaml','cuckoo.yaml']:
 f=p/'conf'/name;backup=f.with_suffix('.yaml.before-host-config')
 if not backup.exists():shutil.copyfile(f,backup)
 d=yaml.safe_load(f.read_text())
 if name.startswith('machineries'):
  for key,binary in [('qemu_img','qemu-img'),('qemu_system_x86_64','qemu-system-x86_64')]:
   d['binaries'][key]=shutil.which(binary,path=os.defpath) or d['binaries'][key]
  if sys.argv[2]:d['interface']=sys.argv[2]
 else:
  if sys.argv[3]:d['resultserver']['listen_ip']=sys.argv[3]
  if sys.argv[4]:d['tcpdump']['path']=sys.argv[4]
 f.write_text(yaml.safe_dump(d,sort_keys=False))
'''
    run([venv/'bin/python','-c',code,cwd,values.get('CUCKOO_INTERFACE') or '',
         values.get('CUCKOO_RESULTSERVER_IP') or '',values.get('CUCKOO_TCPDUMP') or ''])
    print('Host paths configured. Previous YAML backed up; registered machines unchanged.')


def import_vms(values, directory):
    """Import operator-prepared VMCloak snapshots; never manufacture attestation."""
    venv,cwd,_=paths(values)
    directory=directory.expanduser().resolve()
    if not directory.is_dir():raise RuntimeError('VMCloak VM directory does not exist')
    interface=values.get('CUCKOO_INTERFACE')
    address=values.get('CUCKOO_RESULTSERVER_IP')
    if not interface or not address:raise RuntimeError('Set CUCKOO_INTERFACE and CUCKOO_RESULTSERVER_IP for the verified isolated guest network')
    import ipaddress,socket
    ipaddress.ip_address(address)
    if interface not in {name for _,name in socket.if_nameindex()}:raise RuntimeError('Configured guest network interface does not exist')
    run([venv/'bin/cuckoo','--cwd',cwd,'machine','import','qemu',directory])
    code='''import sys,yaml,shutil,os
from pathlib import Path
p=Path(sys.argv[1]);interface=sys.argv[2];address=sys.argv[3]
f=p/'conf/machineries/qemu.yaml';d=yaml.safe_load(f.read_text());d['interface']=interface
for key,binary in [('qemu_img','qemu-img'),('qemu_system_x86_64','qemu-system-x86_64')]:
 d['binaries'][key]=shutil.which(binary,path=os.defpath) or d['binaries'][key]
for m in d['machines'].values():m['interface']=interface
f.write_text(yaml.safe_dump(d,sort_keys=False))
f=p/'conf/cuckoo.yaml';d=yaml.safe_load(f.read_text());d['resultserver']['listen_ip']=address;d['tcpdump']['path']=sys.argv[4] or shutil.which('tcpdump',path=os.defpath) or d['tcpdump']['path']
f.write_text(yaml.safe_dump(d,sort_keys=False))
'''
    run([venv/'bin/python','-c',code,cwd,interface,address,values.get('CUCKOO_TCPDUMP') or ''])
    print('Imported prepared snapshots. Isolation confirmation is unchanged; run doctor and live verification.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['install','configure','doctor','host-config','import-vms'])
    parser.add_argument('--vms-path',type=Path)
    args=parser.parse_args();values=configuration()
    try:
        if args.command=='doctor':
            result=doctor(values);print(json.dumps(result,indent=2));sys.exit(0 if result['ready'] else 2)
        elif args.command=='install':install(values)
        elif args.command=='host-config':host_config(values)
        elif args.command=='import-vms':
            if not args.vms_path:raise RuntimeError('import-vms requires --vms-path')
            import_vms(values,args.vms_path)
        else:configure(values)
    except (RuntimeError,subprocess.CalledProcessError,OSError) as error:
        print('Cuckoo setup failed: '+(str(error) if isinstance(error,RuntimeError) else type(error).__name__),file=sys.stderr)
        sys.exit(1)
