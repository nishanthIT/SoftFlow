"""Idempotent application, host and guest provisioning; no fabricated attestation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def step(label,args,logname='setup-steps.log',capture=False):
    print('[SETUP] '+label,flush=True)
    logfile=ROOT/'.local/logs'/logname;logfile.parent.mkdir(parents=True,exist_ok=True)
    with logfile.open('a') as output:
        process=subprocess.Popen([str(a) for a in args],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        lines=[]
        for line in process.stdout:
            output.write(line);output.flush()
            if capture:lines.append(line)
            else:print(line,end='',flush=True)
        if process.wait():
            if capture:print(''.join(lines),end='',flush=True)
            raise RuntimeError(label+' failed. Inspect '+str(logfile.relative_to(ROOT)))
    print('[OK] '+label,flush=True)
    return ''.join(lines)


def dependencies():
    stamp=ROOT/'.local/run/app-install.json'
    expected={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ['backend/requirements.txt','frontend/package-lock.json']}
    expected['python']=sys.version.split()[0]
    current=json.loads(stamp.read_text()) if stamp.exists() else {}
    healthy=subprocess.run([sys.executable,'-m','pip','check'],capture_output=True).returncode==0
    if not healthy or current.get('backend/requirements.txt')!=expected['backend/requirements.txt'] or current.get('python')!=expected['python']:
        step('Install pinned application Python dependencies',[sys.executable,'-m','pip','install','-r','backend/requirements.txt'])
    step('Validate application Python dependencies',[sys.executable,'-m','pip','check'])
    healthy=subprocess.run(['npm','ls','--prefix','frontend','--omit=dev','--depth=0'],capture_output=True).returncode==0
    if not healthy or current.get('frontend/package-lock.json')!=expected['frontend/package-lock.json'] or not (ROOT/'frontend/node_modules/next/package.json').exists():
        step('Install locked frontend dependencies',['npm','ci','--prefix','frontend'])
    stamp.write_text(json.dumps(expected,indent=2))


def stop_idle_application():
    """Provisioning may stop our idle processes, never interrupt active jobs."""
    from local import alive
    path=ROOT/'.local/run/processes.json'
    state=json.loads(path.read_text()) if path.exists() else {}
    if not any(alive(item) for item in state.values()):return
    sys.path.insert(0,str(ROOT/'backend'))
    from app.models import Session,Job,SSLCheck
    from sqlalchemy import select,inspect
    try:
        with Session() as db:
            if db.scalar(select(Job.id).where(Job.status.in_(['RUNNING','QUEUED'])).limit(1)):
                raise RuntimeError('Analyses are queued or running. Let them finish before provisioning; no active analysis was interrupted.')
            if inspect(db.get_bind()).has_table(SSLCheck.__tablename__) and db.scalar(select(SSLCheck.id).where(SSLCheck.status.in_(['RUNNING','QUEUED'])).limit(1)):
                raise RuntimeError('Certificate checks are queued or running. Let them finish before provisioning.')
    except RuntimeError:raise
    except Exception:raise RuntimeError('Could not prove the running application is idle. Restore database connectivity before provisioning.')
    finally:
        # Session.close() returns its connection to the pool. The setup process
        # stays alive while waiting for local.py, so explicitly close that pool
        # before asking PostgreSQL to shut down.
        Session.kw['bind'].dispose()
    # All processes belong to this application's PID/start-time inventory.
    step('Stop idle managed application for guest provisioning',[sys.executable,'scripts/local.py','stop'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accept-windows-license',action='store_true',help='Confirm authorization to install Windows from the configured media')
    parser.add_argument('--check',action='store_true',help='Read-only prerequisite report; no installation or configuration changes')
    args=parser.parse_args()
    if args.check:
        from cuckoo_local import configuration,doctor
        result=doctor(configuration());print(json.dumps(result,indent=2));return 0 if result['ready'] else 2
    dependencies()
    stop_idle_application()
    from verify_cuckoo_guest import check_idle
    check_idle()
    from dotenv import set_key
    from cuckoo_local import configuration,doctor
    step('Configure application services',[sys.executable,'scripts/configure_local.py'])
    values=configuration()
    if not (args.accept_windows_license or values.get('CUCKOO_WINDOWS_LICENSE_ACCEPTED','false').lower()=='true'):
        if not sys.stdin.isatty():raise RuntimeError('Windows license authorization is required. Rerun npm run setup -- --accept-windows-license only if you are authorized to install this media.')
        reply=input('Are you authorized to install Windows using the configured ISO? [yes/no] ').strip().lower()
        if reply!='yes':raise RuntimeError('Windows guest installation was not authorized; no media was downloaded or guest created')
    set_key(ROOT/'.env','CUCKOO_WINDOWS_LICENSE_ACCEPTED','true')
    set_key(ROOT/'.env','CUCKOO_REQUIRED','true')
    step('Install or validate pinned Cuckoo environment',[sys.executable,'scripts/cuckoo_local.py','install'],'cuckoo-setup.log')
    step('Install or validate pinned VMCloak environment',[sys.executable,'scripts/cuckoo_guest.py','install'],'guest-setup.log')
    step('Prepare explicit isolated network plan',[sys.executable,'scripts/cuckoo_guest.py','host-plan'],'network-setup.log')
    print('[NETWORK] Applying the dedicated bridge/firewall plan shown above; existing firewall tables are preserved.',flush=True)
    step('Provision isolated host network and boot service',['sudo','python3','scripts/prepare_cuckoo_host.py','--install-service'],'network-setup.log')
    proof=json.loads(step('Verify installed host isolation',['sudo','python3','scripts/prepare_cuckoo_host.py','--verify-json'],'network-verification.log',capture=True))
    (ROOT/'.local/run/cuckoo-host-verification.json').write_text(json.dumps(proof,indent=2))
    if not proof['verified']:raise RuntimeError('Host isolation verification failed; guest build was not started')
    set_key(ROOT/'.env','SANDBOX_NETWORK_POLICY','blocked')
    step('Configure Cuckoo host interfaces',[sys.executable,'scripts/cuckoo_local.py','host-config'],'cuckoo-setup.log')
    step('Verify or resume Windows installation media',[sys.executable,'scripts/cuckoo_guest.py','download'],'guest-download.log')
    step('Build or reuse the Windows guest and clean snapshot',[sys.executable,'scripts/cuckoo_guest.py','build'],'guest-build.log')
    result=doctor(configuration())
    (ROOT/'.local/run/cuckoo-doctor.json').write_text(json.dumps(result,indent=2))
    if not result['prerequisites_ready']:raise RuntimeError('Guest prerequisites failed after provisioning; inspect .local/run/cuckoo-doctor.json')
    from cuckoo_local import paths,isolated_env
    venv,cwd,_=paths(configuration())
    set_key(ROOT/'.env','SANDBOX_ISOLATION_CONFIRMED','false')
    # This executes only a fixed, harmless marker check in the guest while the
    # application and Cuckoo scheduler are stopped. No user samples are submitted.
    command=[str(venv/'bin/python'),str(ROOT/'scripts/verify_cuckoo_guest.py'),'--cwd',str(cwd),
        '--plan',str(ROOT/'.local/run/cuckoo-host-plan.json'),'--output',str(ROOT/'.local/run/cuckoo-guest-verification.json')]
    print('[VERIFY] Restoring each clean guest snapshot twice and checking a harmless marker is discarded',flush=True)
    with (ROOT/'.local/logs/guest-verification.log').open('a') as output:
        subprocess.run(command,cwd=ROOT,env=isolated_env(),stdout=output,stderr=subprocess.STDOUT,check=True,timeout=3600)
    guest_proof=json.loads((ROOT/'.local/run/cuckoo-guest-verification.json').read_text())
    if not guest_proof.get('verified'):raise RuntimeError('Guest restoration remains unverified; inspect guest-verification.log')
    # Recheck host rules after the guest test before enabling application uploads.
    step('Recheck host isolation',['sudo','python3','scripts/prepare_cuckoo_host.py','--verify-json'],'network-verification.log',capture=True)
    set_key(ROOT/'.env','SANDBOX_ISOLATION_CONFIRMED','true')
    set_key(ROOT/'.env','SANDBOX_ENABLED','true')
    step('Start and check all application services',['bash','start.sh','--prepared-app'],'setup-start.log')
    step('Run harmless end-to-end analysis',[sys.executable,'scripts/verify_sandbox.py'],'verification.log')
    print('[OK] Setup and live workflow verification completed. Subsequent launches use npm start.',flush=True)
    return 0


if __name__=='__main__':
    try:sys.exit(main())
    except Exception as error:
        print('[ERROR] '+(str(error) if isinstance(error,RuntimeError) else type(error).__name__),file=sys.stderr)
        sys.exit(1)
