"""Foreground process regressions with harmless local services; no real sandbox/DB."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import subprocess
import sys
import time
import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import service


FIXTURE_MANAGER = '''import json, os, signal, subprocess, sys, time
from pathlib import Path
from dotenv import dotenv_values
ROOT=Path(__file__).resolve().parents[1]
def alive(item):
    try:return Path('/proc/'+str(item['pid'])+'/stat').read_text().rsplit(')',1)[1].split()[0]!='Z'
    except OSError:return False
if __name__=='__main__':
    values={**dotenv_values(ROOT/'.env'),**os.environ}
    with (ROOT/'calls.jsonl').open('a') as out:
        out.write(json.dumps({'action':sys.argv[1],'args':sys.argv[2:],'value':values.get('APP_TEST_VALUE')})+'\\n')
    run=ROOT/'.local/run';run.mkdir(parents=True,exist_ok=True)
    if sys.argv[1]=='start':
        if (ROOT/'fail-start').exists():sys.exit(1)
        if (ROOT/'block-start').exists():
            child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'])
            (ROOT/'build-child.pid').write_text(str(child.pid))
            time.sleep(120)
        statefile=run/'processes.json'
        state=json.loads(statefile.read_text()) if statefile.exists() else {}
        if not state or not all(alive(item) for item in state.values()):
            child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'],start_new_session=True)
            (ROOT/'managed.pid').write_text(str(child.pid))
            state={name:{'pid':child.pid} for name in ('postgres','redis','api','worker','ssl-worker','maintenance','scheduler','frontend')}
            statefile.write_text(json.dumps(state))
        (run/'stopped').unlink(missing_ok=True)
    elif sys.argv[1]=='stop':
        (run/'stopped').touch()
        if (ROOT/'managed.pid').exists():
            try:os.kill(int((ROOT/'managed.pid').read_text()),signal.SIGTERM)
            except ProcessLookupError:pass
        (run/'processes.json').write_text('{}')
'''


def wait_for(check,timeout=8):
    deadline=time.monotonic()+timeout
    while not check():
        if time.monotonic()>deadline:raise AssertionError('Fixture did not become ready')
        time.sleep(.05)


def running(pid):
    try:return Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[0]!='Z'
    except OSError:return False


@pytest.fixture
def project(tmp_path):
    scripts=tmp_path/'scripts';scripts.mkdir()
    shutil.copy2(Path(service.__file__),scripts/'service.py')
    (scripts/'local.py').write_text(FIXTURE_MANAGER)
    (tmp_path/'.env').write_text('APP_TEST_VALUE=first\n')
    yield tmp_path
    for file in tmp_path.glob('*.pid'):
        pid=int(file.read_text())
        if running(pid):
            try:os.kill(pid,signal.SIGTERM)
            except ProcessLookupError:pass


def launch(project,log):
    return subprocess.Popen([sys.executable,str(project/'scripts/service.py'),'run'],cwd=project,
        env={**os.environ,'APP_TEST_VALUE':'stale-pm2-value'},stdout=log,stderr=subprocess.STDOUT)


@pytest.mark.parametrize('sig',[signal.SIGINT,signal.SIGTERM])
def test_foreground_stays_up_reloads_env_and_drains_on_signal(project,sig):
    log=project/'output.log'
    with log.open('w') as output:
        process=launch(project,output)
        try:
            wait_for(lambda:'foreground supervisor is running' in log.read_text())
            time.sleep(.3)
            assert process.poll() is None
            calls=[json.loads(line) for line in (project/'calls.jsonl').read_text().splitlines()]
            assert len(calls)==1 and calls[0]['action']=='start' and calls[0]['value']=='first'
            assert '--foreground-start' in calls[0]['args']
            (project/'.env').write_text('APP_TEST_VALUE=updated\n')
            process.send_signal(sig)
            assert process.wait(timeout=8)==0,log.read_text()
            calls=[json.loads(line) for line in (project/'calls.jsonl').read_text().splitlines()]
            assert calls[-1]['action']=='stop' and calls[-1]['value']=='updated'
            wait_for(lambda:not running(int((project/'managed.pid').read_text())))
        finally:
            if process.poll() is None:process.terminate();process.wait(timeout=8)


def test_signal_during_startup_stops_build_group_and_runs_managed_shutdown(project):
    (project/'block-start').touch()
    with (project/'output.log').open('w') as output:
        process=launch(project,output)
        try:
            wait_for(lambda:(project/'build-child.pid').exists())
            build_pid=int((project/'build-child.pid').read_text())
            process.terminate()
            assert process.wait(timeout=8)==0
            wait_for(lambda:not running(build_pid))
            calls=[json.loads(line)['action'] for line in (project/'calls.jsonl').read_text().splitlines()]
            assert calls==['start','stop']
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=8)


def test_failed_start_returns_failure_for_pm2_without_stopping_existing_services(project):
    (project/'fail-start').touch()
    with (project/'output.log').open('w') as output:
        process=launch(project,output)
        assert process.wait(timeout=8)==1
    calls=[json.loads(line)['action'] for line in (project/'calls.jsonl').read_text().splitlines()]
    assert calls==['start']


def test_duplicate_foreground_owner_cannot_launch_or_stop_services(project):
    run=project/'.local/run';run.mkdir(parents=True)
    with (run/'foreground.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        with (project/'output.log').open('w') as output:
            process=launch(project,output)
            assert process.wait(timeout=8)==1
    assert not (project/'calls.jsonl').exists()


@pytest.mark.parametrize('arguments,pm_id,expected',[
    ([],None,['scripts/local.py','start']),
    ([], '0',['scripts/service.py','run']),
    (['--foreground'],None,['scripts/service.py','run','--foreground']),
])
def test_start_entry_selects_foreground_for_pm2_only(tmp_path,arguments,pm_id,expected):
    root=Path(__file__).resolve().parents[2]
    shutil.copy2(root/'start.sh',tmp_path/'start.sh')
    binary=tmp_path/'.venv-local/bin/python';binary.parent.mkdir(parents=True)
    binary.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n');binary.chmod(0o755)
    environment={key:value for key,value in os.environ.items() if key!='pm_id'}
    if pm_id is not None:environment['pm_id']=pm_id
    result=subprocess.run(['bash','start.sh','--prepared-app',*arguments],cwd=tmp_path,env=environment,capture_output=True,text=True,check=True)
    assert result.stdout.splitlines()==expected


@pytest.mark.skipif(not os.environ.get('PM2_TEST_BINARY'),reason='Set PM2_TEST_BINARY for the isolated real-PM2 check')
def test_real_pm2_restart_reloads_env_without_restarting_unrelated_cuckoo(project):
    root=Path(__file__).resolve().parents[2]
    for name in ('start.sh','ecosystem.config.cjs'):shutil.copy2(root/name,project/name)
    (project/'scripts/prepare_app.py').write_text('print("Fixture dependencies ready")\n')
    python=project/'.venv-local/bin/python';python.parent.mkdir(parents=True)
    python.write_text('#!/bin/sh\nexec '+shlex.quote(sys.executable)+' "$@"\n');python.chmod(0o755)
    (project/'unrelated.cjs').write_text('setInterval(() => {}, 1000);\n')
    pm2=os.environ['PM2_TEST_BINARY']
    environment={**os.environ,'PM2_HOME':str(project/'.pm2-test'),'APP_TEST_VALUE':'stale-pm2-value'}
    def command(*args):
        result=subprocess.run([pm2,*args],cwd=project,env=environment,capture_output=True,text=True,timeout=30)
        assert result.returncode==0,result.stderr
        return result.stdout
    def processes():return {p['name']:p for p in json.loads(command('jlist'))}
    def calls():return [json.loads(line) for line in (project/'calls.jsonl').read_text().splitlines()]
    try:
        command('start','unrelated.cjs','--name','cuckoo-api-fixture')
        unrelated=processes()['cuckoo-api-fixture']['pid']
        command('start','ecosystem.config.cjs','--only','auto-scan')
        wait_for(lambda:(project/'managed.pid').exists())
        time.sleep(2)
        first=processes()['auto-scan']
        assert first['pm2_env']['status']=='online' and first['pm2_env']['restart_time']==0
        assert len(calls())==1 and calls()[0]['value']=='first'
        (project/'.env').write_text('APP_TEST_VALUE=changed-after-start\n')
        command('restart','auto-scan','--update-env')
        wait_for(lambda:sum(c['action']=='start' for c in calls())==2)
        time.sleep(2)
        second=processes()
        assert second['auto-scan']['pm2_env']['status']=='online'
        assert second['auto-scan']['pm2_env']['restart_time']==1
        assert second['auto-scan']['pid']!=first['pid']
        assert [c['action'] for c in calls()]==['start','stop','start']
        assert calls()[-1]['value']=='changed-after-start'
        assert second['cuckoo-api-fixture']['pid']==unrelated
        assert second['cuckoo-api-fixture']['pm2_env']['restart_time']==0
        command('stop','auto-scan')
        assert processes()['auto-scan']['pm2_env']['status']=='stopped'
        assert calls()[-1]['action']=='stop'
    finally:
        subprocess.run([pm2,'kill'],cwd=project,env=environment,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
