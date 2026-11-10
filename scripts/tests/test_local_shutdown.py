"""Shutdown ordering and provisioning connection regressions; no real services."""
import json
import fcntl
import os
from pathlib import Path
import signal
import sys
from types import SimpleNamespace
import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT/'backend'))
import local
import provision


@pytest.fixture
def manager(tmp_path,monkeypatch):
    clock=SimpleNamespace(at=0.0)
    names=['postgres','redis','cuckoo-core','worker','maintenance','api','scheduler','frontend']
    state={name:{'pid':100+i,'starttime':'fixture'} for i,name in enumerate(names)}
    # None means running with no shutdown signal yet; infinity models a busy worker.
    exits={item['pid']:None for item in state.values()};delays={};events=[];messages=[]
    def alive(item):return exits[item['pid']] is None or clock.at<exits[item['pid']]
    def sent(pid,sig,group):
        events.append((pid,sig,group,clock.at));exits[pid]=clock.at+delays.get(pid,0)
    monkeypatch.setattr(local,'state',state)
    monkeypatch.setattr(local,'statefile',tmp_path/'processes.json')
    monkeypatch.setattr(local,'values',{})
    monkeypatch.setattr(local,'alive',alive)
    monkeypatch.setattr(local,'message',lambda category,message:messages.append((category,message)))
    monkeypatch.setattr(local,'time',SimpleNamespace(monotonic=lambda:clock.at,sleep=lambda seconds:setattr(clock,'at',clock.at+seconds)))
    monkeypatch.setattr(local,'os',SimpleNamespace(kill=lambda pid,sig:sent(pid,sig,False),killpg=lambda pid,sig:sent(pid,sig,True),replace=os.replace))
    return SimpleNamespace(state=state,pids={n:v['pid'] for n,v in state.items()},clock=clock,delays=delays,exits=exits,events=events,messages=messages)


def test_waits_past_old_ten_second_limit_and_stops_dependencies_last(manager):
    manager.delays[manager.pids['worker']]=15
    local.stop()
    events={pid:(sig,group,at) for pid,sig,group,at in manager.events}
    assert events[manager.pids['worker']][:2]==(signal.SIGTERM,False)
    assert events[manager.pids['postgres']][:2]==(signal.SIGINT,False)
    assert events[manager.pids['redis']][2]>=15 and events[manager.pids['cuckoo-core']][2]>=15
    assert any('Waiting for worker' in text for _,text in manager.messages)
    assert json.loads(local.statefile.read_text())=={}
    assert local.state=={}


def test_busy_worker_keeps_database_broker_and_sandbox_running_on_timeout(manager):
    local.values['LOCAL_SHUTDOWN_TIMEOUT']='1'
    manager.delays[manager.pids['worker']]=float('inf')
    with pytest.raises(RuntimeError,match=r'worker \(PID .*ownership records were retained'):
        local.stop()
    signalled={event[0] for event in manager.events}
    assert not signalled.intersection(manager.pids[n] for n in ('postgres','redis','cuckoo-core'))
    assert set(json.loads(local.statefile.read_text()))=={'worker','postgres','redis','cuckoo-core'}
    assert not any(sig==signal.SIGKILL for _,sig,_,_ in manager.events)


def test_stale_owned_processes_are_pruned_and_stop_is_idempotent(manager):
    for pid in manager.exits:manager.exits[pid]=0
    local.stop();local.stop()
    assert not manager.events and json.loads(local.statefile.read_text())=={}


def test_cache_cleanup_does_not_deadlock_a_stopping_maintenance_worker(tmp_path,monkeypatch,capsys):
    run=tmp_path/'.local/run';run.mkdir(parents=True)
    monkeypatch.setattr(local,'root',tmp_path)
    monkeypatch.setattr(local,'local',tmp_path/'.local')
    monkeypatch.setattr(local,'run',run)
    monkeypatch.setattr(local,'logs',tmp_path/'.local/logs')
    monkeypatch.setattr(local,'statefile',run/'processes.json')
    monkeypatch.setattr(sys,'argv',['local.py','cache-gc'])
    with (run/'manager.lock').open('w') as holder:
        fcntl.flock(holder,fcntl.LOCK_EX)
        assert local.main()==2
    assert 'Cache cleanup deferred' in capsys.readouterr().out


@pytest.mark.parametrize('active',[False,True])
def test_provision_closes_real_connection_pool_before_shutdown(tmp_path,monkeypatch,active):
    from sqlalchemy import create_engine,event
    from sqlalchemy.orm import sessionmaker
    from app import models
    database=create_engine('sqlite:///'+str(tmp_path/'app.db'))
    models.Base.metadata.create_all(database)
    session=sessionmaker(database)
    if active:
        with database.begin() as db:
            db.execute(models.Job.__table__.insert().values(sample_id='fixture',user_id='fixture',status='RUNNING'))
    closed=[];event.listen(database,'close',lambda *args:closed.append(True))
    run=tmp_path/'.local/run';run.mkdir(parents=True)
    (run/'processes.json').write_text(json.dumps({'postgres':{'pid':42}}))
    monkeypatch.setattr(provision,'ROOT',tmp_path)
    monkeypatch.setattr(local,'alive',lambda _:True)
    monkeypatch.setattr(models,'Session',session)
    calls=[]
    def stop(*args,**kwargs):
        assert closed and database.pool.checkedin()==0
        calls.append(args)
    monkeypatch.setattr(provision,'step',stop)
    if active:
        with pytest.raises(RuntimeError,match='queued or running'):provision.stop_idle_application()
        assert not calls
    else:
        provision.stop_idle_application();assert len(calls)==1
    assert closed
    database.dispose()
