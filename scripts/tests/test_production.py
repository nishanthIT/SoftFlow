"""Release invalidation, safe pruning and local HTTP startup regressions."""
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import local
import production
import service


def test_release_cache_ignores_generated_types_but_tracks_source_and_api(tmp_path,monkeypatch):
    frontend=tmp_path/'frontend';(frontend/'src').mkdir(parents=True)
    source=frontend/'src/page.tsx';source.write_text('first')
    config=frontend/'tsconfig.json';config.write_text(json.dumps({'include':['src/**/*.ts','.next/types/**/*.ts']}))
    monkeypatch.setattr(production,'ROOT',tmp_path)
    monkeypatch.setattr(production.subprocess,'check_output',lambda *a,**kw:b'v22.21.1')
    values={'API_INTERNAL_URL':'http://127.0.0.1:8100'}
    initial=production.source_signature(values)
    config.write_text(json.dumps({'include':['src/**/*.ts','.next-releases/abc/types/**/*.ts']}))
    assert production.source_signature(values)==initial
    source.write_text('changed')
    assert production.source_signature(values)!=initial
    source.write_text('first');values['API_INTERNAL_URL']='http://127.0.0.1:8101'
    assert production.source_signature(values)!=initial


def test_pruning_preserves_current_recent_incomplete_and_unowned_paths(tmp_path,monkeypatch):
    directory=tmp_path/'frontend/.next-releases';directory.mkdir(parents=True)
    current='1'*24
    for index in range(1,5):
        release=directory/(str(index)*24);release.mkdir()
        marker=release/'release.json';marker.write_text('{}');os.utime(marker,(index,index))
    incomplete=directory/('5'*24);incomplete.mkdir()
    stale=directory/('6'*24);stale.mkdir();os.utime(stale,(time.time()-90000,)*2)
    unowned=directory/'keep-me';unowned.mkdir()
    outside=tmp_path/'outside';outside.mkdir();(outside/'important').write_text('retained')
    (directory/('7'*24)).symlink_to(outside,target_is_directory=True)
    monkeypatch.setattr(production,'ROOT',tmp_path)
    production.prune_releases(current)
    assert (directory/current).exists() and (directory/('3'*24)).exists() and (directory/('4'*24)).exists()
    assert not (directory/('2'*24)).exists() and not stale.exists()
    assert incomplete.exists() and unowned.exists() and (outside/'important').read_text()=='retained'


def test_native_production_does_not_enable_cuckoo(monkeypatch):
    values={'SANDBOX_ENABLED':'false','CUCKOO_REQUIRED':'true','CUCKOO_AUTO_START':'true'}
    monkeypatch.setattr(local,'values',values);monkeypatch.setattr(local,'env',{})
    local.configure_mode()
    assert values['APP_ENV']=='production' and values['PRESENTATION_MODE']=='false'
    assert values['CUCKOO_REQUIRED']=='false' and values['CUCKOO_AUTO_START']=='false'
    assert 'proxy' not in service.REQUIRED


def test_log_trimming_bounds_regular_logs_without_following_links(tmp_path):
    outside=tmp_path/'outside';outside.write_bytes(b'private')
    logs=tmp_path/'logs';logs.mkdir()
    (logs/'small.log').write_bytes(b'small')
    (logs/'large.log').write_bytes(b'x'*100+b'tail')
    (logs/'linked.log').symlink_to(outside)
    service.trim_logs(logs,limit=20,keep=4)
    assert (logs/'large.log').read_bytes()==b'tail'
    assert (logs/'small.log').read_bytes()==b'small' and outside.read_bytes()==b'private'


def test_user_service_pins_terminal_node_and_validates_before_stopping(tmp_path,monkeypatch):
    monkeypatch.setattr(service,'ROOT',tmp_path/'project with spaces')
    monkeypatch.setattr(Path,'home',lambda:tmp_path)
    monkeypatch.setattr(service.shutil,'which',lambda name:'/opt/node version/bin/node')
    calls=[]
    monkeypatch.setattr(service.subprocess,'run',lambda args,**kwargs:calls.append(args))
    service.install()
    unit=tmp_path/'.config/systemd/user/sentinelscan.service'
    text=unit.read_text()
    assert f'WorkingDirectory={tmp_path}/project with spaces\n' in text
    assert 'Environment="PATH=/opt/node version/bin:' in text
    assert calls[0]==['systemd-analyze','--user','verify',str(unit)]
    assert calls[1][-1]=='stop'
