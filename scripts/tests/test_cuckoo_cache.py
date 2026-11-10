"""Offline shared-cache ownership tests, using no real Cuckoo data or processes."""
import json
import os
from pathlib import Path
import sqlite3
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cuckoo_cache import prune

AT=2000000000

@pytest.fixture
def cache(tmp_path):
    with sqlite3.connect(tmp_path/'cuckoo.db') as db:
        db.executescript('CREATE TABLE analyses(id TEXT,state TEXT);CREATE TABLE tasks(id TEXT,state TEXT);CREATE TABLE targets(sha256 TEXT);')
    def binary(char,old=True):
        sha=char*64;path=tmp_path/'storage/binaries'/sha[0]/sha[1]/sha
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'cache fixture')
        os.utime(path,(AT-169*3600 if old else AT,)*2)
        return path
    return tmp_path,binary


def test_unused_old_cache_removed_recent_and_submitted_target_kept(cache):
    root,binary=cache;old=binary('a');recent=binary('b',False);submitted=binary('c');target=binary('d')
    with sqlite3.connect(root/'cuckoo.db') as db:
        db.execute("INSERT INTO analyses VALUES ('20261101-ABCDEF','finished')")
        db.execute('INSERT INTO targets VALUES (?)',(target.name,))
    folder=root/'storage/analyses/20261101/ABCDEF';folder.mkdir(parents=True)
    (folder/'analysis.json').write_text(json.dumps({'id':'20261101-ABCDEF','submitted':{'sha256':submitted.name}}))
    (folder/'binary').symlink_to(submitted)
    assert prune(root,AT)['deleted']==1
    assert not old.exists() and all(p.exists() for p in (recent,submitted,target))


def test_running_analysis_or_missing_inventory_never_deletes(cache):
    root,binary=cache;old=binary('a')
    with sqlite3.connect(root/'cuckoo.db') as db:db.execute("INSERT INTO analyses VALUES ('20261101-ABCDEF','running')")
    with pytest.raises(RuntimeError,match='unfinished'):prune(root,AT)
    with sqlite3.connect(root/'cuckoo.db') as db:db.execute("UPDATE analyses SET state='finished'")
    with pytest.raises(RuntimeError,match='documents are missing'):prune(root,AT)
    assert old.exists()


def test_cache_symlink_and_incomplete_submission_are_refused(cache):
    root,binary=cache;old=binary('a');folder=root/'storage/analyses/20261101/ABCDEF';folder.mkdir(parents=True)
    (folder/'binary').symlink_to(old)
    with pytest.raises(RuntimeError,match='Incomplete'):prune(root,AT)
    assert old.exists()
