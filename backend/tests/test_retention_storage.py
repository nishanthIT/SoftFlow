from datetime import datetime, timezone
import pytest
from app import storage
from app.config import settings

STAMP=datetime(2026,11,1,tzinfo=timezone.utc)

class Paginator:
    def __init__(self, pages): self.pages=pages
    def paginate(self, **kwargs): return iter(self.pages)

class Bucket:
    def __init__(self): self.deleted=[]; self.aborted=[]; self.fail=False
    def get_paginator(self, operation):
        if operation=='list_multipart_uploads':
            return Paginator([{'Uploads':[{'Key':'tmp/old','UploadId':'1','Initiated':STAMP}]}])
        return Paginator([
            {'Versions':[{'Key':'reports/job.json','VersionId':'older','LastModified':STAMP}]},
            {'Versions':[{'Key':'reports/job.json','VersionId':'newer','LastModified':STAMP}],
             'DeleteMarkers':[{'Key':'reports/job.json','VersionId':'marker','LastModified':STAMP},
                              {'Key':'reports/job.json.extra','VersionId':'keep','LastModified':STAMP}]}])
    def delete_objects(self, **kwargs):
        self.deleted.extend(kwargs['Delete']['Objects'])
        return {'Errors':[{'Code':'AccessDenied'}]} if self.fail else {}
    def abort_multipart_upload(self, **kwargs): self.aborted.append(kwargs)

@pytest.fixture
def bucket(monkeypatch):
    monkeypatch.setattr(settings,'storage_backend','s3')
    b=Bucket();monkeypatch.setattr(storage,'client',lambda:b)
    return b


def test_deletes_every_version_and_marker_but_not_similar_key(bucket):
    storage.delete('reports/job.json')
    assert {v['VersionId'] for v in bucket.deleted}=={'older','newer','marker'}
    assert all(v['Key']=='reports/job.json' for v in bucket.deleted)


def test_partial_s3_delete_errors_are_not_treated_as_success(bucket):
    bucket.fail=True
    with pytest.raises(RuntimeError): storage.delete('reports/job.json')


def test_inventory_includes_deleted_versions_for_orphan_cleanup(bucket):
    assert list(storage.objects('reports/'))==[('reports/job.json',STAMP),('reports/job.json.extra',STAMP)]


def test_abandoned_multipart_cleanup_protects_owned_uploads(bucket):
    storage.abort_abandoned_uploads(STAMP, lambda key:True)
    assert not bucket.aborted
    storage.abort_abandoned_uploads(STAMP, lambda key:False)
    assert bucket.aborted


def test_orphan_age_uses_newest_version_across_pages(bucket):
    from datetime import timedelta
    recent=STAMP+timedelta(days=7)
    bucket.get_paginator=lambda operation:Paginator([
        {'Versions':[{'Key':'samples/hash','VersionId':'new','LastModified':recent}]},
        {'Versions':[{'Key':'samples/hash','VersionId':'old','LastModified':STAMP}]}])
    assert list(storage.objects('samples/'))==[('samples/hash',recent)]
