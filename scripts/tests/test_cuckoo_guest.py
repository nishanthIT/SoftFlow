"""ISO storage/recovery checks using tiny fixtures; no network or VM execution."""
from contextlib import contextmanager
import errno
import hashlib
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cuckoo_guest as guest
import cuckoo_local


@pytest.fixture
def media(tmp_path, monkeypatch):
    data = b'fixture ISO'
    iso = tmp_path / 'windows.iso'
    values = {'CUCKOO_WINDOWS_ISO': str(iso)}
    calls = []
    monkeypatch.setitem(guest.VERSIONS, 'windows_iso_sha1', hashlib.sha1(data).hexdigest())
    monkeypatch.setitem(guest.VERSIONS, 'windows_iso_url', 'https://media.invalid/windows.iso')
    monkeypatch.setattr(guest, 'ISO_CHUNK_BYTES', 4)
    monkeypatch.setattr(guest, 'ISO_SPACE_MARGIN_BYTES', 2)
    monkeypatch.setattr(guest.shutil, 'disk_usage', lambda _: SimpleNamespace(free=1_000))

    def handler(request):
        calls.append(request)
        if request.method == 'HEAD':
            return httpx.Response(200, headers={'content-length': str(len(data)), 'accept-ranges': 'bytes'})
        start, end = map(int, request.headers['range'].removeprefix('bytes=').split('-'))
        return httpx.Response(206, content=data[start:end+1],
                              headers={'content-range': f'bytes {start}-{end}/{len(data)}'})

    original_client = httpx.Client
    transport = httpx.MockTransport(handler)

    def client(**kwargs):
        return original_client(transport=transport, **kwargs)

    @contextmanager
    def stream(*args, **kwargs):
        with client() as connection:
            with connection.stream(*args, **kwargs) as response:
                yield response

    monkeypatch.setattr(guest.httpx, 'Client', client)
    monkeypatch.setattr(guest.httpx, 'stream', stream)
    return SimpleNamespace(data=data, iso=iso, values=values, calls=calls)


def seed_fragments(media):
    parts = media.iso.with_suffix('.parts')
    parts.mkdir()
    for index, offset in enumerate(range(0, len(media.data), 4)):
        (parts / str(index)).write_bytes(media.data[offset:offset+4])
    return parts


def test_low_disk_stops_before_downloading(media, monkeypatch):
    # Enough for the fragments alone, but not for the assembled copy as well.
    monkeypatch.setattr(guest.shutil, 'disk_usage', lambda _: SimpleNamespace(free=len(media.data)+2))
    with pytest.raises(RuntimeError, match='Not enough disk space.*fragments are preserved'):
        guest.download(media.values)
    assert [request.method for request in media.calls] == ['HEAD']
    assert not media.iso.exists()


def test_retry_reclaims_failed_assembly_and_keeps_fragments(media, monkeypatch):
    parts = seed_fragments(media)
    temporary = media.iso.with_suffix('.verified-part')
    temporary.write_bytes(media.data[:5])

    def disk_usage(_):
        assert not temporary.exists(), 'Measure free space after reclaiming the incomplete copy'
        return SimpleNamespace(free=0)

    monkeypatch.setattr(guest.shutil, 'disk_usage', disk_usage)
    with pytest.raises(RuntimeError, match='Not enough disk space'):
        guest.download(media.values)
    assert b''.join((parts / str(i)).read_bytes() for i in range(3)) == media.data
    assert [request.method for request in media.calls] == ['HEAD']


def test_partial_fragment_resume_and_verified_iso_reuse(media):
    parts = media.iso.with_suffix('.parts')
    parts.mkdir()
    (parts / '0').write_bytes(media.data[:4])
    (parts / '1').write_bytes(media.data[4:6])
    guest.download(media.values)
    assert media.iso.read_bytes() == media.data
    assert not parts.exists()
    assert media.iso.with_suffix('.json').is_file()
    assert sorted(r.headers['range'] for r in media.calls if r.method == 'GET') == ['bytes=6-7', 'bytes=8-10']
    media.calls.clear()
    guest.download(media.values)
    assert not media.calls, 'An already verified ISO needs no network access'


def test_space_is_rechecked_after_download(media, monkeypatch):
    checks = iter([1_000, 0])
    monkeypatch.setattr(guest.shutil, 'disk_usage', lambda _: SimpleNamespace(free=next(checks)))
    with pytest.raises(RuntimeError, match='Not enough disk space'):
        guest.download(media.values)
    assert len(list(media.iso.with_suffix('.parts').iterdir())) == 3
    assert not media.iso.exists()
    assert not media.iso.with_suffix('.verified-part').exists()


def test_disk_full_during_assembly_can_resume_without_redownloading(media, monkeypatch):
    parts = seed_fragments(media)
    original_copy = guest.shutil.copyfileobj

    def full_disk(source, destination):
        destination.write(source.read(2))
        raise OSError(errno.ENOSPC, 'No space left on device')

    monkeypatch.setattr(guest.shutil, 'copyfileobj', full_disk)
    with pytest.raises(OSError) as error:
        guest.download(media.values)
    assert error.value.errno == errno.ENOSPC
    assert not media.iso.exists()
    assert len(list(parts.iterdir())) == 3
    assert media.iso.with_suffix('.verified-part').stat().st_size == 2

    monkeypatch.setattr(guest.shutil, 'copyfileobj', original_copy)
    guest.download(media.values)
    assert media.iso.read_bytes() == media.data
    assert all(request.method == 'HEAD' for request in media.calls)


def test_bad_checksum_never_promotes_iso_or_removes_fragments(media):
    parts = seed_fragments(media)
    (parts / '0').write_bytes(b'bad!')
    with pytest.raises(RuntimeError, match='checksum mismatch'):
        guest.download(media.values)
    assert not media.iso.exists()
    assert len(list(parts.iterdir())) == 3


def test_cli_keeps_os_error_details(monkeypatch, capsys):
    def full_disk():
        raise OSError(errno.ENOSPC, 'No space left on device')

    monkeypatch.setattr(cuckoo_local, 'configuration', full_disk)
    monkeypatch.setattr(sys, 'argv', ['cuckoo_guest.py', 'download'])
    with pytest.raises(SystemExit) as error:
        runpy.run_path(guest.__file__, run_name='__main__')
    assert error.value.code == 1
    assert 'Guest setup failed: OSError: [Errno 28] No space left on device' in capsys.readouterr().err
