"""Bounded file I/O; samples are never executed by the application host."""
import hashlib
import io
import struct
from contextlib import contextmanager
from pathlib import Path

@contextmanager
def opened(sample):
    if isinstance(sample,(bytes,bytearray)):
        with io.BytesIO(sample) as f: yield f
    else:
        with Path(sample).open('rb') as f: yield f

def length(sample):
    return len(sample) if isinstance(sample,(bytes,bytearray)) else Path(sample).stat().st_size

def hashes(sample):
    sums={name:hashlib.new(name) for name in ('sha256','sha1','md5')}
    with opened(sample) as f:
        while chunk:=f.read(1024*1024):
            for digest in sums.values(): digest.update(chunk)
    return {name:digest.hexdigest() for name,digest in sums.items()}

def validate(sample):
    size=length(sample)
    with opened(sample) as f:
        header=f.read(64)
        if len(header)<64 or header[:2]!=b'MZ':raise ValueError('Invalid DOS header')
        offset=struct.unpack_from('<I',header,60)[0]
        if offset+24>size:raise ValueError('Invalid PE header offset')
        f.seek(offset);header=f.read(24)
        if header[:4]!=b'PE\0\0':raise ValueError('Invalid PE header')
        characteristics=struct.unpack_from('<H',header,22)[0]
        if not characteristics&2:raise ValueError('PE is not executable')
        if characteristics&0x2000:raise ValueError('DLL submissions are unsupported; submit a Windows EXE')
        if struct.unpack_from('<H',header,4)[0] not in (0x14c,0x8664):raise ValueError('Unsupported executable architecture')

def post(client,url,sample,filename='sample.exe',**kwargs):
    with opened(sample) as f:
        return client.post(url,files={'file':(filename,f,'application/octet-stream')},**kwargs)
