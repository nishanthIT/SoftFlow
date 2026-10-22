"""Remove a spurious executable-stack flag from the pinned roach x86_64 aPLib.

Modern glibc refuses to load this bundled library. Only its GNU_STACK program
header flag is changed; no executable-stack exception is enabled on the host.
Run inside the separate Cuckoo environment after dependency installation.
"""
import hashlib
from importlib import metadata
from pathlib import Path
import struct

ORIGINAL = 'd9b355d44c4b91d5a7130a005615933c3b9c4eed958724a943f0f95cb6214d6a'


def repair():
    library = Path(metadata.distribution('roach').locate_file('roach/native/components/aplib-64.so'))
    data = bytearray(library.read_bytes())
    if data[:6] != b'\x7fELF\x02\x01':raise RuntimeError('Unexpected aPLib ELF format')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    for index in range(count):
        header = offset + index * size
        kind, flags = struct.unpack_from('<II', data, header)
        if kind != 0x6474e551:continue  # PT_GNU_STACK
        if not flags & 1:
            original=bytearray(data);struct.pack_into('<I',original,header+4,flags|1)
            if hashlib.sha256(original).hexdigest()!=ORIGINAL:raise RuntimeError('Unrecognized patched aPLib library')
            return
        if hashlib.sha256(data).hexdigest() != ORIGINAL:raise RuntimeError('Refusing to modify an unrecognized aPLib library')
        backup=library.with_suffix('.so.original')
        if not backup.exists():backup.write_bytes(data)
        struct.pack_into('<I', data, header + 4, flags & ~1)
        library.write_bytes(data)
        print('Applied pinned aPLib non-executable-stack compatibility fix')
        return
    raise RuntimeError('aPLib has no GNU_STACK header')


if __name__ == '__main__':
    repair()
    from roach.native.aplib import unpack
    assert unpack(b'A\xc0\x00') == b'A', 'aPLib decompression self-check failed'
    print('aPLib import and harmless decompression check passed')
