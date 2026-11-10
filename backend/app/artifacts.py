"""Stream verified sandbox artifacts into the analysis-owned retention namespace."""
import hashlib
import re
import time
from . import storage
from .config import settings


def collect(client, job_id, analysis_id, report):
    saved, errors = [], []
    # post.json names are untrusted; never turn arbitrary report URLs into fetches.
    for item in report.get('tasks', []):
        task_id = item['task']['id']
        files = [('pcap', 'capture.pcap', 'application/vnd.tcpdump.pcap')]
        for screenshot in item.get('post', {}).get('screenshot', []):
            name = screenshot.get('name', '') if isinstance(screenshot, dict) else ''
            if re.fullmatch(r'[0-9]{1,14}\.(jpg|png)', name):
                files.append(('screenshot/' + name, name, 'image/png' if name.endswith('.png') else 'image/jpeg'))
        for route, filename, content_type in files:
            key = f'artifacts/{job_id}/{task_id}/{filename}'
            try:
                deadline = time.monotonic() + settings.request_timeout * 4
                with client.stream('GET', f'analysis/{analysis_id}/task/{task_id}/{route}') as response:
                    response.raise_for_status()
                    length = response.headers.get('content-length')
                    if length and int(length) > settings.sandbox_artifact_max_bytes:
                        raise ValueError('Artifact exceeds configured storage limit')
                    digest = hashlib.sha256(); size = 0; signature = bytearray()
                    with storage.scratch() as (out, path):
                        for chunk in response.iter_bytes(1024 * 1024):
                            size += len(chunk)
                            if size > settings.sandbox_artifact_max_bytes or time.monotonic() > deadline:
                                raise ValueError('Artifact exceeds size or transfer deadline')
                            storage.require_space(len(chunk))
                            if len(signature)<8:signature.extend(chunk[:8-len(signature)])
                            out.write(chunk); digest.update(chunk)
                        out.flush()
                        if not size: raise ValueError('Empty artifact')
                        if route=='pcap' and bytes(signature[:4]) not in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d',b'\x0a\x0d\x0d\x0a'):
                            raise ValueError('Artifact is not a packet capture')
                        if route.startswith('screenshot/') and not (bytes(signature).startswith(b'\x89PNG\r\n\x1a\n') or bytes(signature).startswith(b'\xff\xd8\xff')):
                            raise ValueError('Artifact is not a supported screenshot')
                        storage.put_file(key, path, content_type)
                saved.append({'task_id': task_id, 'name': filename, 'kind': route.split('/')[0],
                              'size': size, 'sha256': digest.hexdigest(), 'object_key': key,
                              'download_url': f'/api/analysis/{job_id}/artifacts/{task_id}/{filename}'})
            except Exception as error:
                # Parsed telemetry remains usable, but absence of downloadable
                # artifacts is explicit. No response body or credential is logged.
                errors.append({'task_id': task_id, 'name': filename, 'error': type(error).__name__})
    return {'files': saved, 'errors': errors}
