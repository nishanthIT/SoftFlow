"""Remove only recorded, finished sandbox tasks through their owning service."""
import hashlib
import re
import httpx
from .config import settings


class SandboxStillActive(Exception): pass


def endpoint_identity():
    return hashlib.sha256(settings.cuckoo_api_url.rstrip('/').encode()).hexdigest()


def delete_analysis(data, sha256):
    task=data.get('task_id')
    if not task:
        if data.get('phase') == 'submission_pending':
            raise RuntimeError('Sandbox submission outcome is unknown')
        return
    kind=data.get('provider') or data.get('source')
    if kind not in ('cape', 'cuckoo', 'cuckoo3') or kind != settings.sandbox_kind:
        raise RuntimeError('Sandbox ownership configuration changed')
    if not settings.cuckoo_api_url:
        raise RuntimeError('Sandbox cleanup endpoint is unavailable')
    if data.get('endpoint_identity', endpoint_identity()) != endpoint_identity():
        raise RuntimeError('Sandbox cleanup endpoint changed')
    task=str(task)
    if not re.fullmatch(r'\d{8}-[A-Z0-9]{6}' if kind=='cuckoo3' else r'[1-9]\d*', task):
        raise ValueError('Invalid sandbox analysis identifier')
    view=f'analysis/{task}' if kind=='cuckoo3' else f'tasks/view/{task}'+('/' if kind=='cape' else '')
    delete=f'analysis/{task}/deleteanalysis' if kind=='cuckoo3' else f'tasks/delete/{task}'+('/' if kind=='cape' else '')
    with httpx.Client(base_url=settings.cuckoo_api_url.rstrip('/')+'/',
                      headers={'Authorization':('Bearer ' if kind=='cuckoo' else 'Token ')+settings.cuckoo_api_token},
                      timeout=settings.request_timeout) as client:
        response=client.get(view)
        if response.status_code==404: return
        response.raise_for_status()
        payload=response.json()
        # CAPE returns HTTP 200 even for a missing task. Do not confuse disabled
        # APIs, permission errors or transport failures with successful cleanup.
        if kind=='cape' and payload.get('error_value')=='Task not found in database': return
        if payload.get('error'): raise RuntimeError('Sandbox status check failed')
        detail=payload if kind=='cuckoo3' else payload.get('data' if kind=='cape' else 'task', {})
        if str(detail.get('id')) != task: raise ValueError('Sandbox identity mismatch')
        status=detail.get('state' if kind=='cuckoo3' else 'status')
        terminal={'finished','fatal_error','no_selected'} if kind=='cuckoo3' else {'reported','failed_analysis','failed_processing','failed_reporting','failed_machine'}
        if status not in terminal: raise SandboxStillActive('Sandbox task is not finished')
        if kind=='cuckoo3' and any(t.get('state') not in ('reported','fatal_error') for t in detail.get('tasks', [])):
            raise SandboxStillActive('Sandbox execution task is not finished')
        fingerprint=(detail.get('submitted') if kind=='cuckoo3' else detail.get('sample')) or {}
        if fingerprint.get('sha256', '').lower()!=sha256:
            raise ValueError('Sandbox sample hash mismatch')
        response=client.get(delete)
        if response.status_code==404:
            # A missing deletion route is not evidence that artifacts vanished.
            check=client.get(view)
            if check.status_code==404: return
            check.raise_for_status()
            if kind=='cape' and check.json().get('error_value')=='Task not found in database': return
            raise RuntimeError('Sandbox deletion endpoint is unavailable')
        response.raise_for_status()
        if response.content and response.json().get('error'):
            raise RuntimeError('Sandbox deletion failed')
        verify=client.get(view)
        if verify.status_code==404:return
        verify.raise_for_status()
        if kind=='cape' and verify.json().get('error_value')=='Task not found in database':return
        raise RuntimeError('Sandbox deletion was not confirmed; analysis remains available')
