"""Reuse an installed Cuckoo without provisioning guests or changing networks."""
import configparser
import os
from pathlib import Path
import shutil
import socket
from urllib.parse import urlsplit


def configure(values, root):
    """Resolve runtime-only settings. Never rewrite the operator's .env/Cuckoo files."""
    if values.get('CUCKOO_MODE', 'existing') != 'existing' or values.get('SANDBOX_ENABLED','true').lower()=='false':
        return
    binary = values.get('CUCKOO_BINARY') or shutil.which('cuckoo')
    installed = Path.home()/'.venvs/cuckoo/bin/cuckoo'
    if not binary and installed.is_file(): binary = str(installed)
    cwd = Path(values.get('CUCKOO_CWD') or '~/.cuckoo').expanduser()
    if not cwd.is_absolute(): cwd = root / cwd
    conf = configparser.ConfigParser(interpolation=None)
    legacy = cwd / 'conf/cuckoo.conf'
    if legacy.is_file(): conf.read(legacy)
    kind = values.get('SANDBOX_KIND')
    if not kind:
        kind = 'cuckoo' if legacy.is_file() else 'cuckoo3' if (cwd/'conf/cuckoo.yaml').is_file() else 'cuckoo'
    if kind not in ('cuckoo', 'cuckoo3'):
        raise RuntimeError('Existing mode requires SANDBOX_KIND=cuckoo or cuckoo3. CAPE is not needed.')
    values['SANDBOX_KIND'] = kind
    values.setdefault('CUCKOO_API_URL', 'http://127.0.0.1:8090')
    if not values['CUCKOO_API_URL']: values['CUCKOO_API_URL'] = 'http://127.0.0.1:8090'
    if not values.get('CUCKOO_API_TOKEN') and kind == 'cuckoo':
        values['CUCKOO_API_TOKEN'] = conf.get('cuckoo', 'api_token', fallback='').strip()
    values['CUCKOO_CWD'] = str(cwd)
    if binary: values['CUCKOO_BINARY'] = str(Path(binary).expanduser().absolute())
    values.setdefault('SANDBOX_ENABLED', 'true')
    values.setdefault('CUCKOO_REQUIRED', 'true')
    # Existing service cache/VM state belongs to its operator, not app retention.
    values['CUCKOO_AUTO_START'] = 'false'


def child_environment(binary):
    allowed = ('HOME', 'USER', 'LOGNAME', 'PATH', 'LANG', 'LC_ALL', 'TMPDIR', 'XDG_RUNTIME_DIR')
    result = {k: os.environ[k] for k in allowed if k in os.environ}
    result['PATH'] = str(Path(binary).parent) + os.pathsep + result.get('PATH', os.defpath)
    result['PYTHONUNBUFFERED'] = '1'
    return result


def core_running(cwd):
    """Cuckoo 2 writes cwd/pidfiles/cuckoo.pid. Verify PID identity, not just file existence."""
    try:
        pid = int((cwd/'pidfiles/cuckoo.pid').read_text().strip())
        if pid <= 1: return False
        command = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        return any(Path(os.fsdecode(arg)).name == 'cuckoo' for arg in command if arg) and b'api' not in command
    except (OSError, ValueError): return False


def start_existing(manager):
    values = manager.values
    from app.config import settings
    from app.provider_status import check
    for name in ('cuckoo_api_url', 'cuckoo_api_token', 'sandbox_kind'):
        setattr(settings, name, values.get(name.upper(), getattr(settings, name)))
    settings.sandbox_enabled = values.get('SANDBOX_ENABLED', 'true').lower() == 'true'
    settings.sandbox_isolation_confirmed = values.get('SANDBOX_ISOLATION_CONFIRMED', 'false').lower() == 'true'
    initial = check('sandbox', refresh=True)
    restart_core = values['SANDBOX_KIND']=='cuckoo' and initial.get('core_running') is False
    if initial['status'] in ('CONNECTED', 'ISOLATION_REQUIRED', 'NO_ANALYSIS_MACHINE') and not restart_core:
        manager.message('CUCKOO', 'Connected to existing Cuckoo API; preserving its services and configuration')
        return initial
    url = urlsplit(values['CUCKOO_API_URL'])
    # Only launch if the local port is closed. An auth error or a different service
    # on that port must never trigger a second Cuckoo process.
    local = url.scheme == 'http' and url.hostname in ('127.0.0.1', 'localhost') and url.path in ('', '/')
    if not local or values.get('CUCKOO_START_EXISTING', 'true').lower() != 'true': return initial
    launch_api = not restart_core and initial['status'] != 'CORE_NOT_READY'
    if launch_api:
        try:
            with socket.create_connection((url.hostname, url.port or 80), timeout=1): return initial
        except ConnectionRefusedError: pass
        except OSError: return initial
    binary = values.get('CUCKOO_BINARY')
    cwd = Path(values['CUCKOO_CWD'])
    if not binary or not Path(binary).is_file():
        raise RuntimeError('Existing Cuckoo executable not found. Activate its environment before ./start or set CUCKOO_BINARY to its absolute path. No sandbox was installed or changed.')
    config = cwd/'conf'/('cuckoo.conf' if values['SANDBOX_KIND']=='cuckoo' else 'cuckoo.yaml')
    if not config.is_file(): raise RuntimeError('CUCKOO_CWD does not contain the existing Cuckoo configuration. Set its correct path; startup will not initialize or overwrite it.')
    if values['SANDBOX_KIND']=='cuckoo3':
        raise RuntimeError('Start your existing Cuckoo 3 core/API service, or use CUCKOO_MODE=managed for the repository-managed installation. Existing mode never launches a duplicate Cuckoo 3 core.')
    prefix = [binary, '--cwd', str(cwd)]
    process_env = child_environment(binary)
    if not core_running(cwd): manager.start('cuckoo-core', prefix, process_env=process_env)
    if launch_api: manager.start('cuckoo-api', prefix+['api', '--host', '127.0.0.1', '--port', str(url.port or 80)], process_env=process_env)
    import time
    deadline = time.monotonic()+int(values.get('CUCKOO_STARTUP_TIMEOUT', '60'))
    result = initial
    while time.monotonic() < deadline:
        result = check('sandbox', refresh=True)
        if result.get('execution_ready'): return result
        if result['status'] in ('ISOLATION_REQUIRED', 'API_TOKEN_REQUIRED', 'INVALID_API_TOKEN', 'INVALID_REQUEST', 'INVALID_API_KEY', 'ACCESS_DENIED'): return result
        for name in ('cuckoo-api', 'cuckoo-core'):
            if name in manager.state and not manager.alive(manager.state[name]):
                raise RuntimeError(name+' exited; inspect .local/logs/'+name+'.log. Existing network and guest configuration were preserved.')
        time.sleep(.5)
    return result
