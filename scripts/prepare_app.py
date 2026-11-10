"""Prepare application dependencies on startup, without provisioning a sandbox."""
import fcntl
from pathlib import Path
import subprocess
import sys
import venv

ROOT = Path(__file__).resolve().parents[1]

def main():
    run = ROOT / '.local/run'
    run.mkdir(parents=True, exist_ok=True)
    with (run / 'setup.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Setup or another startup is preparing dependencies. Wait for it to finish.')
        python = ROOT / '.venv-local/bin/python'
        if not python.exists():
            print('[SETUP] Creating application Python environment', flush=True)
            venv.EnvBuilder(with_pip=True).create(ROOT / '.venv-local')
        subprocess.run([str(python), '-c',
            'import sys;sys.path.insert(0,"scripts");from provision import dependencies;dependencies()'], cwd=ROOT, check=True)
        if not (ROOT / '.env').exists():
            subprocess.run([str(python), 'scripts/configure_local.py'], cwd=ROOT, check=True)
        if '--dev' not in sys.argv:
            # An optional sandbox is independent of the production runtime.
            subprocess.run([str(python),'-c',
                "from dotenv import dotenv_values,set_key;v=dotenv_values('.env');"
                "set_key('.env','SANDBOX_ENABLED','false') if 'SANDBOX_ENABLED' not in v else None"],cwd=ROOT,check=True)

if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print('[ERROR] Application preparation failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
