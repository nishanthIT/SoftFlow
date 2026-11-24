"""Build an immutable frontend release before replacing a running application."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import re
import time
from contextlib import contextmanager

ROOT=Path(__file__).resolve().parents[1]

def source_signature(values):
    digest=hashlib.sha256()
    frontend=ROOT/'frontend'
    paths=list((frontend/'src').rglob('*'))+list((frontend/'public').rglob('*'))
    paths += [frontend/name for name in ['package.json','package-lock.json','next.config.ts','tsconfig.json','postcss.config.mjs']]
    for path in sorted(p for p in paths if p.is_file()):
        digest.update(str(path.relative_to(frontend)).encode())
        if path.name=='tsconfig.json':
            config=json.loads(path.read_text())
            config['include']=[item for item in config.get('include',[]) if not item.startswith('.next')]
            digest.update(json.dumps(config,sort_keys=True).encode())
        else:digest.update(path.read_bytes())
    digest.update(values['API_INTERNAL_URL'].encode())
    digest.update(subprocess.check_output(['node','--version']))
    digest.update(Path(__file__).read_bytes())
    return digest.hexdigest()[:24]


@contextmanager
def build_types(frontend, relative):
    """Next rewrites these tracked files; always restore the user's exact bytes."""
    config_path=frontend/'tsconfig.json'
    paths=(config_path,frontend/'next-env.d.ts')
    original={path:path.read_bytes() if path.exists() else None for path in paths}
    try:
        config=json.loads(original[config_path])
        config['include']=[entry for entry in config.get('include',[]) if not entry.startswith('.next')]
        config['include'].append(relative+'/types/**/*.ts')
        config_path.write_text(json.dumps(config,indent=2)+'\n')
        yield
    finally:
        for path,content in original.items():
            if content is None:path.unlink(missing_ok=True)
            else:path.write_bytes(content)


def frontend_release(values):
    frontend=ROOT/'frontend';signature=source_signature(values)
    relative='.next-releases/'+signature;release=frontend/relative
    server=release/'standalone/server.js'
    marker=release/'release.json'
    if not (server.is_file() and marker.is_file() and (release/'BUILD_ID').is_file()):
        print('[BUILD] Compiling production frontend; the current release remains available',flush=True)
        marker.unlink(missing_ok=True)
        env={**os.environ,'NODE_ENV':'production','NEXT_TELEMETRY_DISABLED':'1',
             'API_INTERNAL_URL':values['API_INTERNAL_URL'],'NEXT_DIST_DIR':relative}
        with build_types(frontend,relative):
            subprocess.run(['npm','run','build'],cwd=frontend,env=env,check=True)
        if not server.is_file():
            raise RuntimeError('Frontend build did not create '+str(server)+'. Check outputFileTracingRoot in frontend/next.config.ts; it must point to the frontend directory.')
        shutil.copytree(release/'static',release/'standalone'/relative/'static',dirs_exist_ok=True)
        if (frontend/'public').is_dir():shutil.copytree(frontend/'public',release/'standalone/public',dirs_exist_ok=True)
        marker.write_text(json.dumps({'source':signature,'api':values['API_INTERNAL_URL']}))
    return server,signature

def prune_releases(current):
    directory=ROOT/'frontend/.next-releases'
    releases=[p for p in directory.iterdir() if p.is_dir() and not p.is_symlink() and re.fullmatch(r'[0-9a-f]{24}',p.name)]
    complete=sorted((p for p in releases if (p/'release.json').is_file()),key=lambda p:(p/'release.json').stat().st_mtime,reverse=True)
    keep={current,*[p.name for p in complete[:2]]}
    for path in releases:
        if path.name not in keep and ((path/'release.json').is_file() or path.stat().st_mtime<time.time()-86400):shutil.rmtree(path)
