"""Build an immutable frontend release before replacing a running application."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import re
import time

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
    return digest.hexdigest()[:24]

def frontend_release(values):
    frontend=ROOT/'frontend';signature=source_signature(values)
    relative='.next-releases/'+signature;release=frontend/relative
    server=release/'standalone/server.js'
    marker=release/'release.json'
    if not (server.is_file() and marker.is_file() and (release/'BUILD_ID').is_file()):
        print('[BUILD] Compiling production frontend; the current release remains available',flush=True)
        # Typecheck only this release's routes. Previous builds may reference
        # pages that have since been removed from the source tree.
        config_path=frontend/'tsconfig.json';config=json.loads(config_path.read_text())
        config['include']=[entry for entry in config.get('include',[]) if not entry.startswith('.next')]
        config['include'].append(relative+'/types/**/*.ts')
        config_path.write_text(json.dumps(config,indent=2)+'\n')
        env={**os.environ,'NODE_ENV':'production','NEXT_TELEMETRY_DISABLED':'1',
             'API_INTERNAL_URL':values['API_INTERNAL_URL'],'NEXT_DIST_DIR':relative}
        subprocess.run(['npm','run','build'],cwd=frontend,env=env,check=True)
        if not server.is_file():raise RuntimeError('Next.js standalone server was not generated')
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
