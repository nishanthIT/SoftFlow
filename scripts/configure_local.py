"""Configure the existing .env for local services. Never prints credentials."""
from pathlib import Path
from dotenv import dotenv_values
import json,secrets,shutil
root=Path(__file__).resolve().parents[1]
local=root/'.local';local.mkdir(exist_ok=True,mode=0o700)
p=root/'.env'
if p.exists() and not (local/'.env.before-local').exists():
    shutil.copyfile(p,local/'.env.before-local');(local/'.env.before-local').chmod(0o600)
values=dict(dotenv_values(p if p.exists() else root/'.env.example'))
api_port=values.get('API_PORT') or '8100';frontend_port=values.get('FRONTEND_PORT') or '3100'
pg_port=values.get('LOCAL_POSTGRES_PORT') or '55432';redis_port=values.get('LOCAL_REDIS_PORT') or '56379'
for key in ['POSTGRES_PASSWORD','REDIS_PASSWORD']:
    if not values.get(key) or 'CHANGE_ME' in values[key]:values[key]=secrets.token_hex(24)
values.update({
 'DATABASE_URL':f"postgresql+psycopg://sentinel:{values['POSTGRES_PASSWORD']}@127.0.0.1:{pg_port}/sentinel",
 'REDIS_URL':f"redis://:{values['REDIS_PASSWORD']}@127.0.0.1:{redis_port}/0",
 'STORAGE_BACKEND':'filesystem','LOCAL_STORAGE_PATH':str(local/'storage'),
 'YARA_PATH':str(root/'yara/rules'),'AI_SIGNATURES_PATH':str(root/'ai-signatures/providers.json'),
 'API_PORT':api_port,'FRONTEND_PORT':frontend_port,
 'LOCAL_POSTGRES_PORT':pg_port,'LOCAL_REDIS_PORT':redis_port,
 'ALLOWED_ORIGINS':values.get('ALLOWED_ORIGINS') or '[]',
 'FRONTEND_HOST':values.get('FRONTEND_HOST') or '0.0.0.0',
 'API_INTERNAL_URL':f'http://127.0.0.1:{api_port}',
})
# Preserve provider keys, external-upload policy and sandbox attestation.
p.write_text(''.join(k+'='+str(v or '')+'\n' for k,v in values.items()));p.chmod(0o600)
print(f'Configured private local services and LAN frontend :{frontend_port}. Provider keys preserved.')
