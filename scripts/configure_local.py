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
for key in ['POSTGRES_PASSWORD','REDIS_PASSWORD','AUTH_SECRET','ADMIN_PASSWORD']:
    if not values.get(key) or 'CHANGE_ME' in values[key]:values[key]=secrets.token_hex(24)
values.update({
 'DATABASE_URL':f"postgresql+psycopg://sentinel:{values['POSTGRES_PASSWORD']}@127.0.0.1:55432/sentinel",
 'REDIS_URL':f"redis://:{values['REDIS_PASSWORD']}@127.0.0.1:56379/0",
 'STORAGE_BACKEND':'filesystem','LOCAL_STORAGE_PATH':str(local/'storage'),
 'YARA_PATH':str(root/'yara/rules'),'AI_SIGNATURES_PATH':str(root/'ai-signatures/providers.json'),
 'SECURE_COOKIES':'false','API_PORT':'8100','FRONTEND_PORT':'3100',
 'ALLOWED_ORIGINS':'["http://localhost:3100","http://127.0.0.1:3100"]',
 'API_INTERNAL_URL':'http://127.0.0.1:8100',
})
# Preserve provider keys, external-upload policy and sandbox attestation.
p.write_text(''.join(k+'='+str(v or '')+'\n' for k,v in values.items()));p.chmod(0o600)
print('Configured localhost PostgreSQL, Redis, private filesystem storage, and frontend :3100. Provider keys preserved.')
