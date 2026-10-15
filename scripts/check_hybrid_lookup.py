"""Read-only hash endpoint diagnostics, using SHA-256 of empty input."""
import hashlib
import httpx
from app.config import settings
sha=hashlib.sha256(b'').hexdigest()
with httpx.Client(base_url='https://hybrid-analysis.com/api/v2',headers={'api-key':settings.hybrid_analysis_api_key,'User-Agent':'Falcon Sandbox','accept':'application/json'},timeout=20) as c:
    r=c.get('/search/hash',params={'hash':sha})
    print('GET /search/hash:',r.status_code)
    try:
        result=r.json()
        print('Response type:',type(result).__name__)
        if isinstance(result,dict):
            print('Response field names:',sorted(result.keys()))
            for key in ['message','error','error_message']:
                if isinstance(result.get(key),str):
                    print(key+':',result[key].replace(settings.hybrid_analysis_api_key,'[redacted]')[:400])
        elif isinstance(result,list):print('Number of reports:',len(result))
    except ValueError:print('Non-JSON response')
