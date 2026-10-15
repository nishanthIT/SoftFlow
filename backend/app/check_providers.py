"""Read-only credential checks. Never prints keys or account response bodies."""
import httpx
from .config import settings

def main():
    checks=[
        ('VirusTotal',settings.virustotal_api_key,'https://www.virustotal.com/api/v3/users/'+settings.virustotal_api_key,{'x-apikey':settings.virustotal_api_key}),
        ('Hybrid Analysis',settings.hybrid_analysis_api_key,'https://hybrid-analysis.com/api/v2/key/current',{'api-key':settings.hybrid_analysis_api_key,'User-Agent':'Falcon Sandbox','accept':'application/json'}),
    ]
    for name,key,url,headers in checks:
        if not key:
            print(name+': NOT CONFIGURED',flush=True)
            continue
        try:
            response=httpx.get(url,headers=headers,timeout=20)
            if response.status_code==200:
                print(name+': credentials accepted (HTTP 200)',flush=True)
            else:
                print(name+': credential check returned HTTP '+str(response.status_code),flush=True)
        except httpx.RequestError as e:
            print(name+': connection check failed ('+type(e).__name__+')',flush=True)
    print('No samples or sample hashes were submitted.',flush=True)

if __name__=='__main__': main()
