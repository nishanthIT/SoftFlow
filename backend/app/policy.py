import json
import re
from urllib.parse import urlsplit
from .config import settings

def host(value):
    try: return (urlsplit(value if '://' in value else '//'+value).hostname or '').lower().rstrip('.')
    except ValueError: return ''
def domain_match(value, domain):
    h = host(value)
    return h == domain or h.endswith('.'+domain)

def network(sandbox):
    if sandbox.get('source') == 'cuckoo3':
        from .cuckoo3_results import network as normalize
        return normalize(sandbox)
    raw = sandbox.get('report',{}).get('network')
    if not isinstance(raw,dict) or not any(k in raw for k in ['dns','http','https','tcp','udp']): return None
    events=[]
    for d in raw.get('dns',[]): events.append({'type':'dns','domain':d.get('request'),'answers':d.get('answers',[]),'source':'sandbox'})
    for proto in ['http','https']:
        for r in raw.get(proto,[]): events.append({'type':proto,'host':r.get('host'),'url':r.get('uri') or r.get('url'),'method':r.get('method'),'source':'sandbox'})
    for proto in ['tcp','udp']:
        for r in raw.get(proto,[]): events.append({'type':proto,'ip':r.get('dst'),'port':r.get('dport'),'source':'sandbox'})
    return {'events':events,'domains':sorted({str(e.get('domain') or e.get('host')) for e in events if e.get('domain') or e.get('host')}),
            'ips':sorted({str(e['ip']) for e in events if e.get('ip')}),'capture_scope':'Sandbox report metadata; encrypted request bodies are not available'}

def behavior(sandbox):
    if sandbox.get('source') == 'cuckoo3':
        from .cuckoo3_results import behavior as normalize
        return normalize(sandbox)
    report = sandbox.get('report',{})
    if 'behavior' not in report: return None
    b = report['behavior']; events=[]
    if not b.get('processes') and not b.get('summary'): return None
    # Only observed API calls and summary events, never static imports.
    mapping={'CreateRemoteThread':('process_injection','high','T1055'),'WriteProcessMemory':('process_injection','medium','T1055'),'RegSetValueExW':('registry_modification','low',None),'CreateFileW':('file_manipulation','low',None),'CreateProcessInternalW':('execution','low',None)}
    for p in b.get('processes',[]):
        for call in p.get('calls',[]):
            api = call.get('api')
            if api in mapping:
                cat,severity,mitre=mapping[api]
                events.append({'category':cat,'severity':severity,'source':'sandbox','evidence':api+' observed','timestamp':call.get('timestamp'),'process':p.get('process_name'),'technique':mitre})
    return {'events':events[:10000],'processes':b.get('processes',[]),'process_tree':b.get('processtree',[]),'summary':b.get('summary',{}),'signatures':report.get('signatures',[]),'dropped_files':report.get('dropped',[]),'screenshots':report.get('screenshots',[])}

def ai_detect(static, net, static_ok, network_ok, observed_behavior=None):
    providers=json.loads(open(settings.ai_signatures_path).read())['providers']
    strings=static.get('strings',[]); indicators=[]
    for p in providers:
        for s in strings:
            for marker in p['domains']+p['sdk']:
                if marker.lower() in s.lower():
                    indicators.append({'provider':p['name'],'type':'STATIC_INDICATOR' if marker in p['domains'] else ('MODEL_FILE_DETECTED' if marker.startswith('.') else 'SDK_DETECTED'),'source':'static','evidence':s[:500]})
        for e in net.get('events',[]):
            value=e.get('host') or e.get('domain') or e.get('url') or ''
            if any(domain_match(value,d) for d in p['domains']):
                endpoint=e.get('url') or ''
                is_api=e['type'] in ['http','https'] and any(x.lower() in endpoint.lower() for x in p['endpoints'])
                indicators.append({'provider':p['name'],'type':'API_ENDPOINT_OBSERVED' if is_api else 'RUNTIME_CONNECTION' if e['type'] in ['http','https'] else 'DNS_OBSERVED','source':'sandbox','evidence':e})
    for process in (observed_behavior or {}).get('processes',[]):
        for call in process.get('calls',[]):
            if call.get('api') in ['OrtRun','llama_decode','TF_SessionRun']:
                indicators.append({'provider':'Local inference','type':'LOCAL_INFERENCE','source':'sandbox','evidence':{'api':call['api'],'process':process.get('process_name'),'timestamp':call.get('timestamp')}})
    for event in net.get('events',[]):
        if event.get('type') in ['http','https'] and host(event.get('host') or event.get('url') or '') in ['localhost','127.0.0.1','::1']:
            if any(path in (event.get('url') or '') for path in ['/api/generate','/api/chat']):
                indicators.append({'provider':'Local inference','type':'API_ENDPOINT_OBSERVED','source':'sandbox','evidence':event})
    confirmed=any(i['type'] in ['API_ENDPOINT_OBSERVED','LOCAL_INFERENCE'] for i in indicators)
    runtime=any(i['type'] in ['RUNTIME_CONNECTION','DNS_OBSERVED'] for i in indicators)
    status='DETECTED' if confirmed else 'SUSPECTED' if runtime else 'STATIC_INDICATOR_ONLY' if indicators else 'NOT_OBSERVED' if static_ok and network_ok else 'INCONCLUSIVE'
    return {'status':status,'confidence':'HIGH' if confirmed else 'MEDIUM' if runtime else 'LOW','providers':sorted({i['provider'] for i in indicators}), 'indicators':indicators[:1000],
            'limitations':'Static strings and SDKs do not prove usage. DNS alone does not prove an API call. Encrypted traffic and local model execution may be unobservable. Model and request content are not inferred.'}

def verdict(results):
    from .approval import criteria
    reasons=[]; score=0
    def add(points,source,evidence):
        nonlocal score
        score+=points; reasons.append({'points':points,'source':source,'evidence':evidence})
    vt=results.get('virustotal',{}).get('data',{}); stats=vt.get('stats',{})
    malicious=stats.get('malicious',0)
    if malicious>=5: add(70,'virustotal',f'{malicious} engines classified malicious')
    elif malicious: add(30,'virustotal',f'{malicious} engines classified malicious')
    if stats.get('suspicious',0): add(10,'virustotal','Suspicious provider detections')
    ha=results.get('hybrid-analysis',{}).get('data',{})
    if ha.get('verdict')=='malicious': add(60,'hybrid-analysis','Provider verdict: malicious')
    elif ha.get('verdict')=='suspicious': add(25,'hybrid-analysis','Provider verdict: suspicious')
    yara=results.get('yara',{}).get('data',{}).get('matches',[])
    if yara: add(25,'yara',{'rules':[m['rule'] for m in yara]})
    high=[e for e in results.get('behavior',{}).get('data',{}).get('events',[]) if e['severity']=='high']
    if high: add(30,'behavior',high[:10])
    sandbox=results.get('sandbox',{})
    if sandbox.get('status')=='COMPLETED' and sandbox.get('data',{}).get('source')=='cuckoo3':
        scores=[item.get('post',{}).get('score',0) for item in sandbox['data'].get('report',{}).get('tasks',[])]
        severity=max((s for s in scores if isinstance(s,(int,float))),default=0)
        if severity>=9: add(70,'sandbox',f'Cuckoo 3 reported score {severity}/10')
        elif severity>=6: add(30,'sandbox',f'Cuckoo 3 reported score {severity}/10')
        elif severity>0: add(10,'sandbox',f'Cuckoo 3 reported score {severity}/10; review low-severity findings')
    required=['static','yara','sandbox','behavior','network']+(['virustotal'] if settings.approval_require_reputation else [])
    coverage=all(results.get(k,{}).get('status')=='COMPLETED' for k in required)
    trusted_clean=not settings.approval_require_reputation or stats.get('harmless',0)+stats.get('undetected',0)>=settings.approval_min_reputation_engines
    state='LIKELY_MALICIOUS' if score>=60 else 'SUSPICIOUS' if score>=20 else 'LIKELY_BENIGN' if coverage and trusted_clean else 'INCONCLUSIVE'
    gaps=[{'engine':k,'status':v['status'],'reason':v.get('reason')} for k,v in results.items() if k not in ['verdict','report'] and v['status']!='COMPLETED']
    return {'security':state,'score':min(score,100),'confidence':'MEDIUM' if state!='INCONCLUSIVE' else 'LOW','reasons':reasons,'coverage_gaps':gaps,'approval_policy':criteria(),
            'policy_version':'1.1','ai':results.get('ai',{}).get('data',{}),'explanation':'No adverse evidence is not proof of safety or absence of vulnerabilities. Incomplete required analysis cannot yield a likely-benign verdict. AI indicators never increase the security score.'}
