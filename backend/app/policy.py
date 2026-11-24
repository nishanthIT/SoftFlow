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

def monitoring(result):
    if result is None:return None
    return {**result,'monitoring_status':'OPERATIONAL','traffic_status':'OBSERVED' if result['events'] else 'NO_TRAFFIC_OBSERVED',
            'network_policy':settings.sandbox_network_policy,
            'policy_note':'External network access is intentionally blocked by the configured sandbox policy.' if settings.sandbox_network_policy=='blocked' else 'Network restrictions are determined by the configured sandbox.'}

def dns(net):
    if not net or not net.get('dns_available'):return None
    queries=[e for e in net['events'] if e['type']=='dns']
    responses=[e for e in net['events'] if e['type']=='dns_response']
    for query in queries:
        responses.extend({'domain':query.get('domain'),'source':query.get('source'),'answer':answer} for answer in query.get('answers',[]))
    return {'queries':queries,'responses':responses,'monitoring_status':'OPERATIONAL',
            'traffic_status':'OBSERVED' if queries or responses else 'NO_DNS_OBSERVED',
            'network_policy':net['network_policy'],'events_truncated':net.get('events_truncated',False),
            'limitations':'Only captured DNS is shown. Responses are not attributed to a query unless the source supplies that association.'}

def network(sandbox):
    if sandbox.get('source') == 'cuckoo3':
        from .cuckoo3_results import network as normalize
        return monitoring(normalize(sandbox))
    raw = sandbox.get('report',{}).get('network')
    if not isinstance(raw,dict) or not any(k in raw for k in ['dns','http','https','tcp','udp']): return None
    events=[]
    for d in raw.get('dns',[]): events.append({'type':'dns','domain':d.get('request'),'answers':d.get('answers',[]),'source':'sandbox'})
    for proto in ['http','https']:
        for r in raw.get(proto,[]): events.append({'type':proto,'host':r.get('host'),'url':r.get('uri') or r.get('url'),'method':r.get('method'),'source':'sandbox'})
    for proto in ['tcp','udp']:
        for r in raw.get(proto,[]): events.append({'type':proto,'ip':r.get('dst'),'port':r.get('dport'),'source':'sandbox'})
    return monitoring({'events':events,'domains':sorted({str(e.get('domain') or e.get('host')) for e in events if e.get('domain') or e.get('host')}),
            'ips':sorted({str(e['ip']) for e in events if e.get('ip')}),'dns_available':isinstance(raw.get('dns'),list),
            'capture_scope':'Sandbox report metadata; encrypted request bodies are not available'})

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
    status='DETECTED' if confirmed else 'SUSPECTED' if runtime else 'STATIC_INDICATOR_ONLY' if indicators else 'NOT_OBSERVED' if static_ok and network_ok else 'PARTIAL'
    return {'status':status,'confidence':'HIGH' if confirmed else 'MEDIUM' if runtime else 'LOW','providers':sorted({i['provider'] for i in indicators}), 'indicators':indicators[:1000],
            'limitations':'Static strings and SDKs do not prove usage. DNS alone does not prove an API call. Encrypted traffic and local model execution may be unobservable. Model and request content are not inferred.'}

def verdict(results):
    from .approval import criteria
    from .detection_policy import assess
    decision=assess(results)
    state=decision['security']
    reasons=[{'source':entry['source'],'points':0,'evidence':f"{entry['count']} {entry['basis']}"} for entry in decision['detection_sources']]
    reasons.extend({'source':'correlation','points':0,'evidence':message} for message in decision['review_reasons'])
    gaps=[{'engine':name,'status':row['status'],'reason':row.get('reason')} for name,row in results.items()
          if name not in ('verdict','report') and row['status']!='COMPLETED']
    assessment=results.get('vulnerabilities',{}).get('data',{})
    affected=[f for f in assessment.get('findings',[]) if f.get('classification')=='CONFIRMED_AFFECTED']
    vulnerability_risk='CONFIRMED_AFFECTED' if affected else 'UNCERTAIN' if assessment.get('status')!='COMPLETED' or any(f.get('classification')!='NOT_AFFECTED' for f in assessment.get('findings',[])) else 'NO_MATCHING_AFFECTED_VERSIONS'
    overall='MALWARE_FINDINGS' if state=='MALICIOUS' else 'KNOWN_VULNERABILITIES' if affected else 'INCOMPLETE_EVIDENCE' if state=='PARTIAL' or vulnerability_risk=='UNCERTAIN' else 'LOW_OBSERVED_RISK'
    # Retain the numeric field for older clients; threshold policy is authoritative.
    score=100 if state=='MALICIOUS' else 50 if decision['review_reasons'] or decision['detection_count']==decision['review_threshold'] else 0
    return {**decision,'score':score,'confidence':'LOW' if state=='PARTIAL' else 'MEDIUM',
            'reasons':reasons,'coverage_gaps':gaps,'approval_policy':criteria(),
            'overall_risk':overall,'vulnerability_risk':vulnerability_risk,'confirmed_vulnerability_ids':[f['id'] for f in affected],
            'policy_version':'2.0','ai':results.get('ai',{}).get('data',{})}
