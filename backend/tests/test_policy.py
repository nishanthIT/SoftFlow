import struct
from pathlib import Path
import pytest
from app.config import settings
from app import policy,static
from app.providers import virustotal,hybrid,Unavailable,CuckooCapeProvider

@pytest.fixture(autouse=True)
def paths(monkeypatch):
    root=Path(__file__).resolve().parents[2]
    monkeypatch.setattr(settings,'ai_signatures_path',str(root/'ai-signatures/providers.json'))
    monkeypatch.setattr(settings,'yara_path',str(root/'yara/rules'))

def test_missing_engines_never_clean():
    r=policy.verdict({'virustotal':{'status':'UNAVAILABLE','data':{},'reason':'Not configured'}})
    assert r['security']=='INCONCLUSIVE'
    assert r['coverage_gaps'][0]['status']=='UNAVAILABLE'

def test_malicious_evidence_traceable():
    r=policy.verdict({'virustotal':{'status':'COMPLETED','data':{'stats':{'malicious':8}}}})
    assert r['security']=='LIKELY_MALICIOUS'
    assert r['reasons'][0]['source']=='virustotal'

def test_benign_requires_coverage():
    results={k:{'status':'COMPLETED','data':{}} for k in ['static','yara','virustotal','sandbox','behavior','network']}
    results['virustotal']['data']={'stats':{'undetected':40}}
    assert policy.verdict(results)['security']=='LIKELY_BENIGN'
    results['sandbox']['status']='TIMEOUT'
    assert policy.verdict(results)['security']=='INCONCLUSIVE'

def test_ai_never_increases_malware_score():
    r=policy.verdict({'ai':{'status':'COMPLETED','data':{'status':'DETECTED','providers':['OpenAI']}}})
    assert r['score']==0 and r['security']=='INCONCLUSIVE'

def test_static_sdk_not_usage():
    r=policy.ai_detect({'strings':['openai.resources']},{},True,False)
    assert r['status']=='STATIC_INDICATOR_ONLY'

def test_missing_capture_inconclusive():
    assert policy.ai_detect({'strings':[]},{},True,False)['status']=='INCONCLUSIVE'
    assert policy.ai_detect({'strings':[]},{'events':[]},True,True)['status']=='NOT_OBSERVED'

def test_dns_is_not_proof():
    r=policy.ai_detect({}, {'events':[{'type':'dns','domain':'api.openai.com'}]},True,True)
    assert r['status']=='SUSPECTED'

def test_endpoint_evidence_confirms():
    r=policy.ai_detect({}, {'events':[{'type':'https','host':'api.openai.com','url':'https://api.openai.com/v1/responses'}]},True,True)
    assert r['status']=='DETECTED'
    assert r['indicators'][0]['source']=='sandbox'

def test_domain_suffix_attack():
    for host in ['api.openai.com.evil.test','evilopenai.com','api.openai.com@evil.test']:
        assert not policy.domain_match(host,'api.openai.com')

def test_runtime_summary_not_invented():
    assert policy.network({}) is None
    assert policy.behavior({}) is None
    b=policy.behavior({'report':{'behavior':{'processes':[{'process_name':'test.exe','calls':[{'api':'CreateRemoteThread'}]}]}}})
    assert b['events'][0]['technique']=='T1055'

def test_real_yara():
    r=static.scan_yara(b'MZ'+b'\x00'*128+b'powershell DownloadString Invoke-Expression')
    assert r['matches'][0]['rule']=='Suspicious_PowerShell_Downloader'
    assert r['matches'][0]['strings'][0]['offset']>=130
    assert static.scan_yara(b'MZ just a benign test')['matches']==[]

def test_unconfigured_providers(monkeypatch):
    monkeypatch.setattr(settings,'virustotal_api_key','')
    monkeypatch.setattr(settings,'hybrid_analysis_api_key','')
    monkeypatch.setattr(settings,'cuckoo_api_url','')
    for fn in [lambda:virustotal(b'', 'a'*64,False),lambda:hybrid(b'','a'*64,False),lambda:CuckooCapeProvider()]:
        with pytest.raises(Unavailable): fn()

def test_pe_extraction():
    data=bytearray(1024);data[:2]=b'MZ';struct.pack_into('<I',data,60,128);data[128:132]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',data,132,0x14c,1,0,0,0,224,0x102)
    struct.pack_into('<H',data,152,0x10b)
    struct.pack_into('<I',data,180,0x400000)
    struct.pack_into('<II',data,184,0x1000,0x200)
    struct.pack_into('<II',data,208,0x2000,0x200)
    struct.pack_into('<I',data,244,16)
    data[376:384]=b'.text\0\0\0';struct.pack_into('<IIII',data,384,10,0x1000,512,512)
    data[512:526]=b'openai-python\0'
    r=static.analyze(bytes(data))
    assert r['architecture']=='x86'
    assert r['certificate_present'] is False
    assert r['signature_validation']=='NOT_PERFORMED'
    assert 'openai-python' in r['strings']

def test_empty_sandbox_objects_are_not_coverage():
    assert policy.network({'report':{'network':{}}}) is None
    assert policy.behavior({'report':{'behavior':{}}}) is None

def test_observed_local_inference_api():
    b={'processes':[{'process_name':'local.exe','calls':[{'api':'OrtRun','timestamp':'2026-01-01'}]}]}
    r=policy.ai_detect({}, {},True,False,b)
    assert r['status']=='DETECTED'
    assert r['indicators'][0]['type']=='LOCAL_INFERENCE'
