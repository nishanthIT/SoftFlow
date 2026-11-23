import json
from app.public_results import document
from app.reporting import build_report
from app.pdf_report import render


def test_nested_diagnostics_removed_without_mutating_internal_evidence():
    secret={'status':'UNAVAILABLE','reason':'offline-provider.internal','data':{'diagnostic':{'message':'offline-provider.internal'}}}
    rows=[{'name':'virustotal',**secret},
          {'name':'correlation','status':'COMPLETED','data':{'sources':{'virustotal':secret,'static':{'status':'COMPLETED','data':{'architecture':'x64'}}}}},
          {'name':'verdict','status':'COMPLETED','data':{'security':'MANUAL_REVIEW','coverage_gaps':[{'engine':'virustotal','status':'UNAVAILABLE','reason':'offline-provider.internal'}]}},
          {'name':'report','status':'COMPLETED','data':{}}]
    report=build_report({'id':'a','status':'COMPLETED'},{'filename':'fixture.exe'},rows)
    encoded=json.dumps(report)
    assert 'offline-provider.internal' not in encoded and 'UNAVAILABLE' not in encoded
    assert 'virustotal' not in encoded
    assert report['final_status']=='COMPLETED_WITH_GAPS' and not report['evidence_complete']
    assert report['approval']['recommendation']=='REVIEW_REQUIRED'
    assert rows[0]['reason']=='offline-provider.internal'
    assert document(report)==report
    assert render(report).startswith(b'%PDF-')


def test_partial_vulnerability_findings_retained_with_successful_sources():
    report=document({'final_status':'COMPLETED_WITH_GAPS','engines':[{
        'name':'vulnerabilities','status':'UNAVAILABLE','reason':'Failed-provider',
        'data':{'status':'PARTIAL','reason':'Failed-provider','findings':[{'id':'CVE-fixture'}],
                'providers':[{'name':'Failed-provider','status':'UNAVAILABLE'},{'name':'Available-provider','status':'COMPLETED'}]}}]})
    assert report['engines'][0]['data']['findings']==[{'id':'CVE-fixture'}]
    assert 'Failed-provider' not in json.dumps(report)
    assert 'Available-provider' in json.dumps(report)


def test_legacy_export_filters_steps_and_raw_access_errors():
    source={'final_status':'COMPLETED_WITH_GAPS','engines':[{'name':'sandbox','status':'UNAVAILABLE','data':{}},
        {'name':'hybrid-analysis','status':'COMPLETED','data':{'raw_responses':{'full_report_access':{'status':'FAILED','message':'unreachable-secret'}}}}],
        'steps':[{'stage':'sandbox'},{'stage':'hybrid-analysis'}],
        'summary':{'sandbox_execution':'UNAVAILABLE'},'errors':[{'stage':'sandbox','message':'unreachable-secret'}]}
    result=document(source)
    assert 'unreachable-secret' not in json.dumps(result) and 'UNAVAILABLE' not in json.dumps(result)
    assert result['steps']==[{'stage':'hybrid-analysis','order':1,'evidence_reference':'/engines/0/data'}]


def test_observed_failed_guest_operations_are_not_provider_diagnostics():
    data={'events':[{'status':'FAILED','name':'Guest file access','api':'CreateFileW'}],
          'untrusted_metadata':{'status':{'nested':'value'}}}
    result=document({'engines':[{'name':'behavior','status':'COMPLETED','data':data}]})
    assert result['engines'][0]['data']==data
