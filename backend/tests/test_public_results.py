import json
import pytest
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


@pytest.mark.parametrize('old,new',[
    ('LEGITIMATE','LEGITIMATE'),('LIKELY_BENIGN','LEGITIMATE'),
    ('MALICIOUS','MALICIOUS'),('LIKELY_MALICIOUS','MALICIOUS'),
    ('PARTIAL','PARTIAL'),('MANUAL_REVIEW','PARTIAL'),('INCONCLUSIVE','PARTIAL'),
    ('SUSPICIOUS','PARTIAL'),('UNKNOWN','PARTIAL'),(None,'PARTIAL'),
])
def test_historical_verdicts_have_exactly_three_public_states(old,new):
    source={'verdict':{'security':old},'engines':[{'name':'verdict','status':'COMPLETED','data':{'security':old}}]}
    projected=document(source)
    assert projected['verdict']['security']==projected['engines'][0]['data']['security']==new
    assert source['verdict']['security']==old
    assert document(projected)==projected


@pytest.mark.parametrize('status',['UNAVAILABLE','UNREACHABLE','FAILED','TIMEOUT','SKIPPED','INVALID_API_TOKEN','NETWORK_UNAVAILABLE'])
def test_hidden_integrations_removed_from_every_report_section(status):
    failed={'status':status,'reason':'private-host-offline','data':{'diagnostic':{'code':status}}}
    source={'analysis_id':'legacy','status':'COMPLETED','final_status':'COMPLETED_WITH_GAPS',
        'engines':[{'name':'sandbox',**failed},{'name':'network',**failed},
            {'name':'ai','status':'COMPLETED','data':{'status':'INCONCLUSIVE','indicators':[]}},
            {'name':'verdict','status':'COMPLETED','data':{'security':'INCONCLUSIVE'}},
            {'name':'correlation','status':'COMPLETED','data':{'sources':{'sandbox':failed,'network':failed,
                'ai':{'status':'COMPLETED','data':{'status':'INCONCLUSIVE','indicators':[]}},
                'static':{'status':'COMPLETED','data':{'architecture':'x64'}}}}}],
        'verdict':{'security':'INCONCLUSIVE','ai':{'status':'INCONCLUSIVE'},
            'reasons':[{'source':'sandbox','evidence':'private-host-offline'}],
            'approval_policy':{'required_engines':['sandbox','network'],'detection_review_threshold':3}},
        'approval':{'recommendation':'REVIEW_REQUIRED','reasons':['Guest unavailable. The assessment is inconclusive.']},
        'steps':[{'stage':'sandbox','status':status,'error':'private-host-offline'},
                 {'stage':'verdict','status':'COMPLETED','error':None}],
        'summary':{'sandbox_execution':status},
        'vulnerability_assessment':{'status':'PARTIAL','providers':[{'provider':'Hidden advisory API',**failed}],'findings':[]}}
    projected=document(source);encoded=json.dumps(projected)
    for hidden in ('sandbox','network','private-host-offline','INCONCLUSIVE','Hidden advisory API','UNAVAILABLE','UNREACHABLE'):
        assert hidden not in encoded
    assert 'vulnerability_assessment' not in projected
    assert projected['verdict']['security']=='PARTIAL'
    assert projected['evidence_complete'] is False
    assert source['engines'][0]['status']==status
    assert document(projected)==projected


def test_partial_vulnerability_steps_and_top_level_assessment_agree():
    data={'status':'PARTIAL','reason':'offline-source','findings':[],
        'providers':[{'provider':'offline-source','status':'UNAVAILABLE'},
                     {'provider':'available-source','status':'COMPLETED','records':0}]}
    source={'final_status':'COMPLETED_WITH_GAPS',
        'engines':[{'name':'vulnerabilities','status':'UNAVAILABLE','reason':'offline-source','data':data}],
        'steps':[{'stage':'vulnerabilities','status':'UNAVAILABLE','error':'offline-source'}],
        'vulnerability_assessment':data}
    result=document(source)
    assert result['steps'][0]['status']==result['engines'][0]['status']=='PARTIAL'
    assert result['vulnerability_assessment']==result['engines'][0]['data']
    assert 'offline-source' not in json.dumps(result)
    assert result['engines'][0]['data']['providers'][0]['provider']=='available-source'
    assert document(result)==result


def test_unavailable_assessments_and_artifacts_absent_from_pdf(tmp_path):
    import shutil
    import subprocess
    if not shutil.which('pdftotext'): pytest.skip('pdftotext is required for PDF text verification')
    source={'analysis_id':'legacy-pdf','status':'COMPLETED','final_status':'COMPLETED_WITH_GAPS',
        'verdict':{'security':'INCONCLUSIVE'},'engines':[
            {'name':'sandbox','status':'UNAVAILABLE','data':{'artifacts':{'errors':[{'name':'capture.pcap','error':'private-offline-host'}]}}}],
        'steps':[{'stage':'sandbox','status':'UNAVAILABLE'}],
        'vulnerability_assessment':{'status':'NOT_PERFORMED'},
        'approval':{'recommendation':'REVIEW_REQUIRED','reasons':['Guest unavailable']}}
    path=tmp_path/'report.pdf';path.write_bytes(render(source))
    content=subprocess.check_output(['pdftotext',str(path),'-'],text=True)
    assert 'Malware assessment: Partial' in content
    for hidden in ('Inconclusive','INCONCLUSIVE','UNAVAILABLE','Guest unavailable','Vulnerability assessment','NOT_PERFORMED','sandbox','private-offline-host'):
        assert hidden not in content
