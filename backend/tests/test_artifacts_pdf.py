import hashlib
import json
import shutil
import subprocess
import httpx
from app import artifacts,storage
from app.config import settings
from app.pdf_report import render


def test_artifacts_stream_to_job_namespace_and_bad_content_remains_a_gap(tmp_path,monkeypatch):
    monkeypatch.setattr(settings,'storage_backend','filesystem')
    monkeypatch.setattr(settings,'local_storage_path',str(tmp_path/'objects'))
    monkeypatch.setattr(settings,'worker_temp_path',str(tmp_path/'work'))
    identifier='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';analysis='20261101-ABCDEF';task=analysis+'_1'
    pcap=b'\xd4\xc3\xb2\xa1'+b'\x00'*20
    report={'tasks':[{'task':{'id':task},'post':{'screenshot':[{'name':'123.png'},{'name':'../../private.png'}]}}]}
    calls=[]
    def respond(request):
        calls.append(request.url.path)
        return httpx.Response(200,content=pcap if request.url.path.endswith('/pcap') else b'<html>error</html>')
    with httpx.Client(base_url='http://cuckoo.invalid/',transport=httpx.MockTransport(respond)) as client:
        result=artifacts.collect(client,identifier,analysis,report)
    assert len(calls)==2 and all('private' not in call for call in calls)
    assert len(result['files'])==1 and result['errors'][0]['name']=='123.png'
    item=result['files'][0];assert item['sha256']==hashlib.sha256(pcap).hexdigest()
    assert storage.get(item['object_key'])==pcap
    assert list((tmp_path/'work').iterdir())==[]


def test_pdf_is_real_readable_and_treats_untrusted_markup_as_text(tmp_path):
    report={'analysis_id':'fixture','status':'FAILED','final_status':'FAILED','sample':{'filename':'<img src="file:///private">.exe','sha256':'a'*64},
        'engines':[],'steps':[{'stage':'sandbox','status':'FAILED','error':'Guest unavailable'}],
        'approval':{'recommendation':'REVIEW_REQUIRED','reasons':['Guest unavailable']},
        'vulnerability_assessment':{'status':'PARTIAL','findings':[{'id':'CVE-FIXTURE','classification':'CONFIRMED_AFFECTED',
            'description':'<script>Untrusted advisory text</script>','references':[{'url':'https://example.invalid/advisory','public_exploit_reference':True}]}]}}
    data=render(report);assert data.startswith(b'%PDF-') and len(data)>1000
    if shutil.which('pdftotext'):
        pdf=tmp_path/'report.pdf';pdf.write_bytes(data)
        text=subprocess.check_output(['pdftotext',str(pdf),'-'],text=True)
        assert 'CVE-FIXTURE' in text and 'Guest unavailable' in text and 'Untrusted advisory text' in text
        assert 'file:///private' in text and 'not executed' in text
