"""Live name/version correction and NVD mapping beyond the local catalog."""
import json,shutil,time
from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1];output=ROOT/'.local/verification'
prior=json.loads((output/'name-version-job.json').read_text())['analysis_id']
with sync_playwright() as p:
    browser=p.chromium.launch(executable_path=shutil.which('chromium'),headless=True,args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':1440,'height':1100});errors=[]
    page.on('pageerror',lambda error:errors.append(str(error)))
    base='http://127.0.0.1:3100';page.goto(base+'/analysis/'+prior)
    page.get_by_text('Check or correct software name and version',exact=True).click()
    page.get_by_label('Software name',exact=True).fill('Notepad++')
    page.get_by_label('Software version',exact=True).fill('8.1')
    with page.expect_response(lambda r:r.url.endswith('/api/analysis') and r.request.method=='POST') as response:
        page.get_by_role('button',name='Check name and version',exact=True).click()
    assert response.value.status==201,response.value.text()
    identifier=response.value.json()['analysis_id'];page.wait_for_url('**/analysis/'+identifier)
    print('Browser correction queued:',identifier,flush=True)
    deadline=time.monotonic()+300
    while time.monotonic()<deadline:
        job=page.request.get(base+'/api/analysis/'+identifier).json()
        if job['status'] in ('COMPLETED','FAILED'):break
        page.wait_for_timeout(1000)
    else:raise RuntimeError('Identity check exceeded verification deadline')
    report=page.request.get(base+'/api/analysis/'+identifier+'/report').json()
    assessment=report['vulnerability_assessment']
    assert assessment['identity']['mapping']=='NVD_CPE_MATCH',assessment
    assert assessment['summary']['CONFIRMED_AFFECTED']>0,assessment
    assert assessment['identity']['source']=='User-supplied product and version'
    assert page.request.get(base+'/api/analysis/'+prior).status==200
    page.reload();page.get_by_text(assessment['conclusion'],exact=True).first.wait_for()
    pdf=page.request.get(base+'/api/analysis/'+identifier+'/report.pdf')
    assert pdf.ok and pdf.body().startswith(b'%PDF-')
    (output/'name-version-report.pdf').write_bytes(pdf.body())
    (output/'name-version-report.json').write_text(json.dumps(report,indent=2))
    assert not errors,errors
    evidence={'analysis_id':identifier,'declared_test_identity':True,'product':assessment['identity']['name'],
        'version':assessment['identity']['version'],'mapping':assessment['identity']['mapping'],
        'conclusion':assessment['conclusion'],'summary':assessment['summary'],'providers':assessment['providers'],
        'prior_report_preserved':True,'pdf_verified':True,'browser_errors':errors}
    (output/'name-version-browser-status.json').write_text(json.dumps(evidence,indent=2))
    print(json.dumps(evidence,indent=2));browser.close()
