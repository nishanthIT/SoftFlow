"""Unauthenticated browser check against the actual application; no API mocks."""
from pathlib import Path
import os,shutil,json
from dotenv import dotenv_values
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1]
v=dotenv_values(root/'.env')
base=os.environ.get('VERIFY_BASE_URL') or 'http://127.0.0.1:'+v.get('FRONTEND_PORT','3100')
analysis=os.environ.get('VERIFY_ANALYSIS_ID') or (root/'.local/verification/analysis_id' if (root/'.local/verification/analysis_id').exists() else root/'.local/demo/analysis_id').read_text().strip()
with sync_playwright() as p:
    browser=p.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH') or shutil.which('chromium'),headless=True,args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':1440,'height':1080})
    errors=[]
    page.on('pageerror',lambda e:errors.append(str(e)))
    page.goto(base)
    page.get_by_role('heading',name='Security overview.').wait_for()
    if os.environ.get('VERIFY_UPLOAD')=='1':
        page.goto(base+'/upload')
        page.get_by_label('Choose executable').set_input_files(str(root/'.local/verification/sentinelscan-smoke.exe'))
        with page.expect_response(lambda r:r.url.endswith('/api/samples') and r.request.method=='POST') as submitted:
            page.get_by_role('button',name='Start analysis').click()
        assert submitted.value.status==201,submitted.value.text()
        analysis=submitted.value.json()['analysis_id']
        page.wait_for_url('**/analysis/'+analysis)
        page.wait_for_function("""async id=>{
            const r=await fetch('/api/analysis/'+id);const j=await r.json();
            return ['COMPLETED','FAILED'].includes(j.status);
        }""",arg=analysis,timeout=240000,polling=2000)
        page.reload()
        page.get_by_role('heading',name='Approval decision',exact=True).wait_for()
        assert page.get_by_label('Decision',exact=True).locator('option[value=APPROVE]').evaluate('(e)=>e.disabled')
        page.get_by_label('Decision reason',exact=True).fill('Live LAN verification: sandbox evidence is unavailable; review required.')
        with page.expect_response(lambda r:r.url.endswith('/decision') and r.request.method=='POST') as decision:
            page.get_by_role('button',name='Record decision').click()
        assert decision.value.status==201,decision.value.text()
        assert decision.value.json()['data']['decision']=='REVIEW_REQUIRED'
        print('Browser upload, background processing, and decision persistence verified:',analysis,flush=True)
    for path in ['/settings','/analysis/'+analysis,'/analysis/'+analysis+'/report','/samples','/upload']:
        page.goto(base+path)
        page.wait_for_load_state('networkidle')
        text=page.locator('body').inner_text()
        for key in ['VIRUSTOTAL_API_KEY','HYBRID_ANALYSIS_API_KEY','CUCKOO_API_TOKEN','AUTH_SECRET','ADMIN_PASSWORD']:
            assert not v.get(key) or v[key] not in text,'Secret rendered in page'
        assert page.locator('body').evaluate('(e)=>e.scrollWidth<=innerWidth'),path
        print('Browser OK:',path)
    page.goto(base+'/analysis/'+analysis+'/report')
    with page.expect_download() as download:
        page.get_by_role('button',name='Export JSON').click()
    target=root/'.local/verification/browser-export.json'
    target.parent.mkdir(parents=True,exist_ok=True)
    download.value.save_as(str(target))
    exported=json.loads(target.read_text())
    assert exported['schema_version']=='2.0' and exported['analysis_id']==analysis
    if os.environ.get('VERIFY_UPLOAD')=='1':
        assert exported['approval']['recommendation']=='REVIEW_REQUIRED'
        assert exported['decisions'][0]['data']['decision']=='REVIEW_REQUIRED'
        (root/'.local/verification/browser-status.json').write_text(json.dumps({
            'base_url':base,'analysis_id':analysis,'authentication_required':False,
            'upload_verified':True,'decision_verified':True,'download_verified':True,
            'sandbox_verified':False,'mocked':False},indent=2))
    assert all(step['status'] not in ['RUNNING','QUEUED'] for step in exported['steps'])
    page.goto(base+'/upload')
    page.locator('input[type=file]').set_input_files({'name':'invalid.txt','mimeType':'text/plain','buffer':b'not executable'})
    page.get_by_role('alert').filter(has_text='Select a Windows .exe executable.').wait_for()
    assert page.get_by_role('button',name='Start analysis').is_disabled()
    page.set_viewport_size({'width':390,'height':844})
    page.goto(base+'/analysis/'+analysis+'/report')
    page.wait_for_load_state('networkidle')
    assert page.locator('body').evaluate('(e)=>e.scrollWidth<=innerWidth')
    page.screenshot(path=str(root/'.local/demo/mobile-report.png'),full_page=True)
    assert not errors,errors
    browser.close()
print('Live browser checks passed; no mocked endpoints.')
