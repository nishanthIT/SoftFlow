"""Layout tests use explicitly empty API fixtures; never fabricated analysis results.
Run against the compiled frontend at http://127.0.0.1:3000.
"""
import json
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':1440,'height':1080},device_scale_factor=1)
    errors=[]
    page.on('pageerror',lambda e:errors.append(str(e)))
    def api_fixture(route):
        path=route.request.url.split(':3000')[-1]
        if path.startswith('/api/samples'): data=[]
        elif path=='/api/settings':data={'providers':[{'name':'VirusTotal','configured':False},{'name':'Hybrid Analysis','configured':False},{'name':'CAPE / Cuckoo','configured':False}], 'external_uploads_enabled':False,'max_upload_mb':32}
        else:route.fulfill(status=404,json={'detail':'Unavailable in layout test'});return
        route.fulfill(status=200,content_type='application/json',body=json.dumps(data))
    page.route('**/api/**',api_fixture)
    page.goto('http://127.0.0.1:3000/')
    page.get_by_role('heading',name='Security overview.').wait_for()
    page.get_by_text('Your first investigation starts here').wait_for()
    assert page.locator('body').evaluate('(e)=>e.scrollWidth <= innerWidth')
    page.screenshot(path='/tmp/sentinelscan-desktop.png',full_page=True)
    page.get_by_role('link',name='Analyze an executable').click()
    page.get_by_role('heading',name='Drop your executable here').wait_for()
    page.locator('input[type=file]').set_input_files({'name':'bad.txt','mimeType':'text/plain','buffer':b'not executable'})
    page.get_by_role('alert').filter(has_text='Select a Windows .exe executable.').wait_for()
    assert page.get_by_role('button',name='Start analysis').is_disabled()
    page.set_viewport_size({'width':390,'height':844})
    page.goto('http://127.0.0.1:3000/')
    page.get_by_role('heading',name='Security overview.').wait_for()
    assert page.locator('body').evaluate('(e)=>e.scrollWidth <= innerWidth')
    page.screenshot(path='/tmp/sentinelscan-mobile.png',full_page=True)
    assert not errors,errors
    browser.close()
    print('Browser smoke passed: dashboard, upload validation, responsive widths, no browser errors')
