"""Authenticated browser check against actual localhost state; no API mocks."""
from pathlib import Path
from dotenv import dotenv_values
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1]
v=dotenv_values(root/'.env')
base='http://127.0.0.1:'+v.get('FRONTEND_PORT','3100')
analysis=(root/'.local/demo/analysis_id').read_text().strip()
with sync_playwright() as p:
    browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':1440,'height':1080})
    errors=[]
    page.on('pageerror',lambda e:errors.append(str(e)))
    page.goto(base)
    page.get_by_label('Username',exact=True).fill(v['ADMIN_USERNAME'])
    page.get_by_label('Password',exact=True).fill(v['ADMIN_PASSWORD'])
    page.get_by_role('button',name='Sign in to workspace').click()
    page.get_by_role('heading',name='Security overview.').wait_for()
    for path in ['/settings','/analysis/'+analysis,'/analysis/'+analysis+'/report','/samples','/upload']:
        page.goto(base+path)
        page.wait_for_load_state('networkidle')
        text=page.locator('body').inner_text()
        for key in ['VIRUSTOTAL_API_KEY','HYBRID_ANALYSIS_API_KEY','CUCKOO_API_TOKEN','AUTH_SECRET','ADMIN_PASSWORD']:
            assert not v.get(key) or v[key] not in text,'Secret rendered in page'
        assert page.locator('body').evaluate('(e)=>e.scrollWidth<=innerWidth'),path
        print('Browser OK:',path)
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
