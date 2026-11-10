"""Live domain upload, background processing, Excel and accessible sidebar checks."""
import json,shutil
from pathlib import Path
from openpyxl import load_workbook
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]
output=ROOT/'.local/verification';output.mkdir(exist_ok=True,parents=True)
with sync_playwright() as p:
    browser=p.chromium.launch(executable_path=shutil.which('chromium'),headless=True,args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':1440,'height':1100});errors=[]
    page.on('pageerror',lambda error:errors.append(str(error)))
    page.goto('http://127.0.0.1:3100')
    page.get_by_role('link',name='SSL expiry checker',exact=True).click()
    page.get_by_role('heading',name='SSL expiry checker.').wait_for()
    assert page.get_by_role('button',name='Sign in',exact=True).count()==0
    page.locator('#domain-list').set_input_files(str(ROOT/'docs/ssl-domains-example.txt'))
    with page.expect_response(lambda r:r.url.endswith('/api/ssl-checks') and r.request.method=='POST') as response:
        page.get_by_role('button',name='Check certificates',exact=True).click()
    assert response.value.status==201,response.value.text()
    identifier=response.value.json()['id']
    page.get_by_role('link',name='Download Excel',exact=True).wait_for(timeout=180000)
    with page.expect_download() as download:page.get_by_role('link',name='Download Excel',exact=True).click()
    target=output/'ssl-expiry-results.xlsx';download.value.save_as(str(target));wb=load_workbook(target)
    assert wb.sheetnames==['SSL Results','Summary']
    assert wb['SSL Results'].max_row==6 and wb['SSL Results'].auto_filter.ref=='A1:I6'
    assert all(cell.data_type!='f' for sheet in wb for row in sheet for cell in row)
    page.get_by_role('button',name='DOMAIN',exact=True).click()
    names=page.locator('.ssl-table tbody tr td:first-child strong').all_text_contents()
    assert names==sorted(names,reverse=True)
    page.get_by_label('Filter certificate status').select_option('WILDCARD_NOT_TESTED')
    assert page.locator('.ssl-table tbody tr').count()==1
    page.get_by_label('Filter certificate status').select_option('')
    page.get_by_label('Search certificate results').fill('python');assert page.locator('.ssl-table tbody tr').count()==1
    page.get_by_label('Search certificate results').fill('')
    page.reload();page.get_by_role('link',name='Download Excel',exact=True).wait_for()
    assert page.locator('body').evaluate('(e)=>e.scrollWidth<=innerWidth')
    page.screenshot(path=str(output/'ssl-checker-desktop.png'),full_page=True)
    page.set_viewport_size({'width':390,'height':844})
    assert page.locator('body').evaluate('(e)=>e.scrollWidth<=innerWidth')
    page.screenshot(path=str(output/'ssl-checker-mobile.png'),full_page=True)
    result=page.request.get('http://127.0.0.1:3100/api/ssl-checks/'+identifier).json()
    assert result['status']=='COMPLETED' and result['completed']==5
    assert result['summary']['WILDCARD_NOT_TESTED']==1 and not errors,errors
    evidence={'check_id':identifier,'summary':result['summary'],'browser_errors':errors,'excel_verified':True,
        'sort_filter_reload_mobile_verified':True,'live_network':True,'authentication_required':False}
    (output/'ssl-browser-status.json').write_text(json.dumps(evidence,indent=2));print(json.dumps(evidence,indent=2))
    browser.close()
