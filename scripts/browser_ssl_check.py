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
    picker=page.get_by_role('button',name='Upload TXT file',exact=True)
    picker.wait_for(state='visible')
    assert page.get_by_role('button',name='Check certificates',exact=True).is_disabled()
    # The visible upload button opens the native picker, including by keyboard.
    picker.focus()
    with page.expect_file_chooser() as chooser:picker.press('Enter')
    chooser.value.set_files(str(ROOT/'docs/ssl-domains-example.txt'))
    page.locator('.ssl-selected-file').get_by_text('ssl-domains-example.txt',exact=True).wait_for()
    page.get_by_role('button',name='Remove domain file',exact=True).click()
    assert page.get_by_role('button',name='Check certificates',exact=True).is_disabled()
    zone=page.get_by_role('group',name='Domain file upload',exact=True)
    def drop(files):
        transfer=page.evaluate_handle('''files=>{const data=new DataTransfer();for(const item of files){data.items.add(new File([item.content||'x'.repeat(item.size||0)],item.name,{type:'text/plain'}));}return data;}''',files)
        zone.dispatch_event('dragenter',{'dataTransfer':transfer})
        assert 'dragging' in (zone.get_attribute('class') or '')
        zone.dispatch_event('dragover',{'dataTransfer':transfer})
        zone.dispatch_event('drop',{'dataTransfer':transfer})
        assert 'dragging' not in (zone.get_attribute('class') or '')
        transfer.dispose()
    for files,message in [
        ([{'name':'wrong.csv','content':'example.org'}],'Choose a .txt file with one domain per line.'),
        ([{'name':'empty.txt','size':0}],'The text file is empty.'),
        ([{'name':'large.txt','size':256*1024+1}],'Text file exceeds 256 KiB.'),
        ([{'name':'one.txt','content':'example.org'},{'name':'two.txt','content':'python.org'}],'Choose one .txt file at a time.')]:
        drop(files)
        page.get_by_role('alert').filter(has_text=message).wait_for()
        assert page.get_by_role('button',name='Check certificates',exact=True).is_disabled()
    drop([{'name':'dropped-domains.txt','content':(ROOT/'docs/ssl-domains-example.txt').read_text()}])
    page.locator('.ssl-selected-file').get_by_text('dropped-domains.txt',exact=True).wait_for()
    with page.expect_response(lambda r:r.url.endswith('/api/ssl-checks') and r.request.method=='POST') as response:
        page.get_by_role('button',name='Check certificates',exact=True).click()
    assert response.value.status==201,response.value.text()
    assert response.value.json()['filename']=='dropped-domains.txt'
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
    assert picker.is_visible()
    page.screenshot(path=str(output/'ssl-checker-mobile.png'),full_page=True)
    result=page.request.get('http://127.0.0.1:3100/api/ssl-checks/'+identifier).json()
    assert result['status']=='COMPLETED' and result['completed']==5
    assert result['summary']['WILDCARD_NOT_TESTED']==1 and not errors,errors
    evidence={'check_id':identifier,'summary':result['summary'],'browser_errors':errors,'excel_verified':True,
        'sort_filter_reload_mobile_verified':True,'picker_keyboard_drop_validation_verified':True,
        'live_network':True,'authentication_required':False}
    (output/'ssl-browser-status.json').write_text(json.dumps(evidence,indent=2));print(json.dumps(evidence,indent=2))
    browser.close()
