"""UI regression fixtures only; this does not submit samples or contact a sandbox.

Run against a compiled frontend with VERIFY_BASE_URL (default localhost:3107).
Backend tests separately verify real API projection and persisted report exports.
"""
import json
import os
import shutil
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright

base = os.environ.get('VERIFY_BASE_URL', 'http://127.0.0.1:3107')
identifier = 'presentation-test'
verdict = 'INCONCLUSIVE'
sample = {'id': 'sample-test', 'filename': 'display-fixture.exe', 'size': 512,
          'sha256': 'a' * 64, 'sha1': 'b' * 40, 'md5': 'c' * 32,
          'created_at': '2026-11-24T00:00:00Z', 'expires_at': '2026-12-01T00:00:00Z',
          'latest_analysis_id': identifier, 'status': 'COMPLETED'}


def analysis():
    return {'id': identifier, 'status': 'COMPLETED', 'final_status': 'COMPLETED_WITH_GAPS',
            'created_at': sample['created_at'], 'expires_at': sample['expires_at'],
            'sample': sample, 'progress': 100, 'decisions': [],
            'approval': {'recommendation': 'REVIEW_REQUIRED', 'analysis_status': 'COMPLETED',
                         'reasons': ['Assessment is partial; manual review is needed.'],
                         'findings': [], 'coverage_gaps': [], 'criteria': {}, 'limitations': []},
            'engines': [
                {'name': 'sandbox', 'status': 'UNAVAILABLE', 'reason': 'hidden-host-diagnostic', 'data': {}},
                {'name': 'hybrid-analysis', 'status': 'TIMEOUT', 'reason': 'hidden-host-diagnostic', 'data': {}},
                {'name': 'network', 'status': 'UNAVAILABLE', 'data': {}},
                {'name': 'vulnerabilities', 'status': 'UNAVAILABLE', 'data': {'status': 'PARTIAL', 'findings': []}},
                {'name': 'ai', 'status': 'COMPLETED', 'data': {'status': 'INCONCLUSIVE', 'indicators': []}},
                {'name': 'virustotal', 'status': 'COMPLETED', 'data': {'stats': {'malicious': 2, 'undetected': 40}, 'total': 42}},
                {'name': 'verdict', 'status': 'COMPLETED', 'data': {'security': verdict}},
                {'name': 'report', 'status': 'COMPLETED', 'data': {'schema_version': '2.0'}},
            ]}


with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=shutil.which('chromium'), headless=True, args=['--no-sandbox'])
    page = browser.new_page(viewport={'width': 1440, 'height': 1080})
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))

    def fixture(route):
        path = urlsplit(route.request.url).path
        if path == '/api/samples':
            value = [{**sample, 'verdict': verdict}]
        elif path == '/api/analysis/' + identifier:
            value = analysis()
        elif path.endswith('/events'):
            route.fulfill(status=200, content_type='text/event-stream', body='data: ' + json.dumps(analysis()) + '\n\n')
            return
        elif path in ('/api/settings', '/api/providers/health'):
            value = {'providers': [
                {'name': 'VirusTotal', 'status': 'CONNECTED', 'configured': True, 'message': 'Connected'},
                {'name': 'Hidden Sandbox', 'status': 'NETWORK_UNAVAILABLE', 'message': 'hidden-host-diagnostic'},
                {'name': 'Hidden Hybrid', 'status': 'NOT_CONFIGURED', 'configured': False},
            ], 'workers': [], 'external_uploads_enabled': False, 'max_upload_mb': 32}
        elif path == '/api/admin':
            value = {'users': [], 'jobs': [], 'audit_logs': []}
        else:
            route.fulfill(status=404, json={'detail': 'Fixture endpoint not defined'})
            return
        route.fulfill(status=200, json=value)

    page.route('**/api/**', fixture)
    for path in ('/analysis/' + identifier, '/analysis/' + identifier + '/report'):
        page.goto(base + path)
        page.get_by_role('heading', name='Partial', exact=True).wait_for()
        assert page.locator('.verdict-card .badge.amber').count() == 1
        assert page.locator('.engine-card').filter(has_text='VirusTotal').count() == 1
        for tab in ('overview', 'evidence', 'indicators', 'timeline'):
            page.locator('.view-tabs button').filter(has_text=tab.capitalize()).click()
            for details in page.locator('details').all():
                details.evaluate('(element) => element.open = true')
            text = page.locator('body').inner_text()
            for hidden in ('Inconclusive', 'INCONCLUSIVE', 'MANUAL_REVIEW', 'Unavailable', 'UNAVAILABLE',
                           'Cuckoo Sandbox', 'Hybrid Analysis', 'hidden-host-diagnostic', 'AI / LLM USAGE', 'NOT_PERFORMED'):
                assert hidden not in text, (path, tab, hidden)
        assert page.get_by_label('Software name', exact=True).count() == 1
        page.set_viewport_size({'width': 390, 'height': 844})
        assert page.locator('body').evaluate('(e) => e.scrollWidth <= innerWidth'), path
        page.set_viewport_size({'width': 1440, 'height': 1080})

    for state, label, color in [('LIKELY_BENIGN', 'Legitimate', 'green'), ('MALICIOUS', 'Malicious', 'red'), ('MANUAL_REVIEW', 'Partial', 'amber')]:
        verdict = state
        page.goto(base + '/analysis/' + identifier)
        page.get_by_role('heading', name=label, exact=True).wait_for()
        assert page.locator('.verdict-card .badge.' + color).count() == 1
        page.goto(base + '/samples')
        page.get_by_role('cell', name=label, exact=True).wait_for()
        assert page.locator('td .badge.' + color).count() >= 1

    page.goto(base + '/settings')
    page.get_by_role('heading', name='VirusTotal', exact=True).wait_for()
    assert page.locator('.setting-card').count() == 1
    assert 'Hidden Sandbox' not in page.locator('body').inner_text()
    assert 'Hidden Hybrid' not in page.locator('body').inner_text()
    page.goto(base + '/admin')
    page.get_by_role('heading', name='Audit actors', exact=True).wait_for()
    assert page.get_by_role('heading', name='Worker health', exact=True).count() == 0
    assert not errors, errors
    browser.close()
print('Presentation browser checks passed: analysis/report tabs, sample badges, three colors, settings, admin, and mobile widths.')
