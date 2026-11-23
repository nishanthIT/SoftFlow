"""Public evidence projection; full diagnostics remain in Engine rows and server logs.

Filtering never participates in scoring or approval. Missing evidence is summarized
as partial/manual review, never converted into a successful zero-detection scan.
"""
from copy import deepcopy

HIDDEN = {'FAILED', 'TIMEOUT', 'UNAVAILABLE', 'SKIPPED', 'NOT_CONFIGURED', 'DISABLED',
          'NETWORK_UNAVAILABLE', 'API_UNAVAILABLE', 'INVALID_API_KEY', 'ACCESS_DENIED',
          'RATE_LIMITED', 'ANALYSIS_UNAVAILABLE', 'INVALID_RESPONSE', 'CORE_NOT_READY',
          'NO_ANALYSIS_MACHINE', 'ISOLATION_REQUIRED'}
EXTERNAL = {'virustotal', 'hybrid-analysis', 'sandbox'}


def failed(value):
    return isinstance(value,dict) and isinstance(value.get('status'),str) and value['status'] in HIDDEN


def clean(value, diagnostics=False):
    if isinstance(value, list):
        return [clean(item,diagnostics) for item in value if not (diagnostics and failed(item))]
    if not isinstance(value, dict): return value
    result = {}
    for key, item in value.items():
        if key in ('diagnostic', 'coverage_gaps', 'errors', 'last_transport_error', 'last_http_status', 'endpoint_identity'):
            continue
        context=key in ('providers','sources','raw_responses','full_report_access')
        if (diagnostics or context or key in EXTERNAL) and failed(item): continue
        result[key] = clean(item,context)
    if 'coverage_gaps' in value:
        result['coverage_gaps'] = []
        result['evidence_complete'] = value.get('evidence_complete', not bool(value['coverage_gaps']))
    # A partial intelligence assessment retains successful sources and findings,
    # but its detailed failure explanation may contain unavailable provider names.
    if value.get('status') == 'PARTIAL':
        result['reason'] = 'Assessment is partial; manual review is needed.'
    return result


def engines(rows):
    visible = []
    for row in rows:
        name, status = row['name'], row['status']
        if status in HIDDEN:
            if name == 'vulnerabilities' and row.get('data', {}).get('findings'):
                data = clean(row['data']);data['status'] = 'PARTIAL'
                visible.append({**row, 'status':'PARTIAL', 'reason':'Assessment is partial; manual review is needed.', 'data':data})
            # Local validation/finalization errors are actionable job failures,
            # not unreachable integrations. Keep these explicit.
            elif name in ('validation', 'hashing', 'report') and status == 'FAILED':
                visible.append({**row, 'reason':'This analysis stage could not finish.', 'data':{}})
            continue
        if name in EXTERNAL and status != 'COMPLETED': continue
        visible.append(clean(row))
    return visible


def document(value):
    """Project API/SSE, newly persisted reports, and legacy stored exports alike."""
    source = deepcopy(value)
    rows = source.get('engines', [])
    source['engines'] = engines(rows)
    names = {e['name'] for e in source['engines']}
    if 'steps' in source:
        source['steps'] = [{**step, 'order':i+1, 'evidence_reference':f'/engines/{i}/data'}
                           for i, step in enumerate(s for s in source['steps'] if s['stage'] in names)]
    source['errors'] = []
    if source.get('summary',{}).get('sandbox_execution') in HIDDEN:
        source['summary'].pop('sandbox_execution',None)
    projected = clean(source)
    projected['engines'] = source['engines']
    if 'steps' in source:
        projected['steps'] = [{**step,'error':'This analysis stage could not finish.'} if step.get('status')=='FAILED' else step for step in source['steps']]
    # Preserve incompleteness independently of the filtered table.
    projected['evidence_complete'] = source.get('final_status') == 'COMPLETED'
    return projected
