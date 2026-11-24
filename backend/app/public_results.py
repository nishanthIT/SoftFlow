"""Public projection; full diagnostics remain in Engine rows and server logs.

Filtering never participates in scoring or approval. Missing evidence remains
partial; hiding an integration must never turn a failed check into a clean scan.
This projection also applies to reports saved before the current display policy.
"""
from copy import deepcopy
import re

HIDDEN = {'FAILED', 'TIMEOUT', 'UNAVAILABLE', 'UNREACHABLE', 'SKIPPED', 'NOT_CONFIGURED', 'DISABLED',
          'NOT_PERFORMED', 'NOT_AVAILABLE', 'MISSING', 'ERROR',
          'API_TOKEN_REQUIRED', 'INVALID_API_TOKEN', 'INVALID_REQUEST',
          'NETWORK_UNAVAILABLE', 'API_UNAVAILABLE', 'INVALID_API_KEY', 'ACCESS_DENIED',
          'RATE_LIMITED', 'ANALYSIS_UNAVAILABLE', 'INVALID_RESPONSE', 'CORE_NOT_READY',
          'NO_ANALYSIS_MACHINE', 'ISOLATION_REQUIRED'}
EXTERNAL = {'virustotal', 'hybrid-analysis', 'sandbox'}
PARTIAL_REASON = 'Assessment is partial; manual review is needed.'


def security_state(value):
    """Canonical display states, including historical stored verdicts."""
    if value in ('LEGITIMATE', 'LIKELY_BENIGN'):
        return 'LEGITIMATE'
    if value in ('MALICIOUS', 'LIKELY_MALICIOUS'):
        return 'MALICIOUS'
    return 'PARTIAL'


def failed(value):
    return isinstance(value, dict) and isinstance(value.get('status'), str) and value['status'].upper() in HIDDEN


def vulnerability_result(value):
    if not isinstance(value, dict) or not value:
        return None
    usable = bool(value.get('findings') or any(p.get('status') == 'COMPLETED' for p in value.get('providers', []) if isinstance(p, dict)))
    if value.get('status') == 'COMPLETED':
        return value
    if usable:
        return {**value, 'status': 'PARTIAL', 'reason': PARTIAL_REASON}
    return None


def ai_result(value):
    if not isinstance(value, dict) or not value or failed(value):
        return None
    if isinstance(value.get('data'), dict):
        data = ai_result(value['data'])
        return {**value, 'data': data} if data is not None else None
    if value.get('status') in ('INCONCLUSIVE', 'MANUAL_REVIEW', 'PARTIAL'):
        return {**value, 'status': 'PARTIAL'} if value.get('indicators') else None
    return value if value.get('status') else None


def assessment_text(value):
    """Normalize generated assessment prose, never analyst notes or observations."""
    if not isinstance(value, str):
        return value
    if re.search(r'\b(unavailable|unreachable|not configured|timed out)\b', value, re.I):
        return PARTIAL_REASON
    return re.sub(r'\binconclusive\b', 'partial', value, flags=re.I)


def clean(value, diagnostics=False, hidden_names=frozenset()):
    if isinstance(value, list):
        return [clean(item, diagnostics, hidden_names) for item in value
                if not (diagnostics and (failed(item) or
                    isinstance(item, str) and item in hidden_names or
                    isinstance(item, dict) and any(isinstance(item.get(key), str) and item[key] in hidden_names
                                                  for key in ('source', 'engine', 'name'))))]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key in ('diagnostic', 'coverage_gaps', 'errors', 'last_transport_error', 'last_http_status', 'endpoint_identity'):
            continue
        # Full captured requirements stay in the internal approval record.
        # Public criteria retain thresholds without naming hidden integrations.
        if key == 'required_engines':
            continue
        context = key in ('providers', 'sources', 'raw_responses', 'full_report_access', 'detection_sources')
        if diagnostics and key in hidden_names:
            continue
        if (diagnostics or context or key in EXTERNAL) and failed(item):
            continue
        if key == 'vulnerability_assessment':
            item = vulnerability_result(item)
            if item is None:
                continue
        if key == 'ai':
            item = ai_result(item)
            if item is None:
                continue
        if key == 'security':
            item = security_state(item)
        if key in ('reasons', 'findings') and ('security' in value or 'recommendation' in value):
            context = True
            if isinstance(item, list):
                item = [assessment_text(text) for text in item]
        if key == 'explanation' and 'security' in value and isinstance(item, str):
            item = re.sub(r'\binconclusive\b', 'partial', item, flags=re.I)
            item = item.replace('Cuckoo-only analyses', 'Analyses without antivirus counts')
        result[key] = clean(item, context, hidden_names)
    if 'coverage_gaps' in value:
        result['coverage_gaps'] = []
        result['evidence_complete'] = value.get('evidence_complete', not bool(value['coverage_gaps']))
    if value.get('status') == 'PARTIAL':
        result['reason'] = PARTIAL_REASON
    return result


def engines(rows):
    visible = []
    for row in rows:
        name, status = row['name'], row['status']
        if name == 'vulnerabilities' and status not in ('QUEUED', 'RUNNING'):
            data = vulnerability_result(row.get('data'))
            if data is None:
                continue
            row = {**row, 'status': 'COMPLETED' if status == 'COMPLETED' and data['status'] == 'COMPLETED' else 'PARTIAL', 'data': data}
            if row['status'] == 'PARTIAL':
                row['reason'] = PARTIAL_REASON
                row['data'] = {**data, 'status': 'PARTIAL', 'reason': PARTIAL_REASON}
        elif status in HIDDEN:
            # Local validation/finalization failures remain actionable job errors.
            if name in ('validation', 'hashing', 'report') and status == 'FAILED':
                visible.append({**row, 'reason': 'This analysis stage could not finish.', 'data': {}})
            continue
        if name in EXTERNAL and status != 'COMPLETED':
            continue
        if name in EXTERNAL and failed(row.get('data')):
            continue
        if name == 'ai' and status == 'COMPLETED':
            data = ai_result(row.get('data'))
            if data is None:
                continue
            row = {**row, 'data': data}
        if name == 'verdict' and status == 'COMPLETED':
            row = {**row, 'data': {**row.get('data', {}), 'security': security_state(row.get('data', {}).get('security'))}}
        visible.append(clean(row))
    return visible


def document(value):
    """Project API/SSE, newly persisted reports, and legacy stored exports alike."""
    source = deepcopy(value)
    rows = source.get('engines', [])
    source['engines'] = engines(rows)
    visible = {e['name']: e for e in source['engines']}
    hidden_names = {e['name'] for e in rows} - visible.keys()
    if 'steps' in source:
        steps = []
        for step in source['steps']:
            row = visible.get(step['stage'])
            if row is None:
                continue
            item = {**step, 'order': len(steps) + 1, 'evidence_reference': f'/engines/{len(steps)}/data'}
            if 'status' in item:
                item['status'] = row['status']
            if 'error' in item:
                item['error'] = row.get('reason')
            steps.append(item)
        source['steps'] = steps
    if 'sandbox' not in visible:
        source.get('summary', {}).pop('sandbox_execution', None)
        if 'limitations' in source:
            source['limitations'] = [s for s in source['limitations'] if not s.startswith('Sandbox snapshot restoration')]
    if 'verdict' in source:
        source['verdict'] = {**(source['verdict'] or {}), 'security': security_state((source['verdict'] or {}).get('security'))}
    projected = clean(source, hidden_names=hidden_names)
    # Preserve incompleteness independently of the filtered table.
    projected['evidence_complete'] = source.get('evidence_complete', source.get('final_status') == 'COMPLETED')
    return projected
