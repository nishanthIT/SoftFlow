"""Approval recommendations are distinct from malware findings and human decisions."""
from .config import settings

LIMITATIONS = [
    'No malicious behavior detected is not proof of safety or absence of vulnerabilities.',
    'This workflow does not perform CVE matching, dependency auditing, or vulnerability scanning.',
    'Dynamic coverage is limited to the configured guest, execution time, and available telemetry.',
]


def criteria():
    return {'version': '1.0', 'max_approve_score': settings.approval_max_score,
            'reject_score': settings.approval_reject_score,
            'require_reputation': settings.approval_require_reputation,
            'min_reputation_engines': settings.approval_min_reputation_engines,
            'required_engines': ['validation', 'hashing', 'static', 'yara', 'sandbox', 'behavior', 'network', 'verdict', 'report']}


def recommend(status, engines):
    results = {e['name']: e for e in engines}
    finding = results.get('verdict', {}).get('data', {})
    rules = finding.get('approval_policy') or criteria()
    required = rules['required_engines'] + (['virustotal'] if rules['require_reputation'] else [])
    reasons, gaps = [], []
    for name in required:
        result = results.get(name, {})
        if result.get('status') != 'COMPLETED':
            gaps.append({'engine': name, 'status': result.get('status', 'MISSING'),
                         'reason': result.get('reason') or 'Required evidence is not complete'})
    # Missing optional providers are acceptable; actual failures need review.
    for name, result in results.items():
        if name not in required and result['status'] in ('FAILED', 'TIMEOUT'):
            gaps.append({'engine': name, 'status': result['status'], 'reason': result.get('reason')})
    data = lambda name: results.get(name, {}).get('data', {})
    if not gaps:
        evidence_checks = {
            'static': bool(data('static').get('architecture') and data('static').get('sections')),
            'yara': bool(data('yara').get('rule_files')) and isinstance(data('yara').get('matches'), list),
            'sandbox': bool(data('sandbox').get('task_id') and data('sandbox').get('report')),
            'behavior': bool(data('behavior').get('processes')),
            'network': isinstance(data('network').get('events'), list),
            'verdict': isinstance(finding.get('score'), (int, float)) and bool(finding.get('security')),
        }
        for name, present in evidence_checks.items():
            if not present: gaps.append({'engine': name, 'status': 'EMPTY_EVIDENCE', 'reason': 'Completed flag has no usable evidence'})
    state = 'REVIEW_REQUIRED'
    score = finding.get('score', 0)
    if status != 'COMPLETED' or gaps:
        reasons.append('Analysis is incomplete, failed, unsupported, or missing required evidence.')
    elif score >= rules['reject_score']:
        state = 'REJECT'
        reasons.append(f"Malware score {score} meets rejection threshold {rules['reject_score']}.")
    else:
        stats = data('virustotal').get('stats', {})
        clean_votes = stats.get('harmless', 0) + stats.get('undetected', 0)
        if finding.get('security')=='INCONCLUSIVE':
            reasons.append('The malware assessment is inconclusive and requires review.')
        elif score > rules['max_approve_score'] or finding.get('security') != 'LIKELY_BENIGN':
            reasons.append(f"Malware score {score} exceeds acceptance threshold {rules['max_approve_score']}; review the findings.")
        elif finding.get('reasons'):
            reasons.append('Adverse findings require review even when the configured score permits acceptance.')
        elif rules['require_reputation'] and clean_votes < rules['min_reputation_engines']:
            reasons.append(f"Only {clean_votes} supporting reputation results; {rules['min_reputation_engines']} required.")
        else:
            state = 'APPROVE'
            reasons.append('Required analysis and telemetry completed and meet the configured acceptance criteria.')
            reasons.append(f"Malware score {score} is within acceptance threshold {rules['max_approve_score']}.")
    return {'recommendation': state, 'analysis_status': status, 'reasons': reasons,
            'findings': finding.get('reasons', []), 'coverage_gaps': gaps, 'criteria': rules,
            'limitations': LIMITATIONS}
