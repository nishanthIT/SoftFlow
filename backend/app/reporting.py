"""One versioned export contract for stored reports and API downloads."""
from datetime import datetime, timezone
from .approval import recommend, LIMITATIONS

OPERATIONS = {
    'validation': 'Validate executable headers and upload limits',
    'hashing': 'Compute SHA-256, SHA-1 and MD5 fingerprints',
    'static': 'Inspect PE structure, imports, sections and strings',
    'yara': 'Match configured local YARA rules',
    'virustotal': 'Look up file reputation; submit only with consent',
    'hybrid-analysis': 'Retrieve external sandbox evidence; submit only with consent',
    'sandbox': 'Submit to isolated sandbox, wait for execution and retrieve reports',
    'behavior': 'Normalize observed processes and behavior evidence',
    'network': 'Normalize captured DNS and network evidence',
    'ai': 'Evaluate AI indicators against available evidence',
    'correlation': 'Correlate source-preserving engine results',
    'verdict': 'Apply the deterministic scoring and coverage policy',
    'report': 'Export this structured analysis report',
}
TERMINAL = {'COMPLETED', 'FAILED', 'TIMEOUT', 'UNAVAILABLE', 'SKIPPED'}


def outcome(status, engines):
    if status == 'FAILED': return 'FAILED'
    if status != 'COMPLETED': return 'IN_PROGRESS'
    return 'COMPLETED' if all(e['status'] == 'COMPLETED' for e in engines) else 'COMPLETED_WITH_GAPS'


def build_report(job, sample, engines, generated_at=None):
    ordered = sorted(engines, key=lambda e: list(OPERATIONS).index(e['name']))
    errors = [{'stage': e['name'], 'status': e['status'],
               'code': e.get('data', {}).get('diagnostic', {}).get('code', e['status']),
               'message': e.get('reason') or 'Stage did not complete successfully'}
              for e in ordered if e['status'] in TERMINAL - {'COMPLETED'}]
    verdict = next((e['data'] for e in ordered if e['name'] == 'verdict'), {})
    return {
        'schema_version': '2.0', 'analysis_id': job['id'], 'id': job['id'],
        'status': job['status'], 'final_status': outcome(job['status'], ordered),
        'created_at': job.get('created_at'), 'started_at': job.get('started_at'),
        'completed_at': job.get('completed_at'),
        'generated_at': generated_at or datetime.now(timezone.utc).isoformat(),
        'sample': sample, 'external_submission_consent': job.get('consent', False),
        'progress': round(100 * sum(e['status'] in TERMINAL for e in ordered) / max(1, len(ordered))),
        'summary': {'completed_operations': sum(e['status'] == 'COMPLETED' for e in ordered),
                    'total_operations': len(ordered), 'errors_or_gaps': len(errors),
                    'sandbox_execution': next((e['status'] for e in ordered if e['name'] == 'sandbox'), 'UNAVAILABLE')},
        'steps': [{'order': i + 1, 'stage': e['name'], 'operation': OPERATIONS[e['name']],
                   'status': e['status'], 'started_at': e.get('started_at'), 'completed_at': e.get('completed_at'),
                   'error': e.get('reason'), 'evidence_reference': '/engines/' + str(i) + '/data'}
                  for i, e in enumerate(ordered)],
        'errors': errors, 'verdict': verdict, 'engines': ordered,
        'approval': recommend(job['status'], ordered), 'decisions': job.get('decisions', []),
        'vulnerability_assessment': {'status': 'NOT_PERFORMED', 'findings': [], 'reason': LIMITATIONS[1]},
        'limitations': ['Job completion means processing ended; it does not mean every engine succeeded or that the file is safe.',
                       'Sandbox snapshot restoration is managed by the configured machinery and requires operator verification.',
                       'Provider evidence may include background activity and may omit encrypted traffic or raw API calls.', *LIMITATIONS],
    }
