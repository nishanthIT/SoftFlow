"""Count-based verdicts. Provider severity scores/percentages are not engine counts."""
from .config import settings


def nonnegative_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def assess(results):
    threshold = settings.detection_review_threshold
    counts, conflicts = [], []
    def completed(name):
        entry = results.get(name, {})
        return entry.get('data', {}) if entry.get('status') == 'COMPLETED' else {}
    vt = completed('virustotal')
    stats = vt.get('stats', {})
    if isinstance(stats,dict) and stats and all(nonnegative_int(v) for v in stats.values()) and sum(stats.get(k,0) for k in ('malicious','harmless','undetected','suspicious')) > 0:
        counts.append({'source':'virustotal','count':stats.get('malicious',0), 'basis':'malicious antivirus engines'})
        if stats.get('suspicious',0): conflicts.append('Suspicious reputation evidence requires review.')
    elif results.get('virustotal', {}).get('status') == 'COMPLETED':
        conflicts.append('A completed reputation result contains no usable engine counts.')
    ha = completed('hybrid-analysis')
    raw = ha.get('raw', {})
    # Never interpret av_detect (a rate), threat_score, or verdict text as a count.
    matched, total = raw.get('av_matched'), raw.get('av_total')
    if nonnegative_int(matched) and nonnegative_int(total) and total > 0 and matched <= total:
        counts.append({'source':'hybrid-analysis','count':matched, 'basis':'reported antivirus engines'})
    elif results.get('hybrid-analysis',{}).get('status')=='COMPLETED' and ha.get('verdict') not in ('no specific threat','no-threat','clean','benign'):
        conflicts.append('Behavioral reputation findings require manual review; no comparable engine count was supplied.')
    yara = completed('yara').get('matches', [])
    if yara: conflicts.append('Matched local detection rules require manual review.')
    behavior = completed('behavior')
    if any(e.get('severity') in ('high','critical') for e in behavior.get('events', [])):
        conflicts.append('Observed high-severity behavior requires manual review.')
    sandbox = completed('sandbox')
    report = sandbox.get('report', {})
    reports = [t.get('post',{}) for t in report.get('tasks',[])] if sandbox.get('source')=='cuckoo3' else [report]
    if any(r.get('signatures') or (isinstance(r.get('score'), (int,float)) and r['score']>0) for r in reports):
        conflicts.append('Sandbox findings require manual review; sandbox scores are not antivirus engine counts.')
    required = ['validation','hashing','static','yara','sandbox','behavior','network','dns']
    if settings.approval_require_reputation: required.append('virustotal')
    if settings.virustotal_api_key: required.append('virustotal')
    if settings.hybrid_analysis_api_key: required.append('hybrid-analysis')
    complete = all(results.get(name, {}).get('status') == 'COMPLETED' for name in required)
    complete = complete and bool(sandbox.get('task_id') and report and behavior.get('processes'))
    complete = complete and isinstance(completed('network').get('events'),list)
    complete = complete and isinstance(completed('dns').get('queries'),list) and isinstance(completed('dns').get('responses'),list)
    complete = complete and bool(completed('static').get('sections'))
    complete = complete and bool(completed('yara').get('rule_files'))
    # Do not add overlapping antivirus votes from different services together.
    count = max((c['count'] for c in counts), default=None)
    if count is not None and count > threshold:
        state = 'MALICIOUS'
    elif not complete or conflicts or count == threshold:
        state = 'MANUAL_REVIEW'
    else:
        state = 'LEGITIMATE'
    return {'security':state, 'detection_count':count, 'detection_sources':counts,
            'review_threshold':threshold, 'detection_basis':'maximum reported antivirus engine count; sources are not summed',
            'required_evidence_complete':bool(complete), 'review_reasons':conflicts,
            'explanation':f'Fewer than {threshold} reported antivirus detections qualify as legitimate when required analysis is complete and findings do not conflict. '
                          f'Exactly {threshold} detections, conflicting findings, or partial evidence require manual review; more than {threshold} detections are malicious. '
                          'Cuckoo-only analyses can qualify after completed execution with no adverse findings. This classification is not a guarantee of safety.'}
