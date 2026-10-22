"""Normalize Cuckoo 3 post.json without inventing legacy API call telemetry."""
from urllib.parse import urlsplit


def posts(sandbox):
    return [(item['task']['id'], item['post']) for item in sandbox.get('report', {}).get('tasks', [])
            if item.get('task', {}).get('state') == 'reported' and isinstance(item.get('post'), dict)]


def behavior(sandbox):
    results = posts(sandbox)
    if not results or any(not isinstance(post.get('processes'), list) or not post['processes'] for _, post in results):
        return None
    processes, events, signatures, screenshots = [], [], [], []
    for task_id, post in results:
        for process in post['processes']:
            processes.append({**process, 'task_id': task_id, 'process_name': process.get('name')})
            events.append({'category': 'execution', 'severity': 'low', 'source': 'cuckoo3',
                           'task_id': task_id, 'process': process.get('name'), 'timestamp': process.get('start_ts'),
                           'timestamp_unit': 'milliseconds_since_monitor_start', 'technique': None,
                           'evidence': {'pid': process.get('pid'), 'image': process.get('image'),
                                        'commandline': process.get('commandline')}})
        for signature in post.get('signatures', []):
            signatures.append({**signature, 'task_id': task_id})
            score = signature.get('score', 0)
            events.append({'category': 'sandbox_signature', 'severity': 'high' if score >= 9 else 'medium' if score >= 6 else 'low',
                           'source': 'cuckoo3', 'task_id': task_id, 'timestamp': None, 'process': None,
                           'technique': None, 'techniques': signature.get('ttps', []), 'evidence': signature})
        screenshots.extend({**item, 'task_id': task_id} for item in post.get('screenshot', []))
    return {'events': events[:10000], 'processes': processes, 'process_tree': [], 'summary': {},
            'signatures': signatures, 'screenshots': screenshots, 'dropped_files': [],
            'limitations': 'Cuckoo 3 post reports provide process metadata and signatures. Raw API calls and dropped-file binaries are not exposed by this adapter.'}


def network(sandbox):
    results = posts(sandbox)
    keys = {'dns', 'http', 'https', 'tcp', 'udp'}
    if not results or any(not isinstance(p.get('network'), dict) or not keys.intersection(p['network']) for _, p in results):
        return None
    events, domains, ips = [], set(), set()
    for task_id, post in results:
        raw = post['network']
        for query in raw.get('dns', {}).get('query', []):
            events.append({'type': 'dns', 'domain': query.get('name'), 'query_type': query.get('type'),
                           'timestamp': query.get('ts'), 'task_id': task_id, 'source': 'cuckoo3'})
        for proto in ('http', 'https'):
            for item in raw.get(proto, []):
                request = item.get('request', {})
                url = request.get('url') or ''
                try: hostname = urlsplit(url).hostname
                except ValueError: hostname = None
                events.append({'type': request.get('protocol', proto), 'host': hostname, 'url': url,
                               'method': request.get('method'), 'ip': item.get('dstip'), 'port': item.get('dstport'),
                               'timestamp': item.get('ts'), 'task_id': task_id, 'source': 'cuckoo3'})
        for proto in ('tcp', 'udp'):
            for item in raw.get(proto, []):
                events.append({'type': proto, 'ip': item.get('dstip'), 'port': item.get('dstport'),
                               'timestamp': item.get('ts'), 'task_id': task_id, 'source': 'cuckoo3'})
        domains.update(str(x) for x in raw.get('domain', []))
        ips.update(str(x) for x in raw.get('host', []))
    domains.update(str(e.get('domain') or e.get('host')) for e in events if e.get('domain') or e.get('host'))
    ips.update(str(e['ip']) for e in events if e.get('ip'))
    return {'events': events[:10000], 'domains': sorted(domains), 'ips': sorted(ips),
            'capture_scope': 'Cuckoo 3 processed packet metadata. Events may include background guest traffic; absent traffic does not prove safety.'}
