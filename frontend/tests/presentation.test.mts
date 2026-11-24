import assert from 'node:assert/strict';
import test from 'node:test';
import {securityState, visibleEngines, hasAiResult} from '../src/lib/presentation.ts';

test('only three verdict states, including saved legacy values', () => {
  const cases = [
    ['LEGITIMATE', 'LEGITIMATE'], ['LIKELY_BENIGN', 'LEGITIMATE'],
    ['MALICIOUS', 'MALICIOUS'], ['LIKELY_MALICIOUS', 'MALICIOUS'],
    ['INCONCLUSIVE', 'PARTIAL'], ['MANUAL_REVIEW', 'PARTIAL'],
    ['SUSPICIOUS', 'PARTIAL'], ['PARTIAL', 'PARTIAL'], [null, 'PARTIAL'],
  ] as const;
  for (const [input, expected] of cases) assert.equal(securityState(input), expected);
});

test('unavailable providers and empty AI results are hidden, local failures stay actionable', () => {
  const rows = [
    {name: 'sandbox', status: 'UNAVAILABLE', data: {}},
    {name: 'virustotal', status: 'TIMEOUT', data: {}},
    {name: 'hybrid-analysis', status: 'RUNNING', data: {}},
    {name: 'network', status: 'UNREACHABLE', data: {}},
    {name: 'ai', status: 'COMPLETED', data: {status: 'INCONCLUSIVE', indicators: []}},
    {name: 'report', status: 'FAILED', reason: 'private-host', data: {diagnostic: 'private-host'}},
    {name: 'verdict', status: 'COMPLETED', data: {security: 'MANUAL_REVIEW'}},
  ];
  const projected = visibleEngines(rows);
  assert.deepEqual(projected.map(row => row.name), ['report', 'verdict']);
  assert.equal(projected[1].data.security, 'PARTIAL');
  assert.ok(!JSON.stringify(projected).includes('private-host'));
  assert.equal(rows[6].data.security, 'MANUAL_REVIEW');
  assert.deepEqual(visibleEngines(projected), projected);
  assert.ok(hasAiResult({status: 'NOT_OBSERVED'}));
  assert.ok(!hasAiResult({status: 'PARTIAL', indicators: []}));
});

test('keep partial vulnerability findings and completed sources without failure details', () => {
  const projected = visibleEngines([
    {name: 'vulnerabilities', status: 'UNAVAILABLE', reason: 'offline-source', data: {
      status: 'PARTIAL', reason: 'offline-source', findings: [{id: 'CVE-test'}],
      providers: [{provider: 'offline-source', status: 'UNAVAILABLE'}, {provider: 'completed-source', status: 'COMPLETED'}],
    }},
  ]);
  assert.equal(projected[0].status, 'PARTIAL');
  assert.equal(projected[0].data.findings[0].id, 'CVE-test');
  assert.ok(!JSON.stringify(projected).includes('offline-source'));
  assert.equal(projected[0].data.providers[0].provider, 'completed-source');
  assert.deepEqual(visibleEngines([{name: 'vulnerabilities', status: 'UNAVAILABLE', data: {status: 'PARTIAL', findings: []}}]), []);
});
