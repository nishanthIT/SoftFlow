/** Display policy shared by tables, analysis pages, and the printable report. */
export type SecurityState = 'LEGITIMATE' | 'MALICIOUS' | 'PARTIAL';

export function securityState(value?: string | null): SecurityState {
  if (value === 'LEGITIMATE' || value === 'LIKELY_BENIGN') return 'LEGITIMATE';
  if (value === 'MALICIOUS' || value === 'LIKELY_MALICIOUS') return 'MALICIOUS';
  return 'PARTIAL';
}

const hidden = new Set([
  'FAILED', 'TIMEOUT', 'UNAVAILABLE', 'UNREACHABLE', 'SKIPPED', 'NOT_CONFIGURED', 'DISABLED',
  'NOT_PERFORMED', 'NOT_AVAILABLE', 'MISSING', 'ERROR', 'API_TOKEN_REQUIRED', 'INVALID_API_TOKEN',
  'INVALID_REQUEST', 'NETWORK_UNAVAILABLE', 'API_UNAVAILABLE', 'INVALID_API_KEY', 'ACCESS_DENIED',
  'RATE_LIMITED', 'ANALYSIS_UNAVAILABLE', 'INVALID_RESPONSE', 'CORE_NOT_READY',
  'NO_ANALYSIS_MACHINE', 'ISOLATION_REQUIRED',
]);
const external = new Set(['sandbox', 'virustotal', 'hybrid-analysis']);

export function isAvailable(status?: string): boolean {
  return !!status && !hidden.has(status.toUpperCase());
}

export function hasVulnerabilityResult(data: Record<string, any>): boolean {
  return data.status === 'COMPLETED' || !!data.findings?.length ||
    !!data.providers?.some((p: {status?: string}) => p.status === 'COMPLETED');
}

export function hasAiResult(data: Record<string, any>): boolean {
  return isAvailable(data.status) &&
    (!['INCONCLUSIVE', 'MANUAL_REVIEW', 'PARTIAL'].includes(data.status) || !!data.indicators?.length);
}

type Engine = {name: string; status: string; reason?: string; data: Record<string, any>};

/** Also guards pages against older API responses or cached query data. */
export function visibleEngines<T extends Engine>(rows: T[]): T[] {
  return rows.flatMap(row => {
    if (row.name === 'vulnerabilities' && !['QUEUED', 'RUNNING'].includes(row.status)) {
      if (!hasVulnerabilityResult(row.data)) return [];
      if (row.status !== 'COMPLETED' || row.data.status !== 'COMPLETED') {
        const reason = 'Assessment is partial; manual review is needed.';
        return [{...row, status: 'PARTIAL', reason, data: {...row.data, status: 'PARTIAL', reason,
          providers: row.data.providers?.filter((p: {status?: string}) => p.status === 'COMPLETED')}}];
      }
    }
    if (!isAvailable(row.status)) {
      return ['validation', 'hashing', 'report'].includes(row.name) && row.status === 'FAILED'
        ? [{...row, reason: 'This analysis stage could not finish.', data: {}}] : [];
    }
    if (external.has(row.name) && (row.status !== 'COMPLETED' || (row.data.status && !isAvailable(row.data.status)))) return [];
    if (row.name === 'ai' && row.status === 'COMPLETED' && !hasAiResult(row.data)) return [];
    if (row.name === 'verdict') return [{...row, data: {...row.data, security: securityState(row.data.security)}}];
    return [row];
  });
}
