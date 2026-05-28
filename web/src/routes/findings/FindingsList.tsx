import { useMemo, useState } from 'react';
import type { Finding } from '../../api/generated';
import { EmptyState } from '../../components/EmptyState';
import { FindingsFilters, type FindingFilterState } from './FindingsFilters';
import { SeverityBadge } from './SeverityBadge';
import { FindingStatusBadge } from './FindingStatusBadge';

export const sampleFindings: Finding[] = [{ id: 'fin-1', rule_id: 'npm.lifecycle.install_script', package_name: 'left-pad', version: '1.3.0', severity: 'high', confidence: 'high', status: 'open', summary: 'Install script behavior produced signals requiring review.', evidence_count: 1 }];
export function FindingsList({ items = sampleFindings }: { items?: Finding[] }) {
  const [filters, setFilters] = useState<FindingFilterState>({ ecosystem: '', packageName: '', severity: '', confidence: '', status: '' });
  const filtered = useMemo(() => items.filter((item) => (!filters.packageName || item.package_name?.includes(filters.packageName)) && (!filters.severity || item.severity === filters.severity) && (!filters.confidence || item.confidence === filters.confidence) && (!filters.status || item.status === filters.status)), [items, filters]);
  return <section><h2>Findings</h2><FindingsFilters filters={filters} onChange={setFilters} />{filtered.length === 0 ? <EmptyState title="No findings match" message="Adjust filters or wait for analyzer results." /> : <table><thead><tr><th>Package</th><th>Version</th><th>Severity</th><th>Confidence</th><th>Status</th><th>Rules</th><th>Evidence</th></tr></thead><tbody>{filtered.map((item) => <tr key={item.id}><td>{item.package_name}</td><td>{item.version}</td><td><SeverityBadge severity={item.severity} /></td><td>{item.confidence}</td><td><FindingStatusBadge status={String(item.status)} /></td><td>{item.rule_id}</td><td>{item.evidence_count ?? item.evidence_refs?.length ?? 0}</td></tr>)}</tbody></table>}</section>;
}
