export type FindingFilterState = { ecosystem: string; packageName: string; severity: string; confidence: string; status: string };
export function FindingsFilters({ filters, onChange }: { filters: FindingFilterState; onChange: (filters: FindingFilterState) => void }) {
  const update = (key: keyof FindingFilterState, value: string) => onChange({ ...filters, [key]: value });
  return <form className="filters" aria-label="Finding filters">
    <input aria-label="Ecosystem" value={filters.ecosystem} onChange={(e) => update('ecosystem', e.target.value)} placeholder="ecosystem" />
    <input aria-label="Package" value={filters.packageName} onChange={(e) => update('packageName', e.target.value)} placeholder="package" />
    <select aria-label="Severity" value={filters.severity} onChange={(e) => update('severity', e.target.value)}><option value="">any severity</option><option>high</option><option>critical</option></select>
    <select aria-label="Confidence" value={filters.confidence} onChange={(e) => update('confidence', e.target.value)}><option value="">any confidence</option><option>high</option><option>medium</option></select>
    <select aria-label="Status" value={filters.status} onChange={(e) => update('status', e.target.value)}><option value="">any status</option><option>open</option><option>resolved</option></select>
  </form>;
}
