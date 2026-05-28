import type { EvidenceRef } from '../../api/generated';
export function EvidencePanel({ evidence }: { evidence: EvidenceRef[] }) {
  if (evidence.length === 0) return <p>No evidence references are available yet.</p>;
  return <ul>{evidence.map((item) => <li key={`${item.type}:${item.ref}`}><strong>{item.type}</strong> {item.path ?? item.ref}{item.line ? `:${item.line}` : ''}{item.excerpt && item.excerpt_safe ? <pre>{item.excerpt}</pre> : item.excerpt ? <em>Excerpt withheld until marked safe by the API.</em> : null}</li>)}</ul>;
}
