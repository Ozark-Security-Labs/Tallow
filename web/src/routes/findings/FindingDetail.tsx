import type { Finding } from '../../api/generated';
import { EvidencePanel } from './EvidencePanel';
import { TriageActions } from './TriageActions';
const sample: Finding = { id: 'fin-1', rule_id: 'npm.lifecycle.install_script', package_name: 'left-pad', version: '1.3.0', severity: 'high', confidence: 'high', status: 'open', summary: 'Signals requiring review were found in package metadata.', evidence_refs: [{ type: 'file', ref: 'package.json', path: 'package.json', excerpt: '{"scripts":{"install":"node postinstall.js"}}', excerpt_safe: true }] };
export function FindingDetail({ finding = sample }: { finding?: Finding }) { return <section><h2>Finding detail</h2><p>{finding.summary}</p><dl><dt>Rule</dt><dd>{finding.rule_id}</dd><dt>Package</dt><dd>{finding.package_name}@{finding.version}</dd><dt>Severity</dt><dd>{finding.severity}</dd></dl><EvidencePanel evidence={finding.evidence_refs ?? []} /><TriageActions /></section>; }
