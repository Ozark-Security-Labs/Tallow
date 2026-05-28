export function FindingStatusBadge({ status }: { status?: string }) { return <span className="badge">{status ?? 'open'}</span>; }
