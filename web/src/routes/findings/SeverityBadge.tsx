export function SeverityBadge({ severity }: { severity?: string }) { return <span className={`badge severity-${severity ?? 'unknown'}`}>{severity ?? 'unknown'}</span>; }
