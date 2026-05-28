import { useAuth } from '../../auth/AuthContext';
export function TriageActions() { const { user } = useAuth(); const canTriage = user?.capabilities.includes('findings:triage'); return <div>{canTriage ? <button>Acknowledge finding</button> : <span>Read-only viewer</span>}</div>; }
