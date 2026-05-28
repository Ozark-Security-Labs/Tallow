import { useAuth } from '../../auth/AuthContext';
export function SettingsHome() { const { user } = useAuth(); const admin = user?.capabilities.includes('notifications:manage'); return <section><h2>Settings</h2><p>Non-secret auth and notification metadata.</p>{admin ? <button>Create notification route</button> : <span>Read-only settings metadata</span>}</section>; }
