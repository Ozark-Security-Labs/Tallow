import { useAuth } from '../auth/AuthContext';
import { canManageSettings } from '../auth/capabilities';

const nav = [
  ['/', 'Dashboard'], ['/packages', 'Packages'], ['/findings', 'Findings'], ['/impact', 'Impact'], ['/analyzer-runs', 'Analyzer runs'], ['/settings', 'Settings'],
] as const;

export function Layout({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuth();
  const path = window.location.pathname;
  return <div className="app-shell">
    <aside>
      <h1>Tallow</h1>
      <nav>{nav.map(([href, label]) => label === 'Settings' && !canManageSettings(user?.capabilities) ? null : <a key={href} className={path === href ? 'active' : ''} href={href}>{label}</a>)}</nav>
    </aside>
    <main>
      <header><span>{user ? user.user.email : 'Not signed in'}</span>{user ? <button onClick={() => void logout()}>Logout</button> : <a href="/login">Login</a>}</header>
      {children}
    </main>
  </div>;
}
