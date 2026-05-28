import { Dashboard } from './routes/Dashboard';
import { Packages } from './routes/Packages';
import { Findings } from './routes/Findings';
import { Impact } from './routes/Impact';
import { AnalyzerRuns } from './routes/AnalyzerRuns';
import { Settings } from './routes/Settings';
import { Login } from './routes/Login';
import { Alerts } from './routes/Alerts';

export function RouteView() {
  const path = window.location.pathname;
  if (path === '/login') return <Login />;
  if (path.startsWith('/packages')) return <Packages />;
  if (path.startsWith('/findings')) return <Findings />;
  if (path.startsWith('/alerts')) return <Alerts />;
  if (path.startsWith('/impact')) return <Impact />;
  if (path.startsWith('/analyzer-runs')) return <AnalyzerRuns />;
  if (path.startsWith('/settings')) return <Settings />;
  return <Dashboard />;
}
