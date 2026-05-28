import { AuthProvider } from './auth/AuthContext';
import { Layout } from './components/Layout';
import { RouteView } from './routes';
import './styles.css';

export function App() {
  return <AuthProvider><Layout><RouteView /></Layout></AuthProvider>;
}
