import { FormEvent, useEffect, useState } from 'react';
import { api } from '../api/client';
import type { AuthProvider } from '../api/generated';
import { ErrorState } from '../components/ErrorState';
import { LoadingState } from '../components/LoadingState';

export function Login() {
  const [providers, setProviders] = useState<AuthProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  useEffect(() => { void api.providers().then((res) => setProviders(res.items)).catch(() => setError('Unable to load auth providers')).finally(() => setLoading(false)); }, []);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    await api.localLogin(email, password);
    window.location.href = '/';
  };
  if (loading) return <LoadingState label="Loading auth providers" />;
  return <section><h2>Login</h2>{error ? <ErrorState message={error} /> : null}{providers.some((p) => p.provider === 'local' || p.name === 'local') ? <form onSubmit={(event) => void submit(event)}><label>Email <input value={email} onChange={(e) => setEmail(e.target.value)} /></label><label>Password <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></label><button type="submit">Sign in locally</button></form> : null}{providers.filter((p) => p.type === 'oauth').map((provider) => <a className="button-link" key={provider.name} href={provider.login_url ?? `/v1/auth/${provider.name}/login`}>Continue with {provider.label ?? provider.name}</a>)}</section>;
}
