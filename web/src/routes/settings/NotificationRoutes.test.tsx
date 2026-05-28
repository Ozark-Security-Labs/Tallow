import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { AuthProvider } from '../../auth/AuthContext';
import { SettingsHome } from './SettingsHome';

describe('Notification route settings', () => {
  it('hides admin controls for non-admin roles', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ user: { id: 'u1', email: 'viewer@example.com', roles: ['viewer'], status: 'active' }, capabilities: ['settings:read'] }), { status: 200 })));
    render(<AuthProvider><SettingsHome /></AuthProvider>);
    expect(await screen.findByText('Read-only settings metadata')).toBeInTheDocument();
    expect(screen.queryByText('Create notification route')).not.toBeInTheDocument();
  });
});
