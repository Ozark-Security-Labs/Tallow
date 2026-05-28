import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { AuthProvider } from '../../auth/AuthContext';
import { FindingDetail } from './FindingDetail';

vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ user: { id: 'u1', email: 'viewer@example.com', roles: ['viewer'], status: 'active' }, capabilities: [] }), { status: 200 })));

describe('FindingDetail', () => {
  it('renders safe evidence excerpts and read-only viewer triage', async () => {
    render(<AuthProvider><FindingDetail /></AuthProvider>);
    expect(screen.getByText('Finding detail')).toBeInTheDocument();
    expect(screen.getByText(/postinstall/)).toBeInTheDocument();
    expect(await screen.findByText('Read-only viewer')).toBeInTheDocument();
  });
});
