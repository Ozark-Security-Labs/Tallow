import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { PackageDetail } from './PackageDetail';

describe('PackageDetail', () => {
  it('shows observations, runs, findings, and artifact metadata without raw content', () => {
    render(<PackageDetail />);
    expect(screen.getByText('Package detail')).toBeInTheDocument();
    expect(screen.getByText(/Observation:/)).toBeInTheDocument();
    expect(screen.getByText(/Analyzer run:/)).toBeInTheDocument();
    expect(screen.getByText(/Related finding:/)).toBeInTheDocument();
    expect(screen.getByText(/raw artifact content is not rendered/i)).toBeInTheDocument();
  });
});
