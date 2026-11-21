import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import App from './App';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  localStorage.clear();
});

const health = {
  service: 'BLACK ICE', version: '0.1.0', status: 'restricted', security_core: 'restricted',
  components: { tse_signing: 'unavailable' },
  audit_integrity: { valid: true, events_total: 0, events_verified: 0, first_invalid_sequence: null, tamper_evident_not_immutable: true },
  limitations: [],
};

describe('BLACK ICE operator console', () => {
  it('keeps protected API data locked until an operator token is entered', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => health });
    vi.stubGlobal('fetch', fetchMock);
    render(<MemoryRouter><App /></MemoryRouter>);

    expect(screen.getByText('Operator authorization required')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'ICE-VISION' })).toHaveAttribute('href', '/vision');
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/health', expect.any(Object)));
    expect(fetchMock.mock.calls.some(([url]) => url === '/api/overview')).toBe(false);
  });

  it('sends the entered bearer token to the API without persisting it to browser storage', async () => {
    const overview = {
      status: 'ready',
      counts: { tasks_active: 1, tasks_total: 1, decisions_recent: 0, inspections_total: 0, audit_events: 0, decision_outcomes: {} },
      recent_decisions: [], recent_inspections: [],
      audit_integrity: health.audit_integrity,
      security_boundary: { gateway: 'registered operations only' },
    };
    const fetchMock = vi.fn().mockImplementation(async (url: string) => ({
      ok: true,
      json: async () => url === '/api/overview' ? overview : health,
    }));
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<MemoryRouter><App /></MemoryRouter>);
    await user.type(screen.getByLabelText('Operator bearer token'), 'test-only-operator-token');
    await user.click(screen.getByRole('button', { name: /unlock console/i }));

    await waitFor(() => expect(screen.getByText('1')).toBeInTheDocument());
    const overviewCall = fetchMock.mock.calls.find(([url]) => url === '/api/overview');
    expect(overviewCall).toBeDefined();
    const headers = overviewCall?.[1]?.headers as Headers;
    expect(headers.get('Authorization')).toBe('Bearer test-only-operator-token');
    expect(localStorage.length).toBe(0);
  });
});
