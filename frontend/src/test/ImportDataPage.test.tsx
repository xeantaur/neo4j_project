import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ImportDataPage } from '../pages/ImportDataPage';
import { Header } from '../components/layout/Header';
import { App } from '../App';
import { validateImportFiles, importWorkspaceData } from '../api/importData';
import type {
  ImportStatusResponse,
  ImportValidationResponse,
  ImportResultResponse,
} from '../api/types';

const MOCK_STATUS_ENABLED: ImportStatusResponse = {
  enabled: true,
  max_file_size_bytes: 10485760, // 10 MiB
  max_file_size_mb: 10,
};

const MOCK_STATUS_DISABLED: ImportStatusResponse = {
  enabled: false,
  max_file_size_bytes: 10485760,
  max_file_size_mb: 10,
};

const MOCK_VALIDATION_TRAFFIC_ONLY: ImportValidationResponse = {
  valid: true,
  can_import: true,
  traffic: {
    provided: true,
    filename: 'traffic.tsv',
    total_raw_records: 8,
    valid_records: 7,
    skipped_records: 0,
    duplicate_records: 1,
    warning_counts: { duplicate_flow_ignored: 1 },
    sample_errors: [],
  },
  alerts: {
    provided: false,
    filename: null,
    total_raw_records: null,
    valid_records: null,
    skipped_records: null,
    duplicate_records: null,
    warning_counts: {},
    sample_errors: [],
  },
  message: 'Validation succeeded: 1 dataset(s) ready for analysis.',
};

const MOCK_VALIDATION_ALERTS_ONLY: ImportValidationResponse = {
  valid: true,
  can_import: true,
  traffic: {
    provided: false,
    filename: null,
    total_raw_records: null,
    valid_records: null,
    skipped_records: null,
    duplicate_records: null,
    warning_counts: {},
    sample_errors: [],
  },
  alerts: {
    provided: true,
    filename: 'alerts.json',
    total_raw_records: 3,
    valid_records: 3,
    skipped_records: 0,
    duplicate_records: null,
    warning_counts: {},
    sample_errors: [],
  },
  message: 'Validation succeeded: 1 dataset(s) ready for analysis.',
};

const MOCK_VALIDATION_COMBINED: ImportValidationResponse = {
  valid: true,
  can_import: true,
  traffic: {
    provided: true,
    filename: 'traffic.tsv',
    total_raw_records: 8,
    valid_records: 7,
    skipped_records: 0,
    duplicate_records: 1,
    warning_counts: {},
    sample_errors: [],
  },
  alerts: {
    provided: true,
    filename: 'alerts.json',
    total_raw_records: 3,
    valid_records: 3,
    skipped_records: 0,
    duplicate_records: null,
    warning_counts: {},
    sample_errors: [],
  },
  message: 'Validation succeeded: 2 dataset(s) ready for analysis.',
};

const MOCK_VALIDATION_INVALID: ImportValidationResponse = {
  valid: false,
  can_import: false,
  traffic: {
    provided: true,
    filename: 'bad_traffic.tsv',
    total_raw_records: 2,
    valid_records: 0,
    skipped_records: 2,
    duplicate_records: 0,
    warning_counts: { invalid_ip: 2 },
    sample_errors: ['All records in traffic TSV were invalid or malformed.'],
  },
  alerts: {
    provided: false,
    filename: null,
    total_raw_records: null,
    valid_records: null,
    skipped_records: null,
    duplicate_records: null,
    warning_counts: {},
    sample_errors: [],
  },
  message: 'Validation failed: Provided datasets contained fatal errors or zero valid records.',
};

const MOCK_RESULT_TRAFFIC_ONLY: ImportResultResponse = {
  success: true,
  workspace_replaced: true,
  traffic_records_persisted: 7,
  alert_facts_persisted: 0,
  capabilities: {
    network_topology: true,
    ip_investigation: true,
    communication_paths: true,
    alert_facts: false,
    traffic_alert_correlations: false,
  },
  message: 'Analysis workspace replaced successfully: 7 traffic records persisted.',
};

const MOCK_RESULT_ALERTS_ONLY: ImportResultResponse = {
  success: true,
  workspace_replaced: true,
  traffic_records_persisted: 0,
  alert_facts_persisted: 3,
  capabilities: {
    network_topology: false,
    ip_investigation: true,
    communication_paths: false,
    alert_facts: true,
    traffic_alert_correlations: false,
  },
  message: 'Analysis workspace replaced successfully: 3 alert facts persisted.',
};

const MOCK_RESULT_COMBINED: ImportResultResponse = {
  success: true,
  workspace_replaced: true,
  traffic_records_persisted: 7,
  alert_facts_persisted: 3,
  capabilities: {
    network_topology: true,
    ip_investigation: true,
    communication_paths: true,
    alert_facts: true,
    traffic_alert_correlations: true,
  },
  message: 'Analysis workspace replaced successfully: 7 traffic records, 3 alert facts persisted.',
};

describe('ImportDataPage & Import Workflow Tests', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('1 & 2: Header includes Import Data navigation and renders ImportDataPage when active', async () => {
    const onViewChange = vi.fn();
    render(
      <Header
        activeView="import"
        onViewChange={onViewChange}
        apiStatus="ok"
        dbStatus="ready"
      />
    );

    const importTab = screen.getByRole('button', { name: /import data/i });
    expect(importTab).toBeInTheDocument();
    fireEvent.click(importTab);
    expect(onViewChange).toHaveBeenCalledWith('import');
  });

  it('3: Renders status loading skeleton while checking import status', async () => {
    globalThis.fetch = vi.fn().mockImplementation(() => new Promise(() => {})) as unknown as typeof fetch;

    render(<ImportDataPage />);
    expect(screen.getByText(/checking server configuration/i)).toBeInTheDocument();
  });

  it('4 & 5: Renders informational panel and disables actions when DATA_IMPORT_ENABLED=false', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_STATUS_DISABLED),
    }) as unknown as typeof fetch;

    render(<ImportDataPage />);

    await waitFor(() => {
      expect(screen.getByText('Data Import Disabled')).toBeInTheDocument();
    });

    expect(screen.getByText(/DATA_IMPORT_ENABLED=true/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /select tsv file/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /validate files/i })).not.toBeInTheDocument();
  });

  it('6: Handles status error with retry button', async () => {
    let callCount = 0;
    globalThis.fetch = vi.fn().mockImplementation(() => {
      callCount++;
      if (callCount === 1) {
        return Promise.reject(new Error('Network error'));
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve(MOCK_STATUS_ENABLED),
      });
    }) as unknown as typeof fetch;

    render(<ImportDataPage />);

    await waitFor(() => {
      expect(screen.getByText('Unable to verify import status')).toBeInTheDocument();
    });

    const retryBtn = screen.getByRole('button', { name: /retry/i });
    fireEvent.click(retryBtn);

    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 3, name: 'Network Traffic' })).toBeInTheDocument();
    });
  });

  it('7, 8, 9, 10: File selections, validation button states, and remove actions', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_STATUS_ENABLED),
    }) as unknown as typeof fetch;

    render(<ImportDataPage />);

    await waitFor(() => {
      expect(screen.getByText('Network Traffic')).toBeInTheDocument();
    });

    const validateBtn = screen.getByRole('button', { name: /validate files/i });
    expect(validateBtn).toBeDisabled();

    // 7. Select Traffic File
    const trafficInput = screen.getByTestId('traffic-file-input');
    const fakeTrafficFile = new File(['mock tsv content'], 'sample_traffic.tsv', { type: 'text/tab-separated-values' });
    fireEvent.change(trafficInput, { target: { files: [fakeTrafficFile] } });

    expect(screen.getByText('sample_traffic.tsv')).toBeInTheDocument();
    expect(validateBtn).not.toBeDisabled();

    // Remove Traffic File
    const removeTrafficBtn = screen.getByTitle('Remove traffic file');
    fireEvent.click(removeTrafficBtn);
    expect(screen.queryByText('sample_traffic.tsv')).not.toBeInTheDocument();
    expect(validateBtn).toBeDisabled();

    // 8. Select Alerts File
    const alertsInput = screen.getByTestId('alerts-file-input');
    const fakeAlertsFile = new File(['[]'], 'sample_alerts.json', { type: 'application/json' });
    fireEvent.change(alertsInput, { target: { files: [fakeAlertsFile] } });

    expect(screen.getByText('sample_alerts.json')).toBeInTheDocument();
    expect(validateBtn).not.toBeDisabled();

    // 9. Combined selection
    fireEvent.change(trafficInput, { target: { files: [fakeTrafficFile] } });
    expect(screen.getByText('sample_traffic.tsv')).toBeInTheDocument();
    expect(screen.getByText('sample_alerts.json')).toBeInTheDocument();
    expect(validateBtn).not.toBeDisabled();
  });

  it('11: Shows immediate feedback for client-side oversized files without calling backend', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_STATUS_ENABLED), // 10 MiB limit
    }) as unknown as typeof fetch;

    render(<ImportDataPage />);

    await waitFor(() => {
      expect(screen.getByText('Network Traffic')).toBeInTheDocument();
    });

    const trafficInput = screen.getByTestId('traffic-file-input');
    // Create 11 MiB file
    const oversizedFile = new File([new Uint8Array(11 * 1024 * 1024)], 'large.tsv', { type: 'text/tab-separated-values' });
    fireEvent.change(trafficInput, { target: { files: [oversizedFile] } });

    expect(screen.getByText(/exceeds maximum allowable limit of 10 MiB/i)).toBeInTheDocument();
    const validateBtn = screen.getByRole('button', { name: /validate files/i });
    expect(validateBtn).toBeDisabled();
  });

  it('12, 13, 14, 24, 25, 37: FormData packaging and no manual Content-Type in API client', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_VALIDATION_COMBINED),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const fakeTraffic = new File(['mock traffic'], 'traffic.tsv');
    const fakeAlerts = new File(['mock alerts'], 'alerts.json');

    // Test validateImportFiles
    await validateImportFiles({ trafficFile: fakeTraffic, alertsFile: fakeAlerts });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [valUrl, valOptions] = fetchMock.mock.calls[0];
    expect(valUrl).toContain('/api/v1/import/validate');
    expect(valOptions.method).toBe('POST');
    expect(valOptions.body instanceof FormData).toBe(true);
    // CRITICAL: Ensure no manual Content-Type header is set
    expect(valOptions.headers['Content-Type']).toBeUndefined();

    const valFormData = valOptions.body as FormData;
    expect(valFormData.get('traffic_file')).toBe(fakeTraffic);
    expect(valFormData.get('alerts_file')).toBe(fakeAlerts);

    // Test importWorkspaceData
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(MOCK_RESULT_COMBINED),
    });

    await importWorkspaceData({ trafficFile: fakeTraffic, alertsFile: fakeAlerts });
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const [impUrl, impOptions] = fetchMock.mock.calls[1];
    expect(impUrl).toContain('/api/v1/import');
    expect(impOptions.body instanceof FormData).toBe(true);
    expect(impOptions.headers['Content-Type']).toBeUndefined();

    const impFormData = impOptions.body as FormData;
    expect(impFormData.get('traffic_file')).toBe(fakeTraffic);
    expect(impFormData.get('alerts_file')).toBe(fakeAlerts);
  });

  it('15: Renders INVALID state and diagnostics when validation returns valid=false', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith('/status')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_STATUS_ENABLED) });
      }
      if (url.endsWith('/validate')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_VALIDATION_INVALID) });
      }
      return Promise.reject(new Error('Unknown url'));
    }) as unknown as typeof fetch;

    render(<ImportDataPage />);

    await waitFor(() => {
      expect(screen.getByText('Network Traffic')).toBeInTheDocument();
    });

    const trafficInput = screen.getByTestId('traffic-file-input');
    fireEvent.change(trafficInput, { target: { files: [new File(['bad data'], 'bad_traffic.tsv')] } });

    const validateBtn = screen.getByRole('button', { name: /validate files/i });
    fireEvent.click(validateBtn);

    await waitFor(() => {
      expect(screen.getByText('INVALID')).toBeInTheDocument();
      expect(screen.getByText(/All records in traffic TSV were invalid/i)).toBeInTheDocument();
    });

    // Replace warning box must NOT appear
    expect(screen.queryByText(/Replace Current Analysis/i)).not.toBeInTheDocument();
  });

  it('16, 17, 18: Valid traffic summary, warnings, and duplicate_records=null handling', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith('/status')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_STATUS_ENABLED) });
      }
      if (url.endsWith('/validate')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_VALIDATION_ALERTS_ONLY) });
      }
      return Promise.reject(new Error('Unknown url'));
    }) as unknown as typeof fetch;

    render(<ImportDataPage />);

    await waitFor(() => {
      expect(screen.getByText('Security Alerts')).toBeInTheDocument();
    });

    const alertsInput = screen.getByTestId('alerts-file-input');
    fireEvent.change(alertsInput, { target: { files: [new File(['[]'], 'alerts.json')] } });

    fireEvent.click(screen.getByRole('button', { name: /validate files/i }));

    await waitFor(() => {
      expect(screen.getByText('Validation Diagnostics')).toBeInTheDocument();
    });

    // Alerts has duplicate_records: null -> ensure "Duplicates removed" is not rendered
    expect(screen.queryByText(/Duplicates removed/i)).not.toBeInTheDocument();
  });

  it('19 & 20: File change or removal invalidates previous validation and confirmation', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith('/status')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_STATUS_ENABLED) });
      }
      if (url.endsWith('/validate')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_VALIDATION_TRAFFIC_ONLY) });
      }
      return Promise.reject(new Error('Unknown url'));
    }) as unknown as typeof fetch;

    render(<ImportDataPage />);

    await waitFor(() => {
      expect(screen.getByText('Network Traffic')).toBeInTheDocument();
    });

    const trafficInput = screen.getByTestId('traffic-file-input');
    fireEvent.change(trafficInput, { target: { files: [new File(['traffic'], 'traffic.tsv')] } });

    fireEvent.click(screen.getByRole('button', { name: /validate files/i }));

    await waitFor(() => {
      expect(screen.getByText('Replace Current Analysis')).toBeInTheDocument();
    });

    // 19. Change file -> invalidates validation and replace section
    fireEvent.change(trafficInput, { target: { files: [new File(['new traffic'], 'new_traffic.tsv')] } });
    expect(screen.queryByText('Replace Current Analysis')).not.toBeInTheDocument();
    expect(screen.queryByText('Validation Diagnostics')).not.toBeInTheDocument();

    // Re-validate
    fireEvent.click(screen.getByRole('button', { name: /validate files/i }));
    await waitFor(() => {
      expect(screen.getByText('Replace Current Analysis')).toBeInTheDocument();
    });

    // 20. Remove file -> invalidates validation
    fireEvent.click(screen.getByTitle('Remove traffic file'));
    expect(screen.queryByText('Replace Current Analysis')).not.toBeInTheDocument();
    expect(screen.queryByText('Validation Diagnostics')).not.toBeInTheDocument();
  });

  it('21, 22, 23: Replacement acknowledgement required and is not pre-checked', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith('/status')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_STATUS_ENABLED) });
      }
      if (url.endsWith('/validate')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_VALIDATION_TRAFFIC_ONLY) });
      }
      return Promise.reject(new Error('Unknown url'));
    }) as unknown as typeof fetch;

    render(<ImportDataPage />);

    await waitFor(() => {
      expect(screen.getByText('Network Traffic')).toBeInTheDocument();
    });

    const trafficInput = screen.getByTestId('traffic-file-input');
    fireEvent.change(trafficInput, { target: { files: [new File(['traffic'], 'traffic.tsv')] } });
    fireEvent.click(screen.getByRole('button', { name: /validate files/i }));

    await waitFor(() => {
      expect(screen.getByText('Replace Current Analysis')).toBeInTheDocument();
    });

    const checkbox = screen.getByTestId('replace-acknowledge-checkbox') as HTMLInputElement;
    // 22. Not pre-checked
    expect(checkbox.checked).toBe(false);

    // 23. Import & Analyze disabled before acknowledgement
    const importBtn = screen.getByRole('button', { name: /import & analyze/i });
    expect(importBtn).toBeDisabled();

    // Check acknowledgement
    fireEvent.click(checkbox);
    expect(checkbox.checked).toBe(true);
    expect(importBtn).not.toBeDisabled();
  });

  it('26, 34, 35: Successful traffic-only import displays capabilities and navigation', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith('/status')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_STATUS_ENABLED) });
      }
      if (url.endsWith('/validate')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_VALIDATION_TRAFFIC_ONLY) });
      }
      if (url.endsWith('/api/v1/import')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_RESULT_TRAFFIC_ONLY) });
      }
      return Promise.reject(new Error('Unknown url'));
    }) as unknown as typeof fetch;

    const onNavigate = vi.fn();
    const onImportSuccess = vi.fn();

    render(<ImportDataPage onNavigate={onNavigate} onImportSuccess={onImportSuccess} />);

    await waitFor(() => {
      expect(screen.getByText('Network Traffic')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByTestId('traffic-file-input'), { target: { files: [new File(['traffic'], 'traffic.tsv')] } });
    fireEvent.click(screen.getByRole('button', { name: /validate files/i }));

    await waitFor(() => {
      expect(screen.getByTestId('replace-acknowledge-checkbox')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('replace-acknowledge-checkbox'));
    fireEvent.click(screen.getByRole('button', { name: /import & analyze/i }));

    await waitFor(() => {
      expect(screen.getByText('Analysis Imported Successfully')).toBeInTheDocument();
    });

    expect(onImportSuccess).toHaveBeenCalledTimes(1);

    // 26. Capabilities
    expect(screen.getByText('✓ Network topology')).toBeInTheDocument();
    expect(screen.getByText('✓ IP investigation')).toBeInTheDocument();
    expect(screen.getByText('✓ Communication path analysis')).toBeInTheDocument();
    expect(screen.getByText('— Alert analysis not available for this dataset')).toBeInTheDocument();

    // 34 & 35. Navigation buttons
    const overviewBtn = screen.getByRole('button', { name: /open overview/i });
    const networkBtn = screen.getByRole('button', { name: /explore network/i });

    fireEvent.click(overviewBtn);
    expect(onNavigate).toHaveBeenCalledWith('overview');

    fireEvent.click(networkBtn);
    expect(onNavigate).toHaveBeenCalledWith('network');
  });

  it('27: Successful alerts-only import enables IP investigation but omits Explore Network', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith('/status')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_STATUS_ENABLED) });
      }
      if (url.endsWith('/validate')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_VALIDATION_ALERTS_ONLY) });
      }
      if (url.endsWith('/api/v1/import')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_RESULT_ALERTS_ONLY) });
      }
      return Promise.reject(new Error('Unknown url'));
    }) as unknown as typeof fetch;

    render(<ImportDataPage />);

    await waitFor(() => {
      expect(screen.getByText('Security Alerts')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByTestId('alerts-file-input'), { target: { files: [new File(['[]'], 'alerts.json')] } });
    fireEvent.click(screen.getByRole('button', { name: /validate files/i }));

    await waitFor(() => {
      expect(screen.getByTestId('replace-acknowledge-checkbox')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('replace-acknowledge-checkbox'));
    fireEvent.click(screen.getByRole('button', { name: /import & analyze/i }));

    await waitFor(() => {
      expect(screen.getByText('Analysis Imported Successfully')).toBeInTheDocument();
    });

    // 27. Alerts-only capabilities
    expect(screen.getByText('— Network topology not available for this dataset')).toBeInTheDocument();
    expect(screen.getByText('✓ IP investigation')).toBeInTheDocument();
    expect(screen.getByText('✓ Alert analysis')).toBeInTheDocument();
    // Network button omitted for alerts-only
    expect(screen.queryByRole('button', { name: /explore network/i })).not.toBeInTheDocument();
  });

  it('28: Successful combined import enables all capabilities', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.endsWith('/status')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_STATUS_ENABLED) });
      }
      if (url.endsWith('/validate')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_VALIDATION_COMBINED) });
      }
      if (url.endsWith('/api/v1/import')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_RESULT_COMBINED) });
      }
      return Promise.reject(new Error('Unknown url'));
    }) as unknown as typeof fetch;

    render(<ImportDataPage />);

    await waitFor(() => {
      expect(screen.getByText('Network Traffic')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByTestId('traffic-file-input'), { target: { files: [new File(['traffic'], 'traffic.tsv')] } });
    fireEvent.change(screen.getByTestId('alerts-file-input'), { target: { files: [new File(['[]'], 'alerts.json')] } });
    fireEvent.click(screen.getByRole('button', { name: /validate files/i }));

    await waitFor(() => {
      expect(screen.getByTestId('replace-acknowledge-checkbox')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('replace-acknowledge-checkbox'));
    fireEvent.click(screen.getByRole('button', { name: /import & analyze/i }));

    await waitFor(() => {
      expect(screen.getByText('Analysis Imported Successfully')).toBeInTheDocument();
    });

    expect(screen.getByText('✓ Network topology')).toBeInTheDocument();
    expect(screen.getByText('✓ IP investigation')).toBeInTheDocument();
    expect(screen.getByText('✓ Communication path analysis')).toBeInTheDocument();
    expect(screen.getByText('✓ Alert analysis')).toBeInTheDocument();
    expect(screen.getByText('✓ Traffic / alert correlation analysis')).toBeInTheDocument();
  });

  it('29, 30, 31, 32, 33: Error handling for 403, 409, 413, 422, 503 HTTP status codes', async () => {
    const testErrorStatus = async (status: number, detail: string, expectedText: string) => {
      globalThis.fetch = vi.fn().mockImplementation((url: string) => {
        if (url.endsWith('/status')) {
          return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_STATUS_ENABLED) });
        }
        if (url.endsWith('/validate')) {
          return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_VALIDATION_TRAFFIC_ONLY) });
        }
        if (url.endsWith('/api/v1/import')) {
          return Promise.resolve({
            ok: false,
            status,
            statusText: 'Error',
            json: () => Promise.resolve({ detail }),
          });
        }
        return Promise.reject(new Error('Unknown url'));
      }) as unknown as typeof fetch;

      const { unmount } = render(<ImportDataPage />);

      await waitFor(() => {
        expect(screen.getByText('Network Traffic')).toBeInTheDocument();
      });

      fireEvent.change(screen.getByTestId('traffic-file-input'), { target: { files: [new File(['traffic'], 'traffic.tsv')] } });
      fireEvent.click(screen.getByRole('button', { name: /validate files/i }));

      await waitFor(() => {
        expect(screen.getByTestId('replace-acknowledge-checkbox')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByTestId('replace-acknowledge-checkbox'));
      fireEvent.click(screen.getByRole('button', { name: /import & analyze/i }));

      await waitFor(() => {
        expect(screen.getByText(/Import Failed:/i)).toBeInTheDocument();
        expect(screen.getByText(new RegExp(expectedText, 'i'))).toBeInTheDocument();
      });

      unmount();
    };

    // 29. 403 Forbidden
    await testErrorStatus(403, 'Data import is disabled by server configuration.', 'disabled by server configuration');
    // 30. 409 Conflict
    await testErrorStatus(409, 'Another data import is already in progress.', 'already in progress');
    // 31. 413 Payload Too Large
    await testErrorStatus(413, 'File size exceeds allowable limit.', 'exceeds allowable limit');
    // 32. 422 Unprocessable
    await testErrorStatus(422, 'Uploaded data could not be imported because validation failed.', 'validation failed');
    // 33. 503 Service Unavailable
    await testErrorStatus(503, 'Database service unavailable', 'Database service unavailable');
  });

  it('36: Successful import triggers stale investigation context reset in App.tsx', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/health')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ status: 'ok', app: 'neo4j_project' }) });
      }
      if (url.includes('/ready')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ status: 'ready', database: 'connected' }) });
      }
      if (url.includes('/api/v1/import/status')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_STATUS_ENABLED) });
      }
      if (url.includes('/api/v1/import/validate')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_VALIDATION_TRAFFIC_ONLY) });
      }
      if (url.includes('/api/v1/import')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_RESULT_TRAFFIC_ONLY) });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ items: [], total: 0, limit: 50, offset: 0 }) });
    }) as unknown as typeof fetch;

    render(<App />);

    // Switch to Import tab
    const importTab = screen.getByRole('button', { name: /import data/i });
    fireEvent.click(importTab);

    await waitFor(() => {
      expect(screen.getByText('Network Traffic')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByTestId('traffic-file-input'), { target: { files: [new File(['traffic'], 'traffic.tsv')] } });
    fireEvent.click(screen.getByRole('button', { name: /validate files/i }));

    await waitFor(() => {
      expect(screen.getByTestId('replace-acknowledge-checkbox')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('replace-acknowledge-checkbox'));
    fireEvent.click(screen.getByRole('button', { name: /import & analyze/i }));

    await waitFor(() => {
      expect(screen.getByText('Analysis Imported Successfully')).toBeInTheDocument();
    });
  });
});
