import React, { useState, useEffect, useRef } from 'react';
import {
  Upload,
  FileText,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Trash2,
  Network,
  Activity,
  AlertCircle,
  Info,
} from 'lucide-react';
import { getImportStatus, validateImportFiles, importWorkspaceData } from '../api/importData';
import type {
  ImportStatusResponse,
  ImportValidationResponse,
  ImportResultResponse,
  FileValidationResult,
} from '../api/types';
import type { ActiveView } from '../components/layout/Header';
import { Skeleton } from '../components/common/Skeleton';

interface ImportDataPageProps {
  onNavigate?: (view: ActiveView, context?: { centerIp?: string; sourceIp?: string; targetIp?: string }) => void;
  onImportSuccess?: () => void;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KiB', 'MiB', 'GiB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export const ImportDataPage: React.FC<ImportDataPageProps> = ({ onNavigate, onImportSuccess }) => {
  // Status state
  const [statusLoading, setStatusLoading] = useState<boolean>(true);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [statusConfig, setStatusConfig] = useState<ImportStatusResponse | null>(null);

  // File selection state
  const [trafficFile, setTrafficFile] = useState<File | null>(null);
  const [alertsFile, setAlertsFile] = useState<File | null>(null);
  const [trafficSizeError, setTrafficSizeError] = useState<string | null>(null);
  const [alertsSizeError, setAlertsSizeError] = useState<string | null>(null);

  // Validation state
  const [validating, setValidating] = useState<boolean>(false);
  const [validationResult, setValidationResult] = useState<ImportValidationResponse | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);

  // Replacement & Import state
  const [acknowledged, setAcknowledged] = useState<boolean>(false);
  const [importing, setImporting] = useState<boolean>(false);
  const [importResult, setImportResult] = useState<ImportResultResponse | null>(null);
  const [importError, setImportError] = useState<string | null>(null);

  // Hidden file inputs
  const trafficInputRef = useRef<HTMLInputElement>(null);
  const alertsInputRef = useRef<HTMLInputElement>(null);

  // Fetch status on mount or retry
  const fetchStatus = () => {
    setStatusLoading(true);
    setStatusError(null);
    getImportStatus()
      .then((res) => {
        setStatusConfig(res);
        setStatusLoading(false);
      })
      .catch((err: Error) => {
        setStatusError(err.message || 'Failed to check import status');
        setStatusLoading(false);
      });
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  // Invalidate downstream validation and import state
  const invalidateStaleState = () => {
    setValidationResult(null);
    setValidationError(null);
    setAcknowledged(false);
    setImportResult(null);
    setImportError(null);
  };

  // Handle Traffic file change
  const handleTrafficChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] || null;
    invalidateStaleState();

    if (file) {
      setTrafficFile(file);
      if (statusConfig && file.size > statusConfig.max_file_size_bytes) {
        setTrafficSizeError(
          `File size (${formatBytes(file.size)}) exceeds maximum allowable limit of ${statusConfig.max_file_size_mb} MiB`
        );
      } else {
        setTrafficSizeError(null);
      }
    } else {
      setTrafficFile(null);
      setTrafficSizeError(null);
    }
  };

  const handleClearTraffic = () => {
    setTrafficFile(null);
    setTrafficSizeError(null);
    if (trafficInputRef.current) trafficInputRef.current.value = '';
    invalidateStaleState();
  };

  // Handle Alerts file change
  const handleAlertsChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] || null;
    invalidateStaleState();

    if (file) {
      setAlertsFile(file);
      if (statusConfig && file.size > statusConfig.max_file_size_bytes) {
        setAlertsSizeError(
          `File size (${formatBytes(file.size)}) exceeds maximum allowable limit of ${statusConfig.max_file_size_mb} MiB`
        );
      } else {
        setAlertsSizeError(null);
      }
    } else {
      setAlertsFile(null);
      setAlertsSizeError(null);
    }
  };

  const handleClearAlerts = () => {
    setAlertsFile(null);
    setAlertsSizeError(null);
    if (alertsInputRef.current) alertsInputRef.current.value = '';
    invalidateStaleState();
  };

  // Execute Validation
  const handleValidate = async () => {
    if (!trafficFile && !alertsFile) return;
    if (trafficSizeError || alertsSizeError) return;

    setValidating(true);
    setValidationError(null);
    setValidationResult(null);
    setAcknowledged(false);
    setImportResult(null);
    setImportError(null);

    try {
      const res = await validateImportFiles({
        trafficFile,
        alertsFile,
      });
      setValidationResult(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Validation request failed';
      setValidationError(msg);
    } finally {
      setValidating(false);
    }
  };

  // Execute Workspace Import
  const handleImport = async () => {
    if (!validationResult?.can_import || !acknowledged) return;

    setImporting(true);
    setImportError(null);

    try {
      const res = await importWorkspaceData({
        trafficFile,
        alertsFile,
      });
      setImportResult(res);
      // Reset cross-view investigation context in App.tsx
      onImportSuccess?.();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Import request failed';
      setImportError(msg);
    } finally {
      setImporting(false);
    }
  };

  // 1. Loading State
  if (statusLoading) {
    return (
      <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 600 }}>Import Data</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.2rem' }}>
            Checking server configuration and import status...
          </p>
        </div>
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <Skeleton height="24px" width="40%" />
          <Skeleton height="60px" width="100%" />
        </div>
      </div>
    );
  }

  // 2. Status Error State
  if (statusError || !statusConfig) {
    return (
      <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 600 }}>Import Data</h2>
        </div>
        <div
          className="card"
          style={{
            borderLeft: '4px solid var(--accent-rose)',
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'space-between',
            gap: '1rem',
          }}
        >
          <div style={{ display: 'flex', gap: '0.75rem' }}>
            <AlertCircle size={20} color="var(--accent-rose)" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <div style={{ fontWeight: 600, color: 'var(--accent-rose)' }}>Unable to verify import status</div>
              <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                {statusError || 'The backend could not be reached to determine import configuration.'}
              </div>
            </div>
          </div>
          <button className="btn-secondary" onClick={fetchStatus} style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <RefreshCw size={14} /> Retry
          </button>
        </div>
      </div>
    );
  }

  // 3. Disabled State
  if (!statusConfig.enabled) {
    return (
      <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 600 }}>Import Data</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.2rem' }}>
            Load network traffic and security alert data into the analysis workspace.
          </p>
        </div>

        <div
          className="card"
          style={{
            borderLeft: '4px solid var(--accent-amber)',
            backgroundColor: 'var(--bg-card)',
            padding: '1.5rem',
          }}
        >
          <div style={{ display: 'flex', gap: '0.85rem' }}>
            <Info size={22} color="var(--accent-amber)" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)' }}>Data Import Disabled</h3>
              <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginTop: '0.4rem', lineHeight: 1.5 }}>
                Browser data import and workspace replacement are disabled by server configuration.
              </p>
              <div
                style={{
                  marginTop: '0.75rem',
                  padding: '0.6rem 0.8rem',
                  backgroundColor: 'var(--bg-input)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.85rem',
                  color: 'var(--text-muted)',
                  fontFamily: 'var(--font-family-mono)',
                  display: 'inline-block',
                }}
              >
                DATA_IMPORT_ENABLED=true
              </div>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                To enable dataset uploads for a trusted local deployment, enable the setting above in your server environment.
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // 4. Enabled State — Full Workflow
  const hasSelectedFiles = Boolean(trafficFile || alertsFile);
  const hasClientErrors = Boolean(trafficSizeError || alertsSizeError);
  const canValidate = hasSelectedFiles && !hasClientErrors && !validating && !importing;

  const renderFileResultSummary = (title: string, result: FileValidationResult) => {
    if (!result.provided) return null;

    const isFatal = (result.valid_records || 0) === 0 || result.sample_errors.length > 0;
    const hasWarnings = Object.keys(result.warning_counts).length > 0 || (result.skipped_records || 0) > 0;

    let badgeText = 'VALID';
    let badgeBg = 'var(--accent-emerald-dim)';
    let badgeColor = 'var(--accent-emerald)';
    let badgeBorder = 'rgba(16, 185, 129, 0.3)';

    if (isFatal) {
      badgeText = 'INVALID';
      badgeBg = 'var(--accent-rose-dim)';
      badgeColor = 'var(--accent-rose)';
      badgeBorder = 'rgba(244, 63, 94, 0.3)';
    } else if (hasWarnings) {
      badgeText = 'VALID WITH WARNINGS';
      badgeBg = 'var(--accent-amber-dim)';
      badgeColor = 'var(--accent-amber)';
      badgeBorder = 'rgba(245, 158, 11, 0.3)';
    }

    return (
      <div
        className="card"
        style={{
          flex: 1,
          minWidth: '280px',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.75rem',
          backgroundColor: 'var(--bg-sidebar)',
          border: '1px solid var(--border-card)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <span style={{ fontWeight: 600, fontSize: '0.95rem', color: 'var(--text-primary)' }}>{title}</span>
            {result.filename && (
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
                ({result.filename})
              </span>
            )}
          </div>
          <span
            style={{
              fontSize: '0.7rem',
              fontWeight: 600,
              padding: '0.2rem 0.55rem',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: badgeBg,
              color: badgeColor,
              border: `1px solid ${badgeBorder}`,
            }}
          >
            {badgeText}
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.85rem' }}>
          <div style={{ color: 'var(--text-secondary)' }}>
            Raw records: <strong style={{ color: 'var(--text-primary)' }}>{result.total_raw_records ?? 0}</strong>
          </div>
          <div style={{ color: 'var(--text-secondary)' }}>
            Valid records: <strong style={{ color: 'var(--text-primary)' }}>{result.valid_records ?? 0}</strong>
          </div>
          <div style={{ color: 'var(--text-secondary)' }}>
            Skipped records: <strong style={{ color: 'var(--text-primary)' }}>{result.skipped_records ?? 0}</strong>
          </div>
          {result.duplicate_records !== null && (
            <div style={{ color: 'var(--text-secondary)' }}>
              Duplicates removed: <strong style={{ color: 'var(--text-primary)' }}>{result.duplicate_records}</strong>
            </div>
          )}
        </div>

        {/* Categorized Warnings */}
        {Object.keys(result.warning_counts).length > 0 && (
          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '0.5rem', marginTop: '0.25rem' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--accent-amber)', marginBottom: '0.25rem' }}>
              Warnings ({Object.values(result.warning_counts).reduce((a, b) => a + b, 0)}):
            </div>
            <ul style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', paddingLeft: '1.2rem', margin: 0 }}>
              {Object.entries(result.warning_counts).map(([type, count]) => (
                <li key={type}>
                  <code>{type}</code>: {count} occurrence(s)
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Sample Errors */}
        {result.sample_errors.length > 0 && (
          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '0.5rem', marginTop: '0.25rem' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--accent-rose)', marginBottom: '0.25rem' }}>
              Sample Issues:
            </div>
            <ul style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', paddingLeft: '1.2rem', margin: 0 }}>
              {result.sample_errors.map((err, idx) => (
                <li key={idx} style={{ color: 'var(--accent-rose)' }}>{err}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  };

  return (
    <div style={{ maxWidth: '1440px', width: '100%', margin: '0 auto', padding: '1.75rem 2rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '1.35rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
          Import Data
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '0.2rem' }}>
          Load network traffic and/or IDS security alert data directly into the active analysis workspace.
        </p>
      </div>

      {/* Info notice */}
      <div className="info-banner" style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
        <Info size={16} style={{ flexShrink: 0 }} />
        <div>
          Provide at least one supported data file. Supported formats: tshark tab-separated TSV traffic exports and IDS/Snort JSON alert arrays. Max file size: <strong>{statusConfig.max_file_size_mb} MiB</strong> per file.
        </div>
      </div>

      {/* Source Selection Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.25rem' }}>
        {/* Traffic Source Card */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.4rem' }}>
              <Network size={18} color="var(--accent-cyan)" />
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600 }}>Network Traffic</h3>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Supported format: legacy 7-column TSV or project-defined enriched tshark TSV export profile (ports, packet counts, frame bytes).
            </p>
          </div>

          <div>
            <input
              type="file"
              ref={trafficInputRef}
              onChange={handleTrafficChange}
              accept=".tsv,.txt,.csv"
              style={{ display: 'none' }}
              data-testid="traffic-file-input"
            />

            {trafficFile ? (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '0.6rem 0.8rem',
                  backgroundColor: 'var(--bg-input)',
                  borderRadius: 'var(--radius-sm)',
                  border: trafficSizeError ? '1px solid var(--accent-rose)' : '1px solid var(--border-subtle)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', overflow: 'hidden' }}>
                  <FileText size={16} color="var(--accent-cyan)" style={{ flexShrink: 0 }} />
                  <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <div style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                      {trafficFile.name}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {formatBytes(trafficFile.size)}
                    </div>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleClearTraffic}
                  className="btn-secondary"
                  title="Remove traffic file"
                  style={{ padding: '0.3rem 0.5rem', color: 'var(--accent-rose)' }}
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ) : (
              <button
                type="button"
                className="btn-secondary"
                onClick={() => trafficInputRef.current?.click()}
                style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
              >
                <Upload size={14} /> Select TSV File
              </button>
            )}

            {trafficSizeError && (
              <div style={{ fontSize: '0.75rem', color: 'var(--accent-rose)', marginTop: '0.4rem' }}>
                {trafficSizeError}
              </div>
            )}
          </div>
        </div>

        {/* Alerts Source Card */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.4rem' }}>
              <AlertTriangle size={18} color="var(--accent-amber)" />
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600 }}>Security Alerts</h3>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Supported format: IDS/Snort-compatible JSON array containing alert facts, signatures, and IPs.
            </p>
          </div>

          <div>
            <input
              type="file"
              ref={alertsInputRef}
              onChange={handleAlertsChange}
              accept=".json"
              style={{ display: 'none' }}
              data-testid="alerts-file-input"
            />

            {alertsFile ? (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '0.6rem 0.8rem',
                  backgroundColor: 'var(--bg-input)',
                  borderRadius: 'var(--radius-sm)',
                  border: alertsSizeError ? '1px solid var(--accent-rose)' : '1px solid var(--border-subtle)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', overflow: 'hidden' }}>
                  <FileText size={16} color="var(--accent-amber)" style={{ flexShrink: 0 }} />
                  <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <div style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                      {alertsFile.name}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {formatBytes(alertsFile.size)}
                    </div>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleClearAlerts}
                  className="btn-secondary"
                  title="Remove alerts file"
                  style={{ padding: '0.3rem 0.5rem', color: 'var(--accent-rose)' }}
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ) : (
              <button
                type="button"
                className="btn-secondary"
                onClick={() => alertsInputRef.current?.click()}
                style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
              >
                <Upload size={14} /> Select JSON File
              </button>
            )}

            {alertsSizeError && (
              <div style={{ fontSize: '0.75rem', color: 'var(--accent-rose)', marginTop: '0.4rem' }}>
                {alertsSizeError}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Validation Action */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <button
          type="button"
          className="btn-primary"
          onClick={handleValidate}
          disabled={!canValidate}
          style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.6rem 1.25rem' }}
        >
          {validating ? (
            <>
              <RefreshCw size={15} className="spin-icon" /> Validating Files...
            </>
          ) : (
            <>
              <CheckCircle2 size={15} /> Validate Files
            </>
          )}
        </button>

        {!hasSelectedFiles && (
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Select at least one traffic TSV or alert JSON file to validate.
          </span>
        )}
      </div>

      {/* Validation Transport / Server Error */}
      {validationError && (
        <div
          className="card"
          style={{
            borderLeft: '4px solid var(--accent-rose)',
            backgroundColor: 'var(--bg-card)',
            color: 'var(--accent-rose)',
            fontSize: '0.875rem',
          }}
        >
          <strong>Validation Error:</strong> {validationError}
        </div>
      )}

      {/* Validation Results Display */}
      {validationResult && (
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Validation Diagnostics</h3>
            <span
              style={{
                fontSize: '0.8rem',
                fontWeight: 600,
                color: validationResult.can_import ? 'var(--accent-emerald)' : 'var(--accent-rose)',
              }}
            >
              {validationResult.message}
            </span>
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem' }}>
            {renderFileResultSummary('Network Traffic', validationResult.traffic)}
            {renderFileResultSummary('Security Alerts', validationResult.alerts)}
          </div>

          {!validationResult.can_import && (
            <div
              style={{
                padding: '0.75rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--accent-rose-dim)',
                border: '1px solid rgba(244, 63, 94, 0.3)',
                color: 'var(--accent-rose)',
                fontSize: '0.85rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
              }}
            >
              <XCircle size={16} style={{ flexShrink: 0 }} />
              <span>
                One or more files failed validation. Resolve the errors above and validate again before importing.
              </span>
            </div>
          )}
        </div>
      )}

      {/* Replace Confirmation & Import Action */}
      {validationResult?.valid && validationResult?.can_import && !importResult && (
        <div
          className="card"
          style={{
            borderLeft: '4px solid var(--accent-cyan)',
            display: 'flex',
            flexDirection: 'column',
            gap: '1rem',
            backgroundColor: 'var(--bg-card)',
          }}
        >
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Replace Current Analysis
            </h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.25rem', lineHeight: 1.5 }}>
              Importing these files will replace the current analysis data. Previous data in the active analysis workspace will be removed only if the new dataset is successfully written.
            </p>
          </div>

          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.6rem',
              cursor: 'pointer',
              fontSize: '0.875rem',
              color: 'var(--text-primary)',
            }}
          >
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
              style={{ cursor: 'pointer', width: '16px', height: '16px' }}
              data-testid="replace-acknowledge-checkbox"
            />
            <span>I understand that this import replaces the current analysis.</span>
          </label>

          {importError && (
            <div
              style={{
                padding: '0.6rem 0.8rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--accent-rose-dim)',
                border: '1px solid rgba(244, 63, 94, 0.3)',
                color: 'var(--accent-rose)',
                fontSize: '0.85rem',
              }}
            >
              <strong>Import Failed:</strong> {importError}
            </div>
          )}

          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginTop: '0.25rem' }}>
            <button
              type="button"
              className="btn-primary"
              onClick={handleImport}
              disabled={!acknowledged || importing}
              style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.65rem 1.4rem' }}
            >
              {importing ? (
                <>
                  <RefreshCw size={15} className="spin-icon" /> Importing & Replacing Workspace...
                </>
              ) : (
                <>
                  <Upload size={15} /> Import & Analyze
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {/* Import Success Panel */}
      {importResult && (
        <div
          className="card"
          style={{
            borderLeft: '4px solid var(--accent-emerald)',
            display: 'flex',
            flexDirection: 'column',
            gap: '1.25rem',
            backgroundColor: 'var(--bg-card)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <CheckCircle2 size={24} color="var(--accent-emerald)" />
            <div>
              <h3 style={{ fontSize: '1.2rem', fontWeight: 600, color: 'var(--accent-emerald)' }}>
                Analysis Imported Successfully
              </h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                {importResult.message}
              </p>
            </div>
          </div>

          {/* Persisted Metrics */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '1rem',
              padding: '1rem',
              backgroundColor: 'var(--bg-sidebar)',
              borderRadius: 'var(--radius-sm)',
            }}
          >
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Traffic Records Persisted
              </div>
              <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--accent-cyan)', marginTop: '0.2rem' }}>
                {importResult.traffic_records_persisted}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Alert Facts Persisted
              </div>
              <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--accent-amber)', marginTop: '0.2rem' }}>
                {importResult.alert_facts_persisted}
              </div>
            </div>
          </div>

          {/* Capabilities Breakdown */}
          <div>
            <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
              Active Analysis Capabilities
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.85rem' }}>
              {importResult.capabilities.network_topology ? (
                <div style={{ color: 'var(--accent-emerald)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  ✓ Network topology
                </div>
              ) : (
                <div style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  — Network topology not available for this dataset
                </div>
              )}

              {importResult.capabilities.ip_investigation ? (
                <div style={{ color: 'var(--accent-emerald)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  ✓ IP investigation
                </div>
              ) : (
                <div style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  — IP investigation not available for this dataset
                </div>
              )}

              {importResult.capabilities.communication_paths ? (
                <div style={{ color: 'var(--accent-emerald)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  ✓ Communication path analysis
                </div>
              ) : (
                <div style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  — Communication path analysis not applicable
                </div>
              )}

              {importResult.capabilities.alert_facts ? (
                <div style={{ color: 'var(--accent-emerald)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  ✓ Alert analysis
                </div>
              ) : (
                <div style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  — Alert analysis not available for this dataset
                </div>
              )}

              {importResult.capabilities.traffic_alert_correlations ? (
                <div style={{ color: 'var(--accent-emerald)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  ✓ Traffic / alert correlation analysis
                </div>
              ) : (
                <div style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  — Traffic / alert correlation analysis not applicable
                </div>
              )}
            </div>
          </div>

          {/* Navigation Actions */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.5rem' }}>
            <button
              type="button"
              className="btn-primary"
              onClick={() => onNavigate?.('overview')}
              style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
            >
              <Activity size={15} /> Open Overview
            </button>

            {importResult.capabilities.network_topology && (
              <button
                type="button"
                className="btn-secondary"
                onClick={() => onNavigate?.('network')}
                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
              >
                <Network size={15} /> Explore Network
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
