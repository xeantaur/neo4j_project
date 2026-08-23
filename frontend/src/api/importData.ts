/**
 * API client functions for Browser Data Import (Phase 6.5).
 */

import { request } from './client';
import type {
  ImportStatusResponse,
  ImportValidationResponse,
  ImportResultResponse,
} from './types';

export interface ImportFilesPayload {
  trafficFile?: File | null;
  alertsFile?: File | null;
}

/**
 * Retrieve data import feature configuration and file size limits.
 */
export async function getImportStatus(): Promise<ImportStatusResponse> {
  return request<ImportStatusResponse>('/api/v1/import/status');
}

/**
 * Statelessly validate uploaded datasets without modifying Neo4j.
 *
 * NOTE: Does NOT manually set Content-Type header so the browser/runtime
 * automatically computes the multipart boundary.
 */
export async function validateImportFiles(
  payload: ImportFilesPayload
): Promise<ImportValidationResponse> {
  const formData = new FormData();
  if (payload.trafficFile) {
    formData.append('traffic_file', payload.trafficFile);
  }
  if (payload.alertsFile) {
    formData.append('alerts_file', payload.alertsFile);
  }

  return request<ImportValidationResponse>('/api/v1/import/validate', {
    method: 'POST',
    body: formData,
  });
}

/**
 * Re-validate and atomically replace active workspace data in Neo4j.
 *
 * NOTE: Does NOT manually set Content-Type header so the browser/runtime
 * automatically computes the multipart boundary.
 */
export async function importWorkspaceData(
  payload: ImportFilesPayload
): Promise<ImportResultResponse> {
  const formData = new FormData();
  if (payload.trafficFile) {
    formData.append('traffic_file', payload.trafficFile);
  }
  if (payload.alertsFile) {
    formData.append('alerts_file', payload.alertsFile);
  }

  return request<ImportResultResponse>('/api/v1/import', {
    method: 'POST',
    body: formData,
  });
}
