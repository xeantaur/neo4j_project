"""
Data import service for validating and persisting user-provided network datasets.

Orchestrates bounded file spooling, parser execution, stateless validation,
single-process mutation locking, and atomic workspace replacement in Neo4j.
"""

import logging
import os
import tempfile
import threading
from typing import Optional, Tuple, List
from fastapi import UploadFile

from src.ingestion.models import TrafficRecord, AlertRecord
from src.ingestion.traffic_parser import parse_traffic_file
from src.ingestion.alert_parser import parse_alert_file
from src.graph.repository import Neo4jRepository
from src.api.models import (
    FileValidationResult,
    ImportValidationResponse,
    ImportCapabilities,
    ImportResultResponse,
)

logger = logging.getLogger(__name__)

# Single-process concurrency guard for atomic workspace replacement mutations
# Note: This is an in-process lock protecting a single FastAPI worker/process.
_IMPORT_MUTATION_LOCK = threading.Lock()

CHUNK_SIZE = 64 * 1024  # 64 KiB read buffer


class FileTooLargeError(Exception):
    """Raised when an individual uploaded file exceeds the configured size limit."""
    pass


class ImportConflictError(Exception):
    """Raised when an import mutation is attempted while another import is running."""
    pass


class ImportValidationError(Exception):
    """Raised when uploaded data contains fatal formatting or validation errors."""
    pass


def spool_upload_to_temp(
    upload_file: UploadFile,
    max_bytes: int,
    max_mb: int,
) -> str:
    """Safely stream an UploadFile to a temporary file, enforcing bounded size limits.

    Returns the absolute path of the created temporary file.

    Raises:
        FileTooLargeError: If uploaded bytes exceed max_bytes.
        Exception: If writing fails.
    """
    temp_file = tempfile.NamedTemporaryFile(
        delete=False,
        prefix="neo4j_import_",
        suffix=".tmp",
    )
    temp_path = temp_file.name
    total_bytes = 0

    try:
        while True:
            chunk = upload_file.file.read(CHUNK_SIZE)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > max_bytes:
                raise FileTooLargeError(
                    f"Uploaded file '{upload_file.filename or 'upload'}' exceeds "
                    f"the maximum allowed size of {max_mb} MiB."
                )
            temp_file.write(chunk)
        temp_file.flush()
        temp_file.close()
        return temp_path
    except Exception:
        temp_file.close()
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        raise


def calculate_capabilities(has_traffic: bool, has_alerts: bool) -> ImportCapabilities:
    """Determine available analysis capabilities derived strictly from imported source datasets."""
    return ImportCapabilities(
        network_topology=has_traffic,
        ip_investigation=has_traffic or has_alerts,
        communication_paths=has_traffic,
        alert_facts=has_alerts,
        traffic_alert_correlations=has_traffic and has_alerts,
    )


class ImportService:
    """Service handling stateless validation and atomic workspace replacement."""

    @staticmethod
    def validate_files(
        traffic_file: Optional[UploadFile],
        alerts_file: Optional[UploadFile],
        max_bytes: int,
        max_mb: int,
    ) -> Tuple[ImportValidationResponse, Optional[List[TrafficRecord]], Optional[List[AlertRecord]]]:
        """Stateless parsing and validation of uploaded traffic and alert datasets.

        Creates temporary spool files, invokes parsers, builds diagnostics, and
        guarantees temporary file removal before returning.

        Returns:
            Tuple of (ImportValidationResponse, valid_traffic_records, valid_alert_records)
        """
        traffic_result = FileValidationResult(provided=False)
        alerts_result = FileValidationResult(provided=False)

        valid_traffic: Optional[List[TrafficRecord]] = None
        valid_alerts: Optional[List[AlertRecord]] = None

        traffic_temp_path: Optional[str] = None
        alerts_temp_path: Optional[str] = None

        # 1. Process Traffic File if provided
        if traffic_file is not None:
            traffic_filename = os.path.basename(traffic_file.filename or "traffic.tsv")
            try:
                traffic_temp_path = spool_upload_to_temp(traffic_file, max_bytes, max_mb)
                records, summary = parse_traffic_file(traffic_temp_path)
                valid_traffic = records
                traffic_result = FileValidationResult(
                    provided=True,
                    filename=traffic_filename,
                    total_raw_records=summary.total_raw_records,
                    valid_records=summary.valid_records,
                    skipped_records=summary.skipped_records,
                    duplicate_records=summary.duplicate_records,
                    warning_counts=summary.warning_counts,
                    sample_errors=list(summary.sample_errors),
                )
            except FileTooLargeError:
                raise
            except Exception as exc:
                logger.warning("Traffic validation failed: %s", exc)
                traffic_result = FileValidationResult(
                    provided=True,
                    filename=traffic_filename,
                    total_raw_records=0,
                    valid_records=0,
                    skipped_records=0,
                    duplicate_records=0,
                    warning_counts={"fatal_parse_error": 1},
                    sample_errors=["Malformed or unreadable traffic TSV data."],
                )
            finally:
                if traffic_temp_path and os.path.exists(traffic_temp_path):
                    try:
                        os.unlink(traffic_temp_path)
                    except OSError:
                        pass

        # 2. Process Alerts File if provided
        if alerts_file is not None:
            alerts_filename = os.path.basename(alerts_file.filename or "alerts.json")
            try:
                alerts_temp_path = spool_upload_to_temp(alerts_file, max_bytes, max_mb)
                records, summary = parse_alert_file(alerts_temp_path)
                valid_alerts = records
                alerts_result = FileValidationResult(
                    provided=True,
                    filename=alerts_filename,
                    total_raw_records=summary.total_raw_records,
                    valid_records=summary.valid_records,
                    skipped_records=summary.skipped_records,
                    duplicate_records=None,
                    warning_counts=summary.warning_counts,
                    sample_errors=list(summary.sample_errors),
                )
            except FileTooLargeError:
                raise
            except Exception as exc:
                logger.warning("Alerts validation failed: %s", exc)
                alerts_result = FileValidationResult(
                    provided=True,
                    filename=alerts_filename,
                    total_raw_records=0,
                    valid_records=0,
                    skipped_records=0,
                    duplicate_records=None,
                    warning_counts={"fatal_parse_error": 1},
                    sample_errors=["Malformed or unreadable alerts JSON data."],
                )
            finally:
                if alerts_temp_path and os.path.exists(alerts_temp_path):
                    try:
                        os.unlink(alerts_temp_path)
                    except OSError:
                        pass

        # 3. Apply Validity & Importability Policy
        # Every PROVIDED file must contribute at least one valid record.
        traffic_ok = (not traffic_result.provided) or (traffic_result.valid_records is not None and traffic_result.valid_records > 0)
        alerts_ok = (not alerts_result.provided) or (alerts_result.valid_records is not None and alerts_result.valid_records > 0)

        is_valid = traffic_ok and alerts_ok and (traffic_result.provided or alerts_result.provided)
        can_import = is_valid

        # Construct informative status message
        if not is_valid:
            failed_parts = []
            if traffic_result.provided and (traffic_result.valid_records is None or traffic_result.valid_records == 0):
                failed_parts.append("traffic file contains 0 valid records")
            if alerts_result.provided and (alerts_result.valid_records is None or alerts_result.valid_records == 0):
                failed_parts.append("alerts file contains 0 valid records")
            message = f"Validation failed: {', '.join(failed_parts) if failed_parts else 'no usable records found'}."
        else:
            summary_parts = []
            if traffic_result.provided:
                summary_parts.append(f"{traffic_result.valid_records} valid traffic records")
            if alerts_result.provided:
                summary_parts.append(f"{alerts_result.valid_records} valid alert facts")
            message = f"Validation successful: {', '.join(summary_parts)} ready for workspace import."

        validation_response = ImportValidationResponse(
            valid=is_valid,
            can_import=can_import,
            traffic=traffic_result,
            alerts=alerts_result,
            message=message,
        )

        return validation_response, valid_traffic, valid_alerts

    @classmethod
    def execute_import(
        cls,
        traffic_file: Optional[UploadFile],
        alerts_file: Optional[UploadFile],
        max_bytes: int,
        max_mb: int,
        repository: Neo4jRepository,
    ) -> ImportResultResponse:
        """Independently validate and atomically replace active workspace data.

        Acquires an in-process lock to prevent concurrent import collisions.

        Raises:
            ImportConflictError: If another import is already active in this process.
            ImportValidationError: If validation fails or any provided file has 0 valid records.
            FileTooLargeError: If uploaded file exceeds max_bytes.
            Exception: If database persistence fails.
        """
        # Concurrency guard: Non-blocking acquisition
        if not _IMPORT_MUTATION_LOCK.acquire(blocking=False):
            raise ImportConflictError("Another data import is already in progress.")

        try:
            # Independent re-parsing and validation of uploaded files
            validation, valid_traffic, valid_alerts = cls.validate_files(
                traffic_file=traffic_file,
                alerts_file=alerts_file,
                max_bytes=max_bytes,
                max_mb=max_mb,
            )

            if not validation.can_import:
                raise ImportValidationError(
                    f"Uploaded data failed validation and cannot be imported: {validation.message}"
                )

            # Atomic Neo4j workspace replacement (scoped delete + batched writes in 1 transaction)
            persisted_traffic, persisted_alerts = repository.replace_workspace_data(
                traffic_records=valid_traffic,
                alert_records=valid_alerts,
            )

            capabilities = calculate_capabilities(
                has_traffic=persisted_traffic > 0,
                has_alerts=persisted_alerts > 0,
            )

            return ImportResultResponse(
                success=True,
                workspace_replaced=True,
                traffic_records_persisted=persisted_traffic,
                alert_facts_persisted=persisted_alerts,
                capabilities=capabilities,
                message=(
                    f"Analysis workspace successfully replaced with {persisted_traffic} "
                    f"traffic records and {persisted_alerts} alert facts."
                ),
            )
        finally:
            _IMPORT_MUTATION_LOCK.release()
