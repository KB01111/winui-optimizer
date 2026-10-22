//! Mapping from the public `security-ipc` request enum onto engine methods.
//!
//! Every request is validated before it reaches storage, the scanner or the
//! quarantine vault. Errors are returned as [`ServerResponse::Error`] with a
//! stable machine-readable code; the pipe transport already enforces framing,
//! protocol version and per-client rate limits.

use security_core::ScanSource;
use security_ipc::{ClientRequest, ServerResponse};
use serde_json::Value;

use crate::{
    is_within, validate_existing_path, validate_id, validate_reason, ServiceEngine, ServiceError,
    MAX_LIST_LIMIT,
};

pub(crate) fn handle_request(engine: &ServiceEngine, request: ClientRequest) -> ServerResponse {
    match request {
        ClientRequest::Ping => ServerResponse::Pong {
            version: security_ipc::IPC_PROTOCOL_VERSION.to_string(),
            uptime_secs: engine.uptime_secs(),
        },
        ClientRequest::GetStatus => match serde_json::to_value(engine.status()) {
            Ok(value) => ServerResponse::Status(value),
            Err(err) => server_error(ServiceError::Internal(format!(
                "failed to encode engine status: {err}"
            ))),
        },
        ClientRequest::ScanPath { path, recursive } => {
            match validate_existing_path(&path)
                .and_then(|root| engine.spawn_scan(root, recursive, ScanSource::Manual))
            {
                Ok(job_id) => ServerResponse::ScanAccepted { job_id },
                Err(err) => server_error(err),
            }
        }
        ClientRequest::CancelScan { job_id } => match validate_id(&job_id, "job id") {
            Ok(()) => ServerResponse::Cancelled {
                cancelled: engine.cancel_scan(&job_id),
                job_id,
            },
            Err(err) => server_error(err),
        },
        ClientRequest::ListEvents { limit, offset } => {
            match crate::engine::query_events(engine.database(), limit, offset) {
                Ok(page) => match serde_json::to_value(page) {
                    Ok(value) => ServerResponse::Events(value),
                    Err(err) => server_error(ServiceError::Internal(format!(
                        "failed to encode event page: {err}"
                    ))),
                },
                Err(err) => server_error(err),
            }
        }
        ClientRequest::GetEvent { event_id } => {
            if let Err(err) = validate_id(&event_id, "event id") {
                return server_error(err);
            }
            match engine.database().get_event(&event_id) {
                Ok(Some(event)) => match serde_json::to_value(event) {
                    Ok(value) => ServerResponse::Event(value),
                    Err(err) => server_error(ServiceError::Internal(format!(
                        "failed to encode event: {err}"
                    ))),
                },
                Ok(None) => {
                    ServerResponse::error("not_found", format!("event {event_id} was not found"))
                }
                Err(err) => server_error(err.into()),
            }
        }
        ClientRequest::ListQuarantine => match engine.database().list_quarantine(MAX_LIST_LIMIT) {
            Ok(records) => {
                let mut values = Vec::with_capacity(records.len());
                for record in records {
                    match serde_json::to_value(record) {
                        Ok(value) => values.push(value),
                        Err(err) => {
                            return server_error(ServiceError::Internal(format!(
                                "failed to encode quarantine record: {err}"
                            )))
                        }
                    }
                }
                ServerResponse::Quarantine(values)
            }
            Err(err) => server_error(err.into()),
        },
        ClientRequest::QuarantineFile { path, reason } => {
            let candidate = match validate_existing_path(&path) {
                Ok(path) => path,
                Err(err) => return server_error(err),
            };
            if !candidate.is_file() {
                return server_error(ServiceError::InvalidRequest(
                    "quarantine requires a regular file path".to_string(),
                ));
            }
            if let Some(vault) = engine.vault() {
                if is_within(vault.dir(), &candidate) {
                    return server_error(ServiceError::InvalidRequest(
                        "path is inside the quarantine vault".to_string(),
                    ));
                }
            }
            let reason = match validate_reason(&reason) {
                Ok(reason) => reason,
                Err(err) => return server_error(err),
            };
            match engine.quarantine_file(&candidate, &reason) {
                Ok(record) => match serde_json::to_value(record) {
                    Ok(value) => ServerResponse::QuarantineRecord(value),
                    Err(err) => server_error(ServiceError::Internal(format!(
                        "failed to encode quarantine record: {err}"
                    ))),
                },
                Err(err) => server_error(err),
            }
        }
        ClientRequest::RestoreQuarantine { id } => {
            if let Err(err) = validate_id(&id, "quarantine id") {
                return server_error(err);
            }
            match engine.restore_quarantine(&id) {
                Ok(result) => match serde_json::to_value(result) {
                    Ok(value) => ServerResponse::Restore(value),
                    Err(err) => server_error(ServiceError::Internal(format!(
                        "failed to encode restore result: {err}"
                    ))),
                },
                Err(err) => server_error(err),
            }
        }
        ClientRequest::Subscribe => ServerResponse::Subscribed,
    }
}

fn server_error(err: ServiceError) -> ServerResponse {
    ServerResponse::error(err.code(), err.to_string())
}

/// Serialize an arbitrary value into a `Value` (used by tests and future
/// handlers); kept here so error mapping stays in one place.
#[allow(dead_code)]
pub(crate) fn encode_value<T: serde::Serialize>(value: T) -> Result<Value, ServiceError> {
    serde_json::to_value(value)
        .map_err(|err| ServiceError::Internal(format!("failed to encode value: {err}")))
}
