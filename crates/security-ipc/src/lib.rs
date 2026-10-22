//! Secure local IPC between the unprivileged desktop app and the security
//! service.
//!
//! This crate defines the wire protocol ([`ClientRequest`] / [`ServerResponse`]),
//! strict framing ([`encode_frame`] / [`decode_frame`]) and a token-bucket
//! [`RateLimiter`], plus a Windows named-pipe transport in [`pipe`].
//!
//! Security properties:
//!
//! * Frames are length-prefixed (4-byte little-endian) JSON with a hard upper
//!   bound of [`MAX_FRAME_BYTES`]; oversized, truncated and malformed frames
//!   are rejected with descriptive errors instead of being interpreted.
//! * The named pipe is created with a DACL that grants access only to SYSTEM,
//!   Administrators and interactive users, and is created with
//!   `PIPE_REJECT_REMOTE_CLIENTS` so SMB clients cannot reach it.
//! * Requests carry an explicit protocol version and unknown versions are
//!   rejected.
//! * Each connection gets its own token bucket; abusive clients are rate
//!   limited and logged rather than served.
//!
//! The transport is blocking (one `std::thread` per connection) on purpose: the
//! service-side handler is called synchronously and never shares mutable state
//! across clients.

pub mod pipe;

use std::time::{Duration, Instant};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Default pipe name for the security service.
pub const IPC_PIPE_NAME: &str = r"\\.\pipe\ai-antivirus-security";

/// Maximum accepted payload size (1 MiB). Length prefixes above this are
/// rejected before any allocation happens.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Size of the little-endian u32 length prefix that precedes every payload.
pub const FRAME_HEADER_BYTES: usize = 4;

/// Version of the client/server wire protocol implemented by this crate.
pub const IPC_PROTOCOL_VERSION: u32 = 1;

/// Default burst capacity of [`RateLimiter::default`].
pub const DEFAULT_RATE_LIMIT_BURST: u32 = 64;

/// Default sustained per-second refill of [`RateLimiter::default`].
pub const DEFAULT_RATE_LIMIT_PER_SECOND: u32 = 32;

/// Errors produced by framing, validation and the named-pipe transport.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// The payload (or declared length) exceeds [`MAX_FRAME_BYTES`].
    #[error("frame payload of {size} byte(s) exceeds the maximum of {max} byte(s)")]
    FrameTooLarge { size: usize, max: usize },
    /// No frame data at all (empty buffer or zero declared length).
    #[error("frame is empty")]
    EmptyFrame,
    /// Fewer than [`FRAME_HEADER_BYTES`] bytes were supplied.
    #[error("frame is only {actual} byte(s); at least {FRAME_HEADER_BYTES} bytes are required for the length prefix")]
    HeaderTooShort { actual: usize },
    /// The declared payload length is larger than the data that was supplied.
    #[error("frame is truncated: declared {declared} payload byte(s) but only {actual} byte(s) are available")]
    TruncatedFrame { declared: usize, actual: usize },
    /// Extra bytes follow the declared payload; frames must be decoded one at a
    /// time so stream corruption cannot be silently skipped.
    #[error("frame has {extra} trailing byte(s) beyond the declared payload")]
    TrailingBytes { extra: usize },
    /// Payload is not valid JSON for the requested type.
    #[error("invalid JSON payload: {0}")]
    InvalidJson(String),
    /// In-memory serialization failed.
    #[error("failed to encode message: {0}")]
    Encode(String),
    /// The peer speaks a different protocol version.
    #[error("unsupported IPC protocol version {got}; this build speaks version {expected}")]
    VersionMismatch { expected: u32, got: u32 },
    /// The server answered with an [`ServerResponse::Error`].
    #[error("request rejected by the security service ({code}): {message}")]
    ServerError { code: String, message: String },
    /// Per-client rate limit exceeded.
    #[error("per-client rate limit exceeded")]
    RateLimited,
    /// Named-pipe operation failed (see message for the Win32 error).
    #[error("named-pipe operation failed: {0}")]
    Pipe(String),
    /// Operation is not available on this platform.
    #[error("operation not supported on this platform")]
    Unsupported,
    /// Underlying I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Requests sent from the desktop app to the security service.
///
/// Serialized with the variant name in a `"type"` tag using `snake_case`; for
/// example `{"type":"scan_path","path":"C:\\\\tmp","recursive":true}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientRequest {
    /// Liveness check; answered with [`ServerResponse::Pong`].
    Ping,
    /// Engine status snapshot; answered with [`ServerResponse::Status`].
    GetStatus,
    /// Start an asynchronous scan of `path`.
    ScanPath { path: String, recursive: bool },
    /// Request cancellation of a running scan job.
    CancelScan { job_id: String },
    /// Page through stored security events.
    ListEvents { limit: u32, offset: u32 },
    /// Fetch one stored security event by id.
    GetEvent { event_id: String },
    /// List quarantine records.
    ListQuarantine,
    /// Quarantine (copy into the vault + record) the file at `path`.
    QuarantineFile { path: String, reason: String },
    /// Restore a quarantined file by record id.
    RestoreQuarantine { id: String },
    /// Ask for a push-style event subscription.
    Subscribe,
}

/// Responses sent from the security service back to the client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerResponse {
    /// Answer to [`ClientRequest::Ping`]. `version` is the service's
    /// [`IPC_PROTOCOL_VERSION`] as a string.
    Pong { version: String, uptime_secs: u64 },
    /// Engine status snapshot (`security-service` `EngineStatus`, camelCase).
    Status(serde_json::Value),
    /// A scan job was queued.
    ScanAccepted { job_id: String },
    /// Result of [`ClientRequest::CancelScan`].
    Cancelled { job_id: String, cancelled: bool },
    /// A page of stored events (`EventPage`, camelCase).
    Events(serde_json::Value),
    /// One stored event (`SecurityEvent`, camelCase).
    Event(serde_json::Value),
    /// Quarantine records (`QuarantineRecord`, camelCase).
    Quarantine(Vec<serde_json::Value>),
    /// A quarantine record was created.
    QuarantineRecord(serde_json::Value),
    /// Result of a restore (`RestoreResult`, camelCase).
    Restore(serde_json::Value),
    /// Subscription accepted. See the `security-service` documentation for the
    /// streaming limitation.
    Subscribed,
    /// The request failed. `code` is a stable machine-readable token.
    Error { code: String, message: String },
}

impl ServerResponse {
    /// Build an [`ServerResponse::Error`] from two string-like values.
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Error {
            code: code.into(),
            message: message.into(),
        }
    }

    /// True when this response is an [`ServerResponse::Error`].
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }

    /// Machine-readable error code, when this is an error response.
    pub fn error_code(&self) -> Option<&str> {
        match self {
            Self::Error { code, .. } => Some(code.as_str()),
            _ => None,
        }
    }
}

/// Wire envelope for [`ClientRequest`]: adds the sender's protocol version so
/// the server can reject incompatible clients explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedRequest {
    /// Sender's [`IPC_PROTOCOL_VERSION`].
    pub version: u32,
    /// The request itself.
    pub request: ClientRequest,
}

/// Serialize any message into a length-prefixed frame.
///
/// Layout: 4-byte little-endian payload length, then the JSON payload.
pub fn encode_frame(message: &impl Serialize) -> Result<Vec<u8>, IpcError> {
    let payload = serde_json::to_vec(message).map_err(|err| IpcError::Encode(err.to_string()))?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge {
            size: payload.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Extract the JSON payload from a single complete frame.
pub fn frame_payload(bytes: &[u8]) -> Result<&[u8], IpcError> {
    if bytes.is_empty() {
        return Err(IpcError::EmptyFrame);
    }
    if bytes.len() < FRAME_HEADER_BYTES {
        return Err(IpcError::HeaderTooShort {
            actual: bytes.len(),
        });
    }
    let declared = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if declared == 0 {
        return Err(IpcError::EmptyFrame);
    }
    if declared > MAX_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge {
            size: declared,
            max: MAX_FRAME_BYTES,
        });
    }
    let available = bytes.len() - FRAME_HEADER_BYTES;
    if available < declared {
        return Err(IpcError::TruncatedFrame {
            declared,
            actual: available,
        });
    }
    if available > declared {
        return Err(IpcError::TrailingBytes {
            extra: available - declared,
        });
    }
    Ok(&bytes[FRAME_HEADER_BYTES..])
}

/// Decode exactly one complete frame into `T`.
///
/// Rejects empty input, shortened frames, length prefixes above
/// [`MAX_FRAME_BYTES`], trailing bytes and malformed JSON.
pub fn decode_frame<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, IpcError> {
    let payload = frame_payload(bytes)?;
    decode_payload(payload)
}

/// Decode a raw JSON payload (already stripped of the length prefix).
///
/// Used by stream readers that read the prefix and payload separately.
pub fn decode_payload<T: DeserializeOwned>(payload: &[u8]) -> Result<T, IpcError> {
    if payload.is_empty() {
        return Err(IpcError::EmptyFrame);
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge {
            size: payload.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    serde_json::from_slice(payload).map_err(|err| IpcError::InvalidJson(err.to_string()))
}

/// Encode a [`ClientRequest`] with the current protocol version.
pub fn encode_request(request: &ClientRequest) -> Result<Vec<u8>, IpcError> {
    encode_frame(&VersionedRequest {
        version: IPC_PROTOCOL_VERSION,
        request: request.clone(),
    })
}

/// Decode a [`ClientRequest`] from a complete frame, rejecting unknown
/// protocol versions.
pub fn decode_request(bytes: &[u8]) -> Result<ClientRequest, IpcError> {
    let payload = frame_payload(bytes)?;
    decode_request_payload(payload)
}

/// Decode a [`ClientRequest`] from a raw JSON payload (length prefix already
/// removed by a streaming reader), rejecting unknown protocol versions.
pub fn decode_request_payload(payload: &[u8]) -> Result<ClientRequest, IpcError> {
    let envelope: VersionedRequest = decode_payload(payload)?;
    if envelope.version != IPC_PROTOCOL_VERSION {
        return Err(IpcError::VersionMismatch {
            expected: IPC_PROTOCOL_VERSION,
            got: envelope.version,
        });
    }
    Ok(envelope.request)
}

/// Encode a [`ServerResponse`].
pub fn encode_response(response: &ServerResponse) -> Result<Vec<u8>, IpcError> {
    encode_frame(response)
}

/// Decode a [`ServerResponse`].
pub fn decode_response(bytes: &[u8]) -> Result<ServerResponse, IpcError> {
    decode_frame(bytes)
}

/// Token bucket used to bound how fast a single client may send requests.
///
/// The bucket starts full (allowing a short burst) and refills at
/// `refill_per_second` tokens per second up to `capacity`. Time is injected in
/// [`RateLimiter::try_acquire_at`] so tests are deterministic.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    capacity: f64,
    refill_per_second: f64,
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// Create a limiter that allows `capacity` back-to-back requests and then
    /// refills `refill_per_second` tokens per second.
    pub fn new(capacity: u32, refill_per_second: u32) -> Self {
        let capacity = capacity as f64;
        Self {
            capacity,
            refill_per_second: refill_per_second as f64,
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    /// Try to take one token using the current time.
    pub fn try_acquire(&mut self) -> bool {
        self.try_acquire_at(Instant::now())
    }

    /// Try to take one token at an explicit instant (for deterministic tests).
    pub fn try_acquire_at(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.capacity);
            self.last_refill = now;
        }
    }

    /// Currently available (fractional) token count. Diagnostic only.
    pub fn tokens(&self) -> f64 {
        self.tokens
    }

    /// Configured burst capacity.
    pub fn capacity(&self) -> f64 {
        self.capacity
    }

    /// Configured sustained refill rate per second.
    pub fn refill_per_second(&self) -> f64 {
        self.refill_per_second
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_RATE_LIMIT_BURST, DEFAULT_RATE_LIMIT_PER_SECOND)
    }
}

/// Returned by the transport when a client sends `Subscribe`.
///
/// Streaming pushes are not implemented yet: `Subscribe` is acknowledged with
/// [`ServerResponse::Subscribed`] and clients are expected to poll
/// ([`ClientRequest::ListEvents`] / [`ClientRequest::GetStatus`]) until the
/// stream is implemented.
pub const SUBSCRIBE_STREAMING_SUPPORTED: bool = false;

/// Describe the streaming limitation in one sentence (used in status payloads
/// and documentation).
pub const STREAMING_LIMITATION: &str = "Event streaming is not implemented; Subscribe is acknowledged and clients should poll ListEvents/GetStatus.";

/// Convenience: a `Duration` matching the default pipe read polling cadence for
/// tests. Exposed so integration tests do not hard-code constants.
pub const TEST_PIPE_WAIT: Duration = Duration::from_millis(250);

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample_requests() -> Vec<ClientRequest> {
        vec![
            ClientRequest::Ping,
            ClientRequest::GetStatus,
            ClientRequest::ScanPath {
                path: r"C:\Windows\Temp".to_string(),
                recursive: true,
            },
            ClientRequest::CancelScan {
                job_id: "job_1".to_string(),
            },
            ClientRequest::ListEvents {
                limit: 50,
                offset: 0,
            },
            ClientRequest::GetEvent {
                event_id: "evt_1".to_string(),
            },
            ClientRequest::ListQuarantine,
            ClientRequest::QuarantineFile {
                path: r"C:\Users\a\b.exe".to_string(),
                reason: "test".to_string(),
            },
            ClientRequest::RestoreQuarantine {
                id: "q_1".to_string(),
            },
            ClientRequest::Subscribe,
        ]
    }

    #[test]
    fn requests_roundtrip_through_versioned_frames() {
        for request in sample_requests() {
            let frame = encode_request(&request).expect("encode");
            let decoded = decode_request(&frame).expect("decode");
            assert_eq!(decoded, request);
        }
    }

    #[test]
    fn request_tags_are_snake_case_with_type_field() {
        let value = serde_json::to_value(ClientRequest::GetStatus).expect("json");
        assert_eq!(value["type"], "get_status");

        let value = serde_json::to_value(ClientRequest::ScanPath {
            path: "p".into(),
            recursive: false,
        })
        .expect("json");
        assert_eq!(value["type"], "scan_path");
        assert_eq!(value["path"], "p");
        assert_eq!(value["recursive"], false);

        let value =
            serde_json::to_value(ClientRequest::CancelScan { job_id: "j".into() }).expect("json");
        assert_eq!(value["type"], "cancel_scan");
        assert_eq!(value["job_id"], "j");
    }

    #[test]
    fn response_tags_are_snake_case_with_type_field() {
        let pong = ServerResponse::Pong {
            version: "1".into(),
            uptime_secs: 5,
        };
        let value = serde_json::to_value(&pong).expect("json");
        assert_eq!(value["type"], "pong");
        assert_eq!(value["version"], "1");

        let err = ServerResponse::error("invalid_path", "boom");
        let value = serde_json::to_value(&err).expect("json");
        assert_eq!(value["type"], "error");
        assert_eq!(value["code"], "invalid_path");
        assert!(err.is_error());
        assert_eq!(err.error_code(), Some("invalid_path"));

        let frame = encode_response(&pong).expect("encode");
        let decoded: ServerResponse = decode_frame(&frame).expect("decode");
        assert_eq!(decoded, pong);
    }

    #[test]
    fn frame_layout_is_length_prefixed_little_endian() {
        let frame = encode_frame(&ClientRequest::Ping).expect("encode");
        let declared = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(declared, frame.len() - FRAME_HEADER_BYTES);
        let payload: ClientRequest = decode_frame(&frame).expect("decode");
        assert_eq!(payload, ClientRequest::Ping);
    }

    #[test]
    fn frame_rejects_empty_input() {
        assert!(matches!(
            decode_frame::<ClientRequest>(&[]),
            Err(IpcError::EmptyFrame)
        ));
        assert!(matches!(
            decode_frame::<ClientRequest>(&[0, 0, 0]),
            Err(IpcError::HeaderTooShort { actual: 3 })
        ));
        assert!(matches!(
            decode_frame::<ClientRequest>(&[0, 0, 0, 0]),
            Err(IpcError::EmptyFrame)
        ));
    }

    #[test]
    fn frame_rejects_oversized_payloads() {
        let huge = "x".repeat(MAX_FRAME_BYTES + 1);
        match encode_frame(&huge) {
            Err(IpcError::FrameTooLarge { size, max }) => {
                assert!(size > MAX_FRAME_BYTES);
                assert_eq!(max, MAX_FRAME_BYTES);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }

        let declared = (MAX_FRAME_BYTES as u32 + 1).to_le_bytes();
        let mut bytes = Vec::from(declared);
        bytes.extend_from_slice(b"{}");
        match decode_frame::<ClientRequest>(&bytes) {
            Err(IpcError::FrameTooLarge { size, max }) => {
                assert_eq!(size, MAX_FRAME_BYTES + 1);
                assert_eq!(max, MAX_FRAME_BYTES);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn frame_rejects_truncated_payloads() {
        let frame = encode_frame(&ClientRequest::GetStatus).expect("encode");
        let truncated = &frame[..frame.len() - 2];
        match decode_frame::<ClientRequest>(truncated) {
            Err(IpcError::TruncatedFrame { declared, actual }) => {
                assert_eq!(declared, frame.len() - FRAME_HEADER_BYTES);
                assert_eq!(actual, frame.len() - FRAME_HEADER_BYTES - 2);
            }
            other => panic!("expected TruncatedFrame, got {other:?}"),
        }
    }

    #[test]
    fn frame_rejects_trailing_bytes() {
        let mut frame = encode_frame(&ClientRequest::Ping).expect("encode");
        frame.push(0);
        assert!(matches!(
            decode_frame::<ClientRequest>(&frame),
            Err(IpcError::TrailingBytes { extra: 1 })
        ));
    }

    #[test]
    fn frame_rejects_invalid_json() {
        let payload = b"{not json";
        let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(payload);
        match decode_frame::<ClientRequest>(&frame) {
            Err(IpcError::InvalidJson(message)) => assert!(!message.is_empty()),
            other => panic!("expected InvalidJson, got {other:?}"),
        }
    }

    #[test]
    fn request_rejects_unknown_protocol_version() {
        let envelope = VersionedRequest {
            version: IPC_PROTOCOL_VERSION + 1,
            request: ClientRequest::Ping,
        };
        let frame = encode_frame(&envelope).expect("encode");
        match decode_request(&frame) {
            Err(IpcError::VersionMismatch { expected, got }) => {
                assert_eq!(expected, IPC_PROTOCOL_VERSION);
                assert_eq!(got, IPC_PROTOCOL_VERSION + 1);
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn request_rejects_missing_protocol_version() {
        // A bare ClientRequest (no envelope) must not be accepted.
        let frame = encode_frame(&ClientRequest::Ping).expect("encode");
        match decode_request(&frame) {
            Err(IpcError::InvalidJson(message)) => {
                assert!(message.contains("version"), "message was {message}");
            }
            other => panic!("expected InvalidJson, got {other:?}"),
        }
    }

    #[test]
    fn request_rejects_unknown_variant() {
        let payload = br#"{"version":1,"request":{"type":"launch_missiles"}}"#;
        let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(payload);
        match decode_request(&frame) {
            Err(IpcError::InvalidJson(message)) => assert!(!message.is_empty()),
            other => panic!("expected InvalidJson, got {other:?}"),
        }
    }

    #[test]
    fn rate_limiter_allows_burst_then_denies() {
        let mut limiter = RateLimiter::new(5, 1);
        let now = Instant::now();
        for i in 0..5 {
            assert!(
                limiter.try_acquire_at(now),
                "burst token {i} should be allowed"
            );
        }
        assert!(
            !limiter.try_acquire_at(now),
            "6th request in the same instant must be denied"
        );
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let mut limiter = RateLimiter::new(4, 2);
        let start = Instant::now();
        for _ in 0..4 {
            assert!(limiter.try_acquire_at(start));
        }
        assert!(!limiter.try_acquire_at(start));

        // 500 ms at 2 tokens/s == exactly one token.
        let half_second = start + Duration::from_millis(500);
        assert!(limiter.try_acquire_at(half_second));
        assert!(!limiter.try_acquire_at(half_second));

        // After two more seconds the bucket is full again (capped at capacity).
        let later = half_second + Duration::from_secs(2);
        assert!((limiter.tokens() - 0.0).abs() < f64::EPSILON || limiter.tokens() > 0.0);
        for _ in 0..4 {
            assert!(limiter.try_acquire_at(later));
        }
        assert!(!limiter.try_acquire_at(later));
    }

    #[test]
    fn rate_limiter_never_exceeds_capacity() {
        let mut limiter = RateLimiter::new(3, 10);
        let start = Instant::now();
        for _ in 0..3 {
            assert!(limiter.try_acquire_at(start));
        }
        let much_later = start + Duration::from_secs(3600);
        limiter.refill(much_later);
        assert!(limiter.tokens() <= 3.0);
        for _ in 0..3 {
            assert!(limiter.try_acquire_at(much_later));
        }
        assert!(!limiter.try_acquire_at(much_later));
    }

    #[test]
    fn default_rate_limiter_matches_documented_defaults() {
        let limiter = RateLimiter::default();
        assert_eq!(limiter.capacity(), DEFAULT_RATE_LIMIT_BURST as f64);
        assert_eq!(
            limiter.refill_per_second(),
            DEFAULT_RATE_LIMIT_PER_SECOND as f64
        );
    }
}
