//! Error type shared by the HSM layer and the HTTP API.

use std::time::Duration;

use cryptoki::error::{Error as Pkcs11Error, RvError};

/// Errors produced by key backends (PKCS#11 or mock) and the session pool.
///
/// The variants are deliberately coarse. The HTTP layer maps them to status
/// codes and stable error codes; full detail (including the PKCS#11 return
/// value) is only ever written to logs, never returned to clients.
#[derive(Debug, thiserror::Error)]
pub enum HsmError {
    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("algorithm {algorithm} cannot be used with key {key_id} of kind {kind}")]
    AlgorithmMismatch {
        key_id: String,
        algorithm: String,
        kind: String,
    },

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("decryption failed: ciphertext or additional data did not authenticate")]
    DecryptFailed,

    #[error("HSM busy: no session became available within {0:?}")]
    Busy(Duration),

    #[error("HSM operation timed out after {0:?}")]
    Timeout(Duration),

    #[error("HSM unavailable: {0}")]
    Unavailable(String),

    #[error("PKCS#11 error: {0}")]
    Pkcs11(#[from] Pkcs11Error),

    #[error("internal error: {0}")]
    Internal(String),
}

impl HsmError {
    /// Stable, machine-readable code surfaced to API clients.
    pub fn code(&self) -> &'static str {
        match self {
            Self::KeyNotFound(_) => "KEY_NOT_FOUND",
            Self::AlgorithmMismatch { .. } => "ALGORITHM_MISMATCH",
            Self::UnsupportedAlgorithm(_) => "UNSUPPORTED_ALGORITHM",
            Self::InvalidInput(_) => "INVALID_INPUT",
            Self::DecryptFailed => "DECRYPT_FAILED",
            Self::Busy(_) => "HSM_BUSY",
            Self::Timeout(_) => "HSM_TIMEOUT",
            Self::Unavailable(_) => "HSM_UNAVAILABLE",
            Self::Pkcs11(_) => "HSM_ERROR",
            Self::Internal(_) => "INTERNAL",
        }
    }

    /// The underlying PKCS#11 return value, if this error came from the token.
    pub fn rv(&self) -> Option<&RvError> {
        match self {
            Self::Pkcs11(Pkcs11Error::Pkcs11(rv, _)) => Some(rv),
            _ => None,
        }
    }

    /// True when the session that produced this error can no longer be trusted
    /// and must be closed instead of being returned to the pool.
    pub fn invalidates_session(&self) -> bool {
        matches!(
            self.rv(),
            Some(
                RvError::SessionHandleInvalid
                    | RvError::SessionClosed
                    | RvError::DeviceError
                    | RvError::DeviceRemoved
                    | RvError::UserNotLoggedIn
                    | RvError::TokenNotPresent
                    | RvError::GeneralError
                    | RvError::HostMemory
                    | RvError::OperationActive
            )
        )
    }

    /// True for conditions a client may reasonably retry after a short delay.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Busy(_) | Self::Timeout(_) | Self::Unavailable(_)
        ) || self.invalidates_session()
    }
}
