#[cfg(feature = "std")]
use thiserror::Error;

/// Represents an error in proof creation, verification, or parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum ProofError {
    /// This error occurs when a proof failed to verify.
    #[cfg_attr(feature = "std", error("Proof verification failed."))]
    VerificationError,
}
