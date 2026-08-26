//! The error type shared by every fallible operation in this crate.

/// The result type used throughout this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Everything that can go wrong in this crate.
///
/// The variants describe *shapes* — a wrong length, a truncated box, a
/// malformed attribute — rather than one variant per call site, so matching on
/// them stays useful as the crate grows. It is `#[non_exhaustive]`: match with
/// a `_` arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A byte string was not the length its format requires.
    ///
    /// `what` names the value (`"AES-128 key"`, `"key ID"`, …) so the message
    /// is readable without the caller adding context.
    #[error("{what} must be {expected} bytes, got {actual}")]
    InvalidLength {
        /// What was being measured, for the message.
        what: &'static str,
        /// The length the format requires.
        expected: usize,
        /// The length that was actually supplied.
        actual: usize,
    },

    /// A ciphertext was not a whole number of 16-byte AES blocks.
    #[error("ciphertext of {0} bytes is not a multiple of the 16-byte AES block size")]
    UnalignedCiphertext(usize),

    /// PKCS#7 unpadding failed after decryption.
    ///
    /// This means the decrypted bytes did not end in valid padding, which
    /// usually means the wrong key or IV. Note that CBC is unauthenticated:
    /// see the [crate-level warning](crate#what-this-crate-does-not-do).
    #[error("PKCS#7 padding is invalid — wrong key or IV, or the ciphertext was altered")]
    InvalidPadding,

    /// An input that must be non-empty was empty.
    #[error("{0} must not be empty")]
    EmptyInput(&'static str),

    /// A structure ended before the bytes its own header promised.
    #[error("{what} is truncated: needed {needed} bytes, {available} available")]
    Truncated {
        /// What was being read, for the message.
        what: &'static str,
        /// The byte count the header called for.
        needed: usize,
        /// The byte count actually present.
        available: usize,
    },

    /// A structure was well-sized but did not hold what its format requires.
    #[error("malformed {what}: {detail}")]
    Malformed {
        /// What was being read, for the message.
        what: &'static str,
        /// Why it was rejected.
        detail: &'static str,
    },

    /// A hex-encoded value (an `EXT-X-KEY` `IV`, for instance) did not decode.
    #[error("invalid hex")]
    Hex(#[from] hex::FromHexError),

    /// Reading a file from disk failed.
    #[error("i/o error")]
    Io(#[from] std::io::Error),

    /// The operating system refused to supply random bytes.
    #[error("could not read from the system random number generator")]
    Rng(#[from] getrandom::Error),
}
