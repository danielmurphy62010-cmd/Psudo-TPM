//! Psudo-TPM Rust service.
//!
//! `TPM.bin` is an authenticated-encrypted JSON document. The document contains
//! per-process containers; each container is independently AES-256-GCM sealed
//! with a deterministic key derived from the platform master key and the
//! canonical executable/script manifest.

pub mod crypto;
pub mod identity;
pub mod ipc;
pub mod platform;
pub mod vault;

pub use identity::{FileRecord, ProcessManifest};
pub use vault::Vault;
