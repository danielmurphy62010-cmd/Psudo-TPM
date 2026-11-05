use anyhow::Result;
use std::path::Path;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

/// Load or initialize the 256-bit vault master key using an OS-protected provider.
#[cfg(target_os = "linux")]
pub fn load_or_create_master_key(root: &Path) -> Result<Zeroizing<[u8; 32]>> {
    linux::load_or_create(root)
}

/// Load or initialize the 256-bit vault master key using Windows CNG.
#[cfg(windows)]
pub fn load_or_create_master_key(root: &Path) -> Result<Zeroizing<[u8; 32]>> {
    windows::load_or_create(root)
}

/// Other operating systems are intentionally unsupported.
#[cfg(not(any(target_os = "linux", windows)))]
pub fn load_or_create_master_key(_root: &Path) -> Result<Zeroizing<[u8; 32]>> {
    Err(anyhow::anyhow!("Psudo-TPM currently supports Windows and Linux only"))
}
