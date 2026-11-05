use anyhow::Result;
use std::path::Path;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

/// Load or initialize the 256-bit vault master key using an OS-protected provider.
pub fn load_or_create_master_key(root: &Path) -> Result<Zeroizing<[u8; 32]>> {
    #[cfg(target_os = "linux")]
    { return linux::load_or_create(root); }
    #[cfg(windows)]
    { return windows::load_or_create(root); }
    #[allow(unreachable_code)]
    anyhow::bail!("Psudo-TPM currently supports Windows and Linux only")
}
