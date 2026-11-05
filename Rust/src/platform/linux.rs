use anyhow::{bail, Context, Result};
use keyring::{Entry, Error as KeyringError};
use rand::{rngs::OsRng, RngCore};
use std::{ffi::CString, path::Path};
use zeroize::{Zeroize, Zeroizing};

const SERVICE: &str = "Psudo-TPM";
const USERNAME: &str = "master-key-v1";
const KEY_SPEC_USER_KEYRING: libc::c_long = -4;
const KEYCTL_SEARCH: libc::c_long = 10;
const KEYCTL_READ: libc::c_long = 11;

pub fn load_or_create(root: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let entry = Entry::new(SERVICE, USERNAME).context("opening Linux Secret Service keyring entry")?;
    match entry.get_secret() {
        Ok(secret) => {
            let key = to_master(secret)?;
            let _ = keyctl_store(&key);
            Ok(key)
        }
        Err(KeyringError::NoEntry) => {
            if let Some(key) = keyctl_read()? {
                entry.set_secret(&key[..]).context("restoring master key from the kernel keyring to Secret Service")?;
                return Ok(key);
            }
            if root.join("TPM.bin").exists() {
                bail!("TPM.bin exists but the OS keyring and kernel user keyring are missing the master key; refusing to create a replacement key");
            }
            let mut key = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut *key);
            entry.set_secret(&key[..]).context("storing master key in Linux Secret Service (install/unlock a Secret Service provider such as GNOME Keyring or KWallet)")?;
            keyctl_store(&key).context("caching master key in the kernel user keyring via keyctl")?;
            Ok(key)
        }
        Err(err) => {
            if let Some(key) = keyctl_read()? { return Ok(key); }
            Err(err).context("Linux keyring is unavailable or locked and no kernel-keyring cache exists")
        }
    }
}

fn to_master(mut secret: Vec<u8>) -> Result<Zeroizing<[u8; 32]>> {
    if secret.len() != 32 { secret.zeroize(); bail!("OS keyring entry has an invalid master-key length"); }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&secret);
    secret.zeroize();
    Ok(key)
}

fn key_description() -> CString { CString::new("psudo-tpm/master-key-v1").expect("static key description") }

/// Cache the key in the calling user's kernel keyring. It is still returned to the
/// daemon for AEAD in this implementation; see README for the memory-isolation limit.
fn keyctl_store(key: &[u8; 32]) -> Result<()> {
    let kind = CString::new("user")?;
    let desc = key_description();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            kind.as_ptr(), desc.as_ptr(), key.as_ptr(), key.len(), KEY_SPEC_USER_KEYRING,
        )
    };
    if rc < 0 { return Err(std::io::Error::last_os_error()).context("keyctl add_key(user)"); }
    Ok(())
}

/// Read a cached user key using KEYCTL_SEARCH + KEYCTL_READ.
fn keyctl_read() -> Result<Option<Zeroizing<[u8; 32]>>> {
    let kind = CString::new("user")?;
    let desc = key_description();
    let serial = unsafe {
        libc::syscall(libc::SYS_keyctl, KEYCTL_SEARCH, KEY_SPEC_USER_KEYRING, kind.as_ptr(), desc.as_ptr(), KEY_SPEC_USER_KEYRING)
    };
    if serial < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOKEY) || e.raw_os_error() == Some(libc::EACCES) { return Ok(None); }
        return Err(e).context("keyctl search");
    }
    let mut out = Zeroizing::new([0u8; 32]);
    let n = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_READ, serial, out.as_mut_ptr(), out.len(), 0) };
    if n < 0 { return Err(std::io::Error::last_os_error()).context("keyctl read"); }
    if n != 32 { bail!("kernel keyring returned {} bytes; expected 32", n); }
    Ok(Some(out))
}
