use anyhow::{bail, Context, Result};
use std::{path::PathBuf, sync::Arc};

fn main() -> Result<()> {
    // Acquire the singleton before creating/loading any master key or vault state.
    let _instance_lock = acquire_instance_lock()?;
    let root = dirs_fallback();
    std::fs::create_dir_all(&root)?;
    let vault = Arc::new(psudo_tpm::Vault::open(root)?);
    eprintln!("[Psudo-TPM] Rust service starting");
    psudo_tpm::ipc::run(vault)
}

#[cfg(windows)]
struct InstanceLock(*mut std::ffi::c_void);

#[cfg(windows)]
impl Drop for InstanceLock {
    fn drop(&mut self) {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn ReleaseMutex(mutex: *mut std::ffi::c_void) -> i32;
            fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
        }
        unsafe { ReleaseMutex(self.0); CloseHandle(self.0); }
    }
}

#[cfg(windows)]
fn acquire_instance_lock() -> Result<InstanceLock> {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateMutexW(attributes: *mut c_void, initial_owner: i32, name: *const u16) -> *mut c_void;
        fn GetLastError() -> u32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }
    let name: Vec<u16> = "Local\\PsudoTPM-Service-v2".encode_utf16().chain(Some(0)).collect();
    let handle = unsafe { CreateMutexW(std::ptr::null_mut(), 1, name.as_ptr()) };
    if handle.is_null() { return Err(std::io::Error::last_os_error()).context("CreateMutexW"); }
    if unsafe { GetLastError() } == 183 {
        unsafe { CloseHandle(handle); }
        bail!("another Psudo-TPM service instance is already running");
    }
    Ok(InstanceLock(handle))
}

#[cfg(target_os = "linux")]
struct InstanceLock(std::fs::File);

#[cfg(target_os = "linux")]
fn acquire_instance_lock() -> Result<InstanceLock> {
    use std::{fs, os::unix::{fs::{MetadataExt, OpenOptionsExt, PermissionsExt}, io::AsRawFd}};
    let is_custom = std::env::var_os("XDG_RUNTIME_DIR").is_some();
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join(format!("psudo-tpm-{}", unsafe { libc::geteuid() })));
    fs::create_dir_all(&runtime).with_context(|| format!("creating runtime directory {}", runtime.display()))?;
    let before = fs::symlink_metadata(&runtime)?;
    if !before.file_type().is_dir() || before.uid() != unsafe { libc::geteuid() } {
        bail!("runtime directory must be a real directory owned by the service UID: {}", runtime.display());
    }
    if !is_custom { fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?; }
    let meta = fs::symlink_metadata(&runtime)?;
    if meta.mode() & 0o077 != 0 {
        bail!("runtime directory must not be accessible by group/other users: {}", runtime.display());
    }
    let lock_path = runtime.join("psudo-tpm.lock");
    let lock = fs::OpenOptions::new().read(true).write(true).create(true).mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW).open(&lock_path)
        .with_context(|| format!("opening singleton lock {}", lock_path.display()))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error()).context("another Psudo-TPM service instance is already running");
    }
    Ok(InstanceLock(lock))
}

fn dirs_fallback() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("Psudo-TPM")
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
            .unwrap_or_else(std::env::temp_dir)
            .join("psudo-tpm")
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        std::env::temp_dir().join("psudo-tpm")
    }
}
