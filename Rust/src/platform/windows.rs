use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, RngCore};
use std::{ffi::c_void, fs, io, path::Path, slice};
use zeroize::{Zeroize, Zeroizing};

// Windows DPAPI. By intentionally omitting CRYPTPROTECT_LOCAL_MACHINE, the
// wrapped vault key is tied to the current Windows user profile (and normally
// this computer), rather than being decryptable by every local user.
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x0000_0001;
const DPAPI_MAGIC: &[u8; 8] = b"PTPMDP01";
const DPAPI_ENTROPY: &[u8] = b"Psudo-TPM\0vault-master-key\0v1";

#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

#[link(name = "crypt32")]
unsafe extern "system" {
    fn CryptProtectData(
        data_in: *mut DataBlob,
        description: *const u16,
        optional_entropy: *mut DataBlob,
        reserved: *mut c_void,
        prompt: *mut c_void,
        flags: u32,
        data_out: *mut DataBlob,
    ) -> i32;

    fn CryptUnprotectData(
        data_in: *mut DataBlob,
        description: *mut *mut u16,
        optional_entropy: *mut DataBlob,
        reserved: *mut c_void,
        prompt: *mut c_void,
        flags: u32,
        data_out: *mut DataBlob,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn input_blob(bytes: &[u8]) -> Result<DataBlob> {
    let len = u32::try_from(bytes.len()).context("DPAPI input is larger than DWORD")?;
    Ok(DataBlob { cb_data: len, pb_data: bytes.as_ptr() as *mut u8 })
}

unsafe fn free_blob(blob: &mut DataBlob, wipe: bool) {
    if blob.pb_data.is_null() {
        return;
    }
    if wipe && blob.cb_data != 0 {
        // DPAPI allocates this buffer. Wipe plaintext before releasing it.
        slice::from_raw_parts_mut(blob.pb_data, blob.cb_data as usize).zeroize();
    }
    LocalFree(blob.pb_data.cast());
    blob.pb_data = std::ptr::null_mut();
    blob.cb_data = 0;
}

fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut input = input_blob(plaintext)?;
    let mut entropy = input_blob(DPAPI_ENTROPY)?;
    let mut output = DataBlob { cb_data: 0, pb_data: std::ptr::null_mut() };
    let description = wide("Psudo-TPM vault master key");

    let ok = unsafe {
        CryptProtectData(
            &mut input,
            description.as_ptr(),
            &mut entropy,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        let error = io::Error::last_os_error();
        unsafe { free_blob(&mut output, false); }
        return Err(error).context("CryptProtectData (current-user DPAPI)");
    }
    if output.pb_data.is_null() || output.cb_data == 0 {
        unsafe { free_blob(&mut output, false); }
        bail!("CryptProtectData returned an empty protected blob");
    }

    let protected = unsafe {
        slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec()
    };
    unsafe { free_blob(&mut output, false); }
    Ok(protected)
}

fn dpapi_unprotect(protected: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut input = input_blob(protected)?;
    let mut entropy = input_blob(DPAPI_ENTROPY)?;
    let mut output = DataBlob { cb_data: 0, pb_data: std::ptr::null_mut() };

    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            std::ptr::null_mut(), // no description string requested
            &mut entropy,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        let error = io::Error::last_os_error();
        unsafe { free_blob(&mut output, true); }
        return Err(error).context("CryptUnprotectData (current-user DPAPI)");
    }
    if output.pb_data.is_null() || output.cb_data != 32 {
        let actual = output.cb_data;
        unsafe { free_blob(&mut output, true); }
        bail!("DPAPI returned an invalid master-key length ({actual}; expected 32)");
    }

    let mut key = Zeroizing::new([0u8; 32]);
    unsafe {
        key.copy_from_slice(slice::from_raw_parts(output.pb_data, 32));
        free_blob(&mut output, true);
    }
    Ok(key)
}

/// Load or create a random 256-bit AES master key protected by Windows DPAPI.
///
/// DPAPI protects only the small master key at rest. The vault data itself and
/// all per-container blobs are encrypted by the vault layer with AES-256-GCM.
pub fn load_or_create(root: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let path = root.join("master.dpapi");

    if path.exists() {
        let blob = fs::read(&path).context("reading master.dpapi")?;
        if blob.len() <= DPAPI_MAGIC.len() || &blob[..DPAPI_MAGIC.len()] != DPAPI_MAGIC {
            bail!("invalid master.dpapi envelope");
        }
        return dpapi_unprotect(&blob[DPAPI_MAGIC.len()..])
            .context("unprotecting vault master key with current-user DPAPI");
    }

    // Never silently create a new master key for an existing vault. Doing so
    // would make the existing TPM.bin and its backups permanently unreadable.
    if root.join("TPM.bin").exists() {
        bail!("TPM.bin exists but master.dpapi is missing; refusing to generate a replacement master key");
    }

    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *key);
    let protected = dpapi_protect(&key[..]).context("protecting new AES-256 master key with current-user DPAPI")?;

    let mut envelope = Vec::with_capacity(DPAPI_MAGIC.len() + protected.len());
    envelope.extend_from_slice(DPAPI_MAGIC);
    envelope.extend_from_slice(&protected);
    atomic_write(&path, &envelope).context("writing master.dpapi")?;
    Ok(key)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    let f = fs::OpenOptions::new().read(true).open(&tmp)?;
    f.sync_all()?;
    // This target is a one-time-created key file; an existing master.dpapi is
    // never overwritten by initialization.
    fs::rename(&tmp, path)?;
    Ok(())
}
