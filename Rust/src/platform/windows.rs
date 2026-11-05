use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, RngCore};
use std::{ffi::c_void, fs, path::Path};
use zeroize::Zeroizing;

// CNG / NCrypt. The private RSA key is persisted in the Microsoft Platform Crypto
// Provider. No private-key export API is called by this project.
type NcryptHandle = usize;
const NTE_BAD_KEYSET: i32 = 0x8009_0016u32 as i32;
const NCRYPT_PAD_OAEP_FLAG: u32 = 0x0000_0004;
const RSA_BITS: u32 = 3072;

#[repr(C)]
struct BcryptOaepPaddingInfo {
    hash_algorithm: *const u16,
    label: *mut u8,
    label_length: u32,
}

#[link(name = "ncrypt")]
unsafe extern "system" {
    fn NCryptOpenStorageProvider(provider: *mut NcryptHandle, name: *const u16, flags: u32) -> i32;
    fn NCryptCreatePersistedKey(provider: NcryptHandle, key: *mut NcryptHandle, alg: *const u16, name: *const u16, legacy_spec: u32, flags: u32) -> i32;
    fn NCryptOpenKey(provider: NcryptHandle, key: *mut NcryptHandle, name: *const u16, legacy_spec: u32, flags: u32) -> i32;
    fn NCryptSetProperty(handle: NcryptHandle, property: *const u16, input: *const u8, input_len: u32, flags: u32) -> i32;
    fn NCryptGetProperty(handle: NcryptHandle, property: *const u16, output: *mut u8, output_len: u32, result_len: *mut u32, flags: u32) -> i32;
    fn NCryptFinalizeKey(key: NcryptHandle, flags: u32) -> i32;
    fn NCryptEncrypt(key: NcryptHandle, input: *const u8, input_len: u32, padding: *const c_void, output: *mut u8, output_len: u32, result_len: *mut u32, flags: u32) -> i32;
    fn NCryptDecrypt(key: NcryptHandle, input: *const u8, input_len: u32, padding: *const c_void, output: *mut u8, output_len: u32, result_len: *mut u32, flags: u32) -> i32;
    fn NCryptFreeObject(handle: NcryptHandle) -> i32;
}

struct CngKey { provider: NcryptHandle, key: NcryptHandle }
impl Drop for CngKey {
    fn drop(&mut self) { unsafe { NCryptFreeObject(self.key); NCryptFreeObject(self.provider); } }
}

impl CngKey {
    fn open_or_create() -> Result<Self> {
        let provider_name = wide("Microsoft Platform Crypto Provider");
        let key_name = wide("PsudoTPM.MasterKey.RSA3072.v1");
        let rsa = wide("RSA");
        let mut provider = 0usize;
        let mut key = 0usize;
        let status = unsafe { NCryptOpenStorageProvider(&mut provider, provider_name.as_ptr(), 0) };
        check(status, "NCryptOpenStorageProvider(Microsoft Platform Crypto Provider)")?;
        let status = unsafe { NCryptOpenKey(provider, &mut key, key_name.as_ptr(), 0, 0) };
        if status == NTE_BAD_KEYSET {
            check(unsafe { NCryptCreatePersistedKey(provider, &mut key, rsa.as_ptr(), key_name.as_ptr(), 0, 0) }, "NCryptCreatePersistedKey(RSA)")?;
            let bits = RSA_BITS;
            let no_export = 0u32;
            // The private key is only used to decrypt the wrapped master key.
            // RSA public-key encryption does not require private-key signing usage.
            let decrypt_only = 0x0000_0001u32;
            check(unsafe { NCryptSetProperty(key, wide("Length").as_ptr(), &bits as *const _ as *const u8, 4, 0) }, "set RSA length")?;
            check(unsafe { NCryptSetProperty(key, wide("Export Policy").as_ptr(), &no_export as *const _ as *const u8, 4, 0) }, "disable private-key export")?;
            check(unsafe { NCryptSetProperty(key, wide("Key Usage").as_ptr(), &decrypt_only as *const _ as *const u8, 4, 0) }, "set RSA key usage")?;
            check(unsafe { NCryptFinalizeKey(key, 0) }, "NCryptFinalizeKey")?;
        } else if status != 0 {
            unsafe { NCryptFreeObject(provider); }
            check(status, "NCryptOpenKey")?;
        }
        // Do not trust a pre-existing key with our name. Verify it is the expected
        // size, non-exportable, and has the required public/private operation usage.
        let export_policy = get_u32(key, "Export Policy")?;
        let key_length = get_u32(key, "Length")?;
        let key_usage = get_u32(key, "Key Usage")?;
        if export_policy != 0 || key_length != RSA_BITS || key_usage != 0x1 {
            unsafe { NCryptFreeObject(key); NCryptFreeObject(provider); }
            bail!("existing CNG key does not meet non-exportable, decrypt-only RSA-3072 policy");
        }
        Ok(Self { provider, key })
    }

    fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>> { self.rsa_oaep(input, true) }
    fn decrypt(&self, input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(self.rsa_oaep(input, false)?))
    }

    fn rsa_oaep(&self, input: &[u8], encrypt: bool) -> Result<Vec<u8>> {
        let hash = wide("SHA256");
        let padding = BcryptOaepPaddingInfo { hash_algorithm: hash.as_ptr(), label: std::ptr::null_mut(), label_length: 0 };
        let mut needed = 0u32;
        let first = unsafe {
            if encrypt { NCryptEncrypt(self.key, input.as_ptr(), input.len() as u32, &padding as *const _ as *const c_void, std::ptr::null_mut(), 0, &mut needed, NCRYPT_PAD_OAEP_FLAG) }
            else { NCryptDecrypt(self.key, input.as_ptr(), input.len() as u32, &padding as *const _ as *const c_void, std::ptr::null_mut(), 0, &mut needed, NCRYPT_PAD_OAEP_FLAG) }
        };
        check(first, "NCrypt RSA-OAEP size query")?;
        let mut out = vec![0u8; needed as usize];
        let mut actual = 0u32;
        let status = unsafe {
            if encrypt { NCryptEncrypt(self.key, input.as_ptr(), input.len() as u32, &padding as *const _ as *const c_void, out.as_mut_ptr(), out.len() as u32, &mut actual, NCRYPT_PAD_OAEP_FLAG) }
            else { NCryptDecrypt(self.key, input.as_ptr(), input.len() as u32, &padding as *const _ as *const c_void, out.as_mut_ptr(), out.len() as u32, &mut actual, NCRYPT_PAD_OAEP_FLAG) }
        };
        check(status, "NCrypt RSA-OAEP operation")?;
        out.truncate(actual as usize);
        Ok(out)
    }
}

pub fn load_or_create(root: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let path = root.join("master.rsa");
    let cng = CngKey::open_or_create().context("opening TPM-backed Microsoft Platform Crypto Provider RSA key; this build deliberately does not fall back to a software private key")?;
    if path.exists() {
        let blob = fs::read(&path)?;
        if blob.len() < 12 || &blob[..8] != b"PTPMRSA1" { bail!("invalid master.rsa envelope"); }
        let secret = cng.decrypt(&blob[8..]).context("unwrapping vault master key with CNG RSA-OAEP")?;
        if secret.len() != 32 { bail!("unwrapped master key has invalid length"); }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&secret);
        return Ok(key);
    }
    if root.join("TPM.bin").exists() {
        bail!("TPM.bin exists but master.rsa is missing; refusing to generate a replacement master key");
    }
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *key);
    let wrapped = cng.encrypt(&key[..]).context("wrapping new master key with CNG RSA-OAEP")?;
    let mut data = b"PTPMRSA1".to_vec();
    data.extend_from_slice(&wrapped);
    atomic_write(&path, &data)?;
    Ok(key)
}

fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() }
fn get_u32(handle: NcryptHandle, property: &str) -> Result<u32> {
    let mut value = 0u32;
    let mut size = 0u32;
    check(unsafe { NCryptGetProperty(handle, wide(property).as_ptr(), &mut value as *mut _ as *mut u8, 4, &mut size, 0) }, "NCryptGetProperty")?;
    if size != 4 { bail!("CNG property {property} returned an unexpected size"); }
    Ok(value)
}
fn check(status: i32, what: &str) -> Result<()> {
    if status == 0 { Ok(()) } else { bail!("{what} failed: SECURITY_STATUS {status:#x}") }
}
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    let f = fs::OpenOptions::new().read(true).open(&tmp)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}
