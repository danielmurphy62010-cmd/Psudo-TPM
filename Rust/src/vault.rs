use crate::{crypto::{aes_gcm_decrypt, aes_gcm_encrypt, derive_container_key}, identity::ProcessManifest, platform};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::{Path, PathBuf}, sync::Mutex, time::{SystemTime, UNIX_EPOCH}};
use zeroize::{Zeroize, Zeroizing};

const OUTER_AAD: &[u8] = b"Psudo-TPM TPM.bin outer envelope v2";
const INNER_AAD_PREFIX: &[u8] = b"Psudo-TPM process container v2\0";
const FORMAT: &str = "PSUDO-TPM-VAULT";
const VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContainerData {
    /// Each item is a named secret/key, e.g. { "db-password": { "kind":"bytes", "value":"..." } }.
    pub entries: BTreeMap<String, Entry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub kind: String,
    pub value: String, // Base64; the whole ContainerData is encrypted in the per-container blob.
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ContainerEnvelope {
    manifest: ProcessManifest,
    checksum4: String,
    nonce: String,
    ciphertext: String,
    updated_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct VaultIndex {
    version: u32,
    containers: BTreeMap<String, ContainerEnvelope>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileEnvelope {
    format: String,
    version: u32,
    nonce: String,
    ciphertext: String,
}

pub struct Vault {
    root: PathBuf,
    master: Zeroizing<[u8; 32]>,
    index: Mutex<VaultIndex>,
}

impl Vault {
    pub fn open(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root).with_context(|| format!("creating vault directory {}", root.display()))?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
        let master = platform::load_or_create_master_key(&root)?;
        let main = root.join("TPM.bin");
        let index = if main.exists() {
            let envelope: FileEnvelope = serde_json::from_slice(&fs::read(&main)?)?;
            if envelope.format != FORMAT || envelope.version != VERSION { bail!("unsupported TPM.bin format/version"); }
            let blob = B64.decode(envelope.ciphertext)?;
            let mut packed = b"AGM1".to_vec();
            packed.extend_from_slice(&B64.decode(envelope.nonce)?);
            packed.extend_from_slice(&blob);
            let plaintext = aes_gcm_decrypt(&master[..], &packed, OUTER_AAD).context("authenticating TPM.bin")?;
            let mut idx: VaultIndex = serde_json::from_slice(&plaintext)?;
            if idx.version != VERSION { bail!("vault payload version mismatch"); }
            // The outer AEAD authenticates the index. Reject malformed IDs rather than
            // silently dropping a container and making it appear to have lost data.
            if idx.containers.iter().any(|(id, rec)| id != &rec.manifest.container_id || rec.checksum4 != rec.manifest.script_checksum) {
                bail!("vault index contains an inconsistent process-container record");
            }
            idx
        } else {
            VaultIndex { version: VERSION, containers: BTreeMap::new() }
        };
        let vault = Self { root, master, index: Mutex::new(index) };
        if !main.exists() { vault.persist()?; }
        Ok(vault)
    }

    pub fn container_id(manifest: &ProcessManifest) -> &str { &manifest.container_id }

    pub fn put(&self, manifest: &ProcessManifest, key: &str, kind: &str, secret: &[u8]) -> Result<()> {
        validate_name(key)?;
        let mut index = self.index.lock().map_err(|_| anyhow::anyhow!("vault mutex poisoned"))?;
        let mut data = self.load_container_locked(&index, manifest)?;
        data.entries.insert(key.to_string(), Entry { kind: kind.to_string(), value: B64.encode(secret) });
        self.save_container_locked(&mut index, manifest, &data)
    }

    pub fn get(&self, manifest: &ProcessManifest, key: &str) -> Result<Option<(String, Zeroizing<Vec<u8>>)>> {
        let index = self.index.lock().map_err(|_| anyhow::anyhow!("vault mutex poisoned"))?;
        let data = self.load_container_locked(&index, manifest)?;
        match data.entries.get(key) {
            Some(entry) => Ok(Some((entry.kind.clone(), Zeroizing::new(B64.decode(&entry.value)?)))),
            None => Ok(None),
        }
    }

    pub fn delete(&self, manifest: &ProcessManifest, key: &str) -> Result<bool> {
        let mut index = self.index.lock().map_err(|_| anyhow::anyhow!("vault mutex poisoned"))?;
        let mut data = self.load_container_locked(&index, manifest)?;
        let removed = data.entries.remove(key).is_some();
        if removed { self.save_container_locked(&mut index, manifest, &data)?; }
        Ok(removed)
    }

    pub fn list(&self, manifest: &ProcessManifest) -> Result<Vec<String>> {
        let index = self.index.lock().map_err(|_| anyhow::anyhow!("vault mutex poisoned"))?;
        Ok(self.load_container_locked(&index, manifest)?.entries.keys().cloned().collect())
    }

    fn load_container_locked(&self, index: &VaultIndex, manifest: &ProcessManifest) -> Result<ContainerData> {
        let Some(record) = index.containers.get(&manifest.container_id) else { return Ok(ContainerData::default()); };
        // Compare the full manifest digest, not the 4-byte quick checksum.
        if record.manifest.digest != manifest.digest { bail!("container identity collision or corrupt manifest"); }
        let key = derive_container_key(&self.master, &manifest.digest);
        let mut packed = b"AGM1".to_vec();
        packed.extend_from_slice(&B64.decode(&record.nonce)?);
        packed.extend_from_slice(&B64.decode(&record.ciphertext)?);
        let aad = inner_aad(&manifest.digest);
        let plaintext = aes_gcm_decrypt(&key[..], &packed, &aad)?;
        Ok(serde_json::from_slice(&plaintext).context("decoding process container blob")?)
    }

    fn save_container_locked(&self, index: &mut VaultIndex, manifest: &ProcessManifest, data: &ContainerData) -> Result<()> {
        let key = derive_container_key(&self.master, &manifest.digest);
        let plaintext = Zeroizing::new(serde_json::to_vec(data)?);
        let aad = inner_aad(&manifest.digest);
        let blob = aes_gcm_encrypt(&key[..], &plaintext, &aad)?;
        let record = ContainerEnvelope {
            manifest: manifest.clone(),
            checksum4: manifest.script_checksum.clone(),
            nonce: B64.encode(&blob[4..16]),
            ciphertext: B64.encode(&blob[16..]),
            updated_unix: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        };
        index.containers.insert(manifest.container_id.clone(), record);
        self.persist_locked(index)
    }

    fn persist(&self) -> Result<()> {
        let index = self.index.lock().map_err(|_| anyhow::anyhow!("vault mutex poisoned"))?;
        self.persist_locked(&index)
    }

    fn persist_locked(&self, index: &VaultIndex) -> Result<()> {
        let plaintext = Zeroizing::new(serde_json::to_vec(index)?);
        let blob = aes_gcm_encrypt(&self.master[..], &plaintext, OUTER_AAD)?;
        let envelope = FileEnvelope {
            format: FORMAT.to_string(), version: VERSION,
            nonce: B64.encode(&blob[4..16]), ciphertext: B64.encode(&blob[16..]),
        };
        let bytes = serde_json::to_vec(&envelope)?;
        let main = self.root.join("TPM.bin");
        rotate_backups(&self.root, &main)?;
        atomic_write(&main, &bytes)
    }
}

fn inner_aad(digest: &[u8; 32]) -> Vec<u8> {
    let mut aad = INNER_AAD_PREFIX.to_vec();
    aad.extend_from_slice(digest);
    aad
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 256 || name.contains('\0') { bail!("key name must be 1..256 bytes and contain no NUL"); }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(&tmp)?;
    use std::io::Write;
    f.write_all(bytes)?;
    f.sync_all()?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        unsafe extern "system" { fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32; }
        let from: Vec<u16> = tmp.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
        const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
        let ok = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) };
        if ok == 0 { return Err(std::io::Error::last_os_error()).context("MoveFileExW atomic replace"); }
    }
    #[cfg(not(windows))]
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() { if let Ok(dir) = fs::File::open(parent) { let _ = dir.sync_all(); } }
    Ok(())
}

fn rotate_backups(root: &Path, main: &Path) -> Result<()> {
    if !main.exists() { return Ok(()); }
    for n in (1..10).rev() {
        let from = root.join(format!("TPM version-{n}.bin"));
        let to = root.join(format!("TPM version-{}.bin", n + 1));
        if from.exists() { let _ = fs::copy(from, to)?; }
    }
    fs::copy(main, root.join("TPM version-1.bin"))?;
    Ok(())
}
