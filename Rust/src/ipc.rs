use crate::{crypto, identity, Vault};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

const MAX_FRAME: usize = 16 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct Request {
    action: String,
    #[serde(default, alias = "id", alias = "key")]
    key_id: Option<String>,
    #[serde(default, alias = "value", alias = "bytes")]
    secret: Option<String>,
    #[serde(default, alias = "input", alias = "plaintext")]
    data: Option<String>,
    #[serde(default)]
    aad: Option<String>,
    #[serde(default)]
    length: Option<usize>,
}

impl Drop for Request {
    fn drop(&mut self) {
        if let Some(value) = self.key_id.as_mut() { value.zeroize(); }
        if let Some(value) = self.secret.as_mut() { value.zeroize(); }
        if let Some(value) = self.data.as_mut() { value.zeroize(); }
        if let Some(value) = self.aad.as_mut() { value.zeroize(); }
    }
}

#[derive(Debug, Serialize)]
struct Response {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<Vec<String>>,
}

impl Drop for Response {
    fn drop(&mut self) {
        if let Some(value) = self.message.as_mut() { value.zeroize(); }
        if let Some(value) = self.key_id.as_mut() { value.zeroize(); }
        if let Some(value) = self.data.as_mut() { value.zeroize(); }
        if let Some(values) = self.keys.as_mut() { for value in values { value.zeroize(); } }
    }
}

impl Response {
    fn ok() -> Self { Self { status: "ok", message: None, key_id: None, data: None, keys: None } }
    fn error(e: impl ToString) -> Self { Self { status: "error", message: Some(e.to_string()), key_id: None, data: None, keys: None } }
}

fn decode_optional(s: Option<String>) -> Result<Zeroizing<Vec<u8>>> {
    let Some(mut encoded) = s else { return Ok(Zeroizing::new(Vec::new())); };
    let decoded = B64.decode(encoded.as_bytes());
    encoded.zeroize();
    Ok(Zeroizing::new(decoded?))
}

fn handle(mut req: Request, vault: &Vault, manifest: &identity::ProcessManifest) -> Result<Response> {
    let action = req.action.as_str();
    let key_id = req.key_id.as_deref().unwrap_or("");
    match action {
        "ping" => Ok(Response::ok()),
        "container_id" => {
            let mut r = Response::ok();
            r.key_id = Some(manifest.container_id.clone());
            r.message = Some(format!("script_checksum={}", manifest.script_checksum));
            Ok(r)
        }
        "list" | "list_keys" | "get_keys" => {
            let mut r = Response::ok();
            r.keys = Some(vault.list(manifest)?);
            Ok(r)
        }
        "create_AES_key" | "create_aes_key" | "create_chacha20_key" | "create_bytes" | "put_secret" => {
            if key_id.is_empty() { bail!("key_id is required"); }
            let kind = match action {
                "create_AES_key" | "create_aes_key" => "aes256-gcm",
                "create_chacha20_key" => "chacha20-poly1305",
                _ => "bytes",
            };
            let secret = if req.secret.is_some() || req.data.is_some() {
                decode_optional(req.secret.take().or_else(|| req.data.take()))?
            } else if kind == "bytes" {
                let n = req.length.unwrap_or(32);
                if n > ((MAX_FRAME - 2048) * 3 / 4) { bail!("requested secret is too large for a base64 IPC response"); }
                let mut value = Zeroizing::new(vec![0u8; n]);
                OsRng.fill_bytes(&mut value);
                value
            } else {
                let mut value = Zeroizing::new(vec![0u8; 32]);
                OsRng.fill_bytes(&mut value);
                value
            };
            if kind != "bytes" && secret.len() != 32 { bail!("{kind} key must be exactly 32 bytes"); }
            vault.put(manifest, key_id, kind, &secret)?;
            let mut r = Response::ok();
            r.key_id = Some(key_id.to_string());
            Ok(r)
        }
        "get" | "get_bytes" | "get_secret" => {
            if key_id.is_empty() { bail!("key_id is required"); }
            let Some((_kind, value)) = vault.get(manifest, key_id)? else { bail!("key not found"); };
            let mut r = Response::ok();
            r.key_id = Some(key_id.to_string());
            r.data = Some(B64.encode(&value[..]));
            Ok(r)
        }
        "delete" | "delete_key" | "delete_bytes" | "delete_AES_key" | "delete_chacha20_key" | "delete_secret" => {
            if key_id.is_empty() { bail!("key_id is required"); }
            let deleted = vault.delete(manifest, key_id)?;
            let mut r = Response::ok();
            r.key_id = Some(key_id.to_string());
            r.message = Some(if deleted { "deleted" } else { "not found" }.to_string());
            Ok(r)
        }
        "encryptGCM" | "encrypt_gcm" | "encrypt" | "encrypt_chacha" => {
            if key_id.is_empty() { bail!("key_id is required"); }
            let input = decode_optional(req.data.take())?;
            let aad = decode_optional(req.aad.take())?;
            let Some((kind, key)) = vault.get(manifest, key_id)? else { bail!("key not found"); };
            let ciphertext = if action == "encrypt_chacha" || kind == "chacha20-poly1305" {
                crypto::chacha_encrypt(&key, &input, &aad)?
            } else {
                crypto::aes_gcm_encrypt(&key, &input, &aad)?
            };
            let mut r = Response::ok();
            r.data = Some(B64.encode(ciphertext));
            Ok(r)
        }
        "decryptGCM" | "decrypt_gcm" | "decrypt" | "decrypt_chacha" => {
            if key_id.is_empty() { bail!("key_id is required"); }
            let input = decode_optional(req.data.take())?;
            let aad = decode_optional(req.aad.take())?;
            let Some((kind, key)) = vault.get(manifest, key_id)? else { bail!("key not found"); };
            let plaintext = if action == "decrypt_chacha" || kind == "chacha20-poly1305" {
                crypto::chacha_decrypt(&key, &input, &aad)?
            } else {
                crypto::aes_gcm_decrypt(&key, &input, &aad)?
            };
            let mut r = Response::ok();
            r.data = Some(B64.encode(&plaintext[..]));
            Ok(r)
        }
        _ => bail!("unknown action: {action}"),
    }
}

fn serve_stream<S: Read + Write>(mut stream: S, vault: Arc<Vault>, manifest: identity::ProcessManifest) -> Result<()> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).context("reading request frame length")?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_FRAME { bail!("invalid IPC frame length: {n}"); }
    let mut body = Zeroizing::new(vec![0u8; n]);
    stream.read_exact(&mut body).context("reading request frame")?;
    let response = match serde_json::from_slice::<Request>(&body) {
        Ok(req) => match handle(req, &vault, &manifest) {
            Ok(r) => r,
            Err(e) => Response::error(format!("{e:#}")),
        },
        Err(e) => Response::error(format!("invalid JSON request: {e}")),
    };
    let encoded = Zeroizing::new(serde_json::to_vec(&response)?);
    if encoded.len() > MAX_FRAME { return Err(anyhow!("response exceeds IPC frame limit")); }
    stream.write_all(&(encoded.len() as u32).to_be_bytes())?;
    stream.write_all(&encoded)?;
    stream.flush()?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn run(vault: Arc<Vault>) -> Result<()> {
    use std::{fs, os::unix::{fs::{FileTypeExt, PermissionsExt}, net::{UnixListener, UnixStream}}, path::PathBuf, thread};
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join(format!("psudo-tpm-{}", unsafe { libc::geteuid() })));
    fs::create_dir_all(&runtime)?;
    if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
    }
    let socket = runtime.join("psudo-tpm.sock");
    if socket.exists() {
        let meta = fs::symlink_metadata(&socket)?;
        if !meta.file_type().is_socket() { bail!("refusing to replace non-socket IPC path {}", socket.display()); }
        if UnixStream::connect(&socket).is_ok() { bail!("another Psudo-TPM service is already listening at {}", socket.display()); }
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket).with_context(|| format!("binding {}", socket.display()))?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    eprintln!("[Psudo-TPM] listening on {}", socket.display());
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let vault = Arc::clone(&vault);
                thread::spawn(move || {
                    if let Err(e) = serve_linux_client(stream, vault) { eprintln!("[Psudo-TPM] client error: {e:#}"); }
                });
            }
            Err(e) => eprintln!("[Psudo-TPM] accept error: {e}"),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn serve_linux_client(stream: std::os::unix::net::UnixStream, vault: Arc<Vault>) -> Result<()> {
    use std::{os::fd::AsRawFd, time::Duration};
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    #[repr(C)] struct Ucred { pid: libc::pid_t, uid: libc::uid_t, gid: libc::gid_t }
    let mut cred = Ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<Ucred>() as libc::socklen_t;
    let rc = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut libc::c_void, &mut len) };
    if rc != 0 { return Err(std::io::Error::last_os_error()).context("SO_PEERCRED"); }
    if cred.uid != unsafe { libc::geteuid() } { bail!("IPC peer UID does not match service UID"); }
    if cred.pid <= 0 { bail!("invalid IPC peer PID"); }
    let manifest = identity::inspect_pid(cred.pid as u32).context("identifying Linux IPC peer process")?;
    serve_stream(stream, vault, manifest)
}

#[cfg(windows)]
pub fn run(vault: Arc<Vault>) -> Result<()> {
    use std::{ffi::c_void, fs::File, os::windows::io::FromRawHandle};
    type Handle = *mut c_void;
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const PIPE_TYPE_BYTE: u32 = 0;
    const PIPE_READMODE_BYTE: u32 = 0;
    const PIPE_WAIT: u32 = 0;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x8;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
    #[repr(C)] struct SecurityAttributes { length: u32, descriptor: Handle, inherit: i32 }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateNamedPipeW(name: *const u16, open_mode: u32, pipe_mode: u32, max_instances: u32, out_size: u32, in_size: u32, timeout: u32, security: *mut SecurityAttributes) -> Handle;
        fn ConnectNamedPipe(pipe: Handle, overlapped: *mut c_void) -> i32;
        fn GetNamedPipeClientProcessId(pipe: Handle, client_pid: *mut u32) -> i32;
        fn GetLastError() -> u32;
        fn CloseHandle(handle: Handle) -> i32;
        fn LocalFree(memory: Handle) -> Handle;
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl: *const u16, revision: u32, descriptor: *mut Handle, size: *mut u32) -> i32;
    }
    let pipe_name: Vec<u16> = r"\\.\pipe\tpm".encode_utf16().chain(Some(0)).collect();
    // Only the service account (owner) and LocalSystem can open the pipe.
    let sddl: Vec<u16> = "D:P(A;;GA;;;OW)(A;;GA;;;SY)".encode_utf16().chain(Some(0)).collect();
    let mut descriptor: Handle = std::ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut descriptor, std::ptr::null_mut()) } == 0 {
        return Err(std::io::Error::last_os_error()).context("creating named-pipe security descriptor");
    }
    let mut security = SecurityAttributes { length: std::mem::size_of::<SecurityAttributes>() as u32, descriptor, inherit: 0 };
    eprintln!("[Psudo-TPM] listening on \\\\.\\pipe\\tpm");
    loop {
        let handle = unsafe { CreateNamedPipeW(pipe_name.as_ptr(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, &mut security) };
        if handle == INVALID_HANDLE_VALUE {
            unsafe { LocalFree(descriptor); }
            return Err(std::io::Error::last_os_error()).context("CreateNamedPipeW");
        }
        let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) } != 0 || unsafe { GetLastError() } == 535;
        if !connected { unsafe { CloseHandle(handle); } continue; }
        let mut pid = 0u32;
        if unsafe { GetNamedPipeClientProcessId(handle, &mut pid) } == 0 || pid == 0 {
            unsafe { CloseHandle(handle); }
            continue;
        }
        let manifest = match identity::inspect_pid(pid) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[Psudo-TPM] rejecting pipe client PID {pid}: {e:#}");
                unsafe { CloseHandle(handle); }
                continue;
            }
        };
        let file = unsafe { File::from_raw_handle(handle as _) };
        let vault = Arc::clone(&vault);
        std::thread::spawn(move || {
            if let Err(e) = serve_stream(file, vault, manifest) { eprintln!("[Psudo-TPM] pipe client error: {e:#}"); }
        });
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn run(_vault: Arc<Vault>) -> Result<()> { bail!("IPC server is implemented for Windows and Linux only") }
