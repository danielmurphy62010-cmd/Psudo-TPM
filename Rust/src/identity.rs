use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, path::{Path, PathBuf}, time::SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: String,
    pub role: String,
    pub size: u64,
    pub blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessManifest {
    pub executable: FileRecord,
    pub scripts: Vec<FileRecord>,
    /// First 4 bytes of the script-set BLAKE3 digest (display/cache hint only).
    pub script_checksum: String,
    /// Full 32-byte identity digest: this is the real container ID.
    pub container_id: String,
    pub digest: [u8; 32],
}

impl ProcessManifest {
    pub fn from_paths(executable: &Path, script_paths: &[PathBuf]) -> Result<Self> {
        let exe = fingerprint(executable, "executable")?;
        let mut scripts = Vec::new();
        for p in script_paths {
            let item = fingerprint(p, "script")?;
            if item.path != exe.path { scripts.push(item); }
        }
        scripts.sort_by(|a, b| sort_path(&a.path).cmp(&sort_path(&b.path)));
        scripts.dedup_by(|a, b| a.path == b.path);

        let mut sh = blake3::Hasher::new();
        sh.update(b"Psudo-TPM script-set v1\0");
        for s in &scripts {
            write_field(&mut sh, s.path.as_bytes());
            write_field(&mut sh, &hex::decode(&s.blake3)?);
        }
        let script_digest = sh.finalize();
        let script_checksum = hex::encode(&script_digest.as_bytes()[..4]);

        let mut h = blake3::Hasher::new();
        h.update(b"Psudo-TPM process-container manifest v1\0");
        write_field(&mut h, exe.path.as_bytes());
        write_field(&mut h, &hex::decode(&exe.blake3)?);
        write_field(&mut h, script_digest.as_bytes());
        let digest = *h.finalize().as_bytes();
        let container_id = hex::encode(digest);
        Ok(Self { executable: exe, scripts, script_checksum, container_id, digest })
    }
}

fn write_field(h: &mut blake3::Hasher, data: &[u8]) {
    h.update(&(data.len() as u64).to_be_bytes());
    h.update(data);
}

#[cfg(windows)]
fn sort_path(p: &str) -> String { p.to_lowercase() }
#[cfg(not(windows))]
fn sort_path(p: &str) -> String { p.to_string() }

pub fn fingerprint(path: &Path, role: &str) -> Result<FileRecord> {
    let canonical = path.canonicalize().with_context(|| format!("cannot canonicalize detected file {}", path.display()))?;
    let path_text = canonical.to_str().context("non-UTF-8 file paths are not supported by this manifest format")?.to_string();
    let mut file = File::open(&canonical).with_context(|| format!("cannot open detected file {}", canonical.display()))?;
    let before = file.metadata()?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    let after = file.metadata()?;
    if before.len() != after.len() || modified(&before) != modified(&after) {
        bail!("file changed while it was being fingerprinted: {}", canonical.display());
    }
    Ok(FileRecord { path: normalize_path(&path_text), role: role.to_string(), size: after.len(), blake3: hasher.finalize().to_hex().to_string() })
}

fn modified(m: &std::fs::Metadata) -> Option<SystemTime> { m.modified().ok() }

#[cfg(windows)]
fn normalize_path(path: &str) -> String {
    let p = path.strip_prefix("\\\\?\\").unwrap_or(path);
    p.replace('/', "\\").to_lowercase()
}
#[cfg(not(windows))]
fn normalize_path(path: &str) -> String { path.to_string() }

fn is_script(path: &Path) -> bool {
    let ext = path.extension().and_then(|x| x.to_str()).unwrap_or("").to_ascii_lowercase();
    matches!(ext.as_str(), "py" | "pyw" | "pyc" | "pyo" | "ps1" | "psm1" | "psd1" | "js" | "mjs" | "cjs" | "ts" | "rb" | "pl" | "lua" | "sh" | "bash" | "zsh" | "fish" | "bat" | "cmd" | "php" | "jar" | "r" | "jl" | "tcl" | "awk" | "exs" | "erl")
}

#[cfg(target_os = "linux")]
pub fn inspect_pid(pid: u32) -> Result<ProcessManifest> {
    use std::{collections::BTreeSet, fs};
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let exe = fs::read_link(proc.join("exe")).context("cannot read peer /proc/<pid>/exe; access may be restricted")?;
    let cwd = fs::read_link(proc.join("cwd")).unwrap_or_else(|_| PathBuf::from("/"));
    let raw = fs::read(proc.join("cmdline")).context("cannot read peer command line")?;
    let argv: Vec<String> = raw.split(|b| *b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect();
    let mut candidates = BTreeSet::<PathBuf>::new();

    // Primary script argument (Python, node, ruby, shells, PowerShell under Wine, etc.).
    let mut skip_next = false;
    for arg in argv.iter().skip(1) {
        if skip_next { skip_next = false; continue; }
        if matches!(arg.as_str(), "-c" | "-m" | "-e" | "-Command" | "-File") { skip_next = true; continue; }
        let p = PathBuf::from(arg);
        if is_script(&p) {
            let resolved = if p.is_absolute() { p } else { cwd.join(p) };
            if resolved.is_file() { candidates.insert(resolved); }
        }
    }

    // Capture script/source files that remain open in the process. This is best-effort;
    // short-lived imports are not guaranteed to remain visible here.
    if let Ok(entries) = fs::read_dir(proc.join("fd")) {
        for entry in entries.flatten() {
            if let Ok(target) = fs::read_link(entry.path()) {
                if is_script(&target) && target.is_file() { candidates.insert(target); }
            }
        }
    }
    // Python bytecode and other mapped script files can also appear in /proc/<pid>/maps.
    if let Ok(maps) = fs::read_to_string(proc.join("maps")) {
        for line in maps.lines() {
            // The first five whitespace-delimited fields are address, permissions,
            // offset, device, and inode. Preserve spaces in the optional pathname.
            let bytes = line.as_bytes();
            let mut cursor = 0usize;
            for _ in 0..5 {
                while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() { cursor += 1; }
                while cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() { cursor += 1; }
            }
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() { cursor += 1; }
            if cursor < line.len() {
                let p = PathBuf::from(&line[cursor..]);
                if is_script(&p) && p.is_file() { candidates.insert(p); }
            }
        }
    }

    let scripts: Vec<PathBuf> = candidates.into_iter().collect();
    ProcessManifest::from_paths(&exe, &scripts)
}

#[cfg(windows)]
pub fn inspect_pid(pid: u32) -> Result<ProcessManifest> {
    windows_process::inspect_pid(pid)
}

#[cfg(windows)]
mod windows_process {
    use super::*;
    use anyhow::{bail, Context};
    use std::{ffi::{c_void, OsString}, mem, os::windows::ffi::OsStringExt};

    type Handle = *mut c_void;
    type NtQueryFn = unsafe extern "system" fn(Handle, u32, *mut c_void, u32, *mut u32) -> i32;
    #[repr(C)] struct UnicodeString { length: u16, maximum_length: u16, buffer: *const u16 }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
        fn QueryFullProcessImageNameW(process: Handle, flags: u32, name: *mut u16, size: *mut u32) -> i32;
        fn GetModuleHandleW(name: *const u16) -> Handle;
        fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
        fn LocalFree(mem: Handle) -> Handle;
    }
    #[link(name = "shell32")]
    unsafe extern "system" { fn CommandLineToArgvW(cmd: *const u16, argc: *mut i32) -> *mut *mut u16; }

    pub fn inspect_pid(pid: u32) -> Result<ProcessManifest> {
        const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() { bail!("OpenProcess failed for named-pipe client PID {pid}: {}", std::io::Error::last_os_error()); }
        struct Guard(Handle); impl Drop for Guard { fn drop(&mut self) { unsafe { CloseHandle(self.0); } } }
        let _guard = Guard(process);

        let mut image = vec![0u16; 32768];
        let mut image_len = image.len() as u32;
        if unsafe { QueryFullProcessImageNameW(process, 0, image.as_mut_ptr(), &mut image_len) } == 0 {
            bail!("QueryFullProcessImageNameW failed: {}", std::io::Error::last_os_error());
        }
        let exe = PathBuf::from(OsString::from_wide(&image[..image_len as usize]));

        // ProcessCommandLineInformation (class 60) is intentionally obtained through
        // NtQueryInformationProcess. It is undocumented and may fail on future Windows;
        // fail closed rather than silently inventing a script list.
        let ntdll_name: Vec<u16> = "ntdll.dll".encode_utf16().chain(Some(0)).collect();
        let symbol = b"NtQueryInformationProcess\0";
        let ntdll = unsafe { GetModuleHandleW(ntdll_name.as_ptr()) };
        if ntdll.is_null() { bail!("ntdll.dll not available"); }
        let address = unsafe { GetProcAddress(ntdll, symbol.as_ptr()) };
        if address.is_null() { bail!("NtQueryInformationProcess not available"); }
        let nt_query: NtQueryFn = unsafe { mem::transmute(address) };
        let mut buffer = vec![0u64; 8192]; // aligned buffer for UNICODE_STRING
        let mut returned = 0u32;
        let status = unsafe { nt_query(process, 60, buffer.as_mut_ptr() as *mut c_void, (buffer.len() * 8) as u32, &mut returned) };
        if status < 0 { bail!("NtQueryInformationProcess(ProcessCommandLineInformation) failed: NTSTATUS {status:#x}"); }
        let base = buffer.as_ptr() as usize;
        let limit = base + buffer.len() * 8;
        let us = unsafe { &*(buffer.as_ptr() as *const UnicodeString) };
        let start = us.buffer as usize;
        if us.length % 2 != 0 || start < base || start.checked_add(us.length as usize).filter(|x| *x <= limit).is_none() {
            bail!("NtQueryInformationProcess returned an invalid command-line buffer");
        }
        let cmd = unsafe { std::slice::from_raw_parts(us.buffer, us.length as usize / 2) };
        let mut command_line = cmd.to_vec();
        command_line.push(0);
        let mut argc = 0i32;
        let argv_ptr = unsafe { CommandLineToArgvW(command_line.as_ptr(), &mut argc) };
        if argv_ptr.is_null() { bail!("CommandLineToArgvW failed"); }
        let args = unsafe { std::slice::from_raw_parts(argv_ptr, argc.max(0) as usize) }
            .iter().map(|p| unsafe {
                let mut n = 0;
                while *(*p).add(n) != 0 { n += 1; }
                OsString::from_wide(std::slice::from_raw_parts(*p, n))
            }).collect::<Vec<_>>();
        unsafe { LocalFree(argv_ptr as Handle); }

        let mut scripts = Vec::new();
        let mut skip_next = false;
        for arg in args.iter().skip(1) {
            if skip_next { skip_next = false; continue; }
            if matches!(arg.to_string_lossy().as_ref(), "-c" | "-m" | "-e" | "-Command" | "-File") { skip_next = true; continue; }
            let p = PathBuf::from(arg);
            if is_script(&p) && p.is_absolute() && p.is_file() { scripts.push(p); }
        }
        ProcessManifest::from_paths(&exe, &scripts).context("fingerprinting Windows client files")
    }
}
