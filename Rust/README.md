# Psudo-TPM (Rust port / v2 storage format)

A Rust rewrite of the local Psudo-TPM key-vault service. It creates a separate
cryptographic namespace for each executable + detected-script set. It does not
use the old `Encryption.py` module.

> **Security status:** this is a source baseline, not an audited or production-certified
> TPM implementation. It has deliberately conservative failure behavior, but must be
> built, tested on both target operating systems, and reviewed before storing valuable
> secrets. This environment did not have Rust/Cargo installed, so this source was not
> compiled here.

## Design summary

* **Windows:** a persisted RSA-3072 key is created through CNG `NCrypt` in the
  **Microsoft Platform Crypto Provider**. The private key is configured as
  non-exportable and restricted to private-key decryption; it is used only through CNG
  handles to unwrap a random 256-bit vault master key using RSA-OAEP-SHA-256. The Platform Crypto Provider is TPM-backed
  on supported systems. There is intentionally no silent software-provider fallback.
* **Linux:** the master key is stored in the desktop OS Secret Service using the
  `keyring` crate and cached in the current user's kernel keyring using `add_key(2)` /
  `keyctl(2)`. The kernel cache is session/kernel scoped; the Secret Service credential
  provides persistence across restarts. This Linux implementation is **not** TPM2
  sealed storage and requires an available/unlocked Secret Service provider (such as
  GNOME Keyring or KWallet) on first initialization. It does not use `Encryption.py`.
* **Authenticated encryption:** `TPM.bin` and each process-container blob use
  AES-256-GCM with random 96-bit nonces and domain-separated AAD. Named application
  keys can use AES-256-GCM or ChaCha20-Poly1305. The old unauthenticated AES-CTR path
  is not reproduced; `encrypt`/`decrypt` aliases use AES-GCM instead.
* **IPC:** one JSON request per connection, framed by a 4-byte big-endian length. The service acquires a singleton lock before initializing the vault; Windows also rejects remote named-pipe clients.
  The frame limit is 16 MiB. This replaces Python `pickle`, which should not be
  accepted from untrusted IPC clients.
* **Python use:** `python/TPM_client.py` is a small standard-library IPC client.
  The Rust crate is emitted as an `rlib`; this version does not provide a PyO3
  extension module.

## `TPM.bin` layout

The on-disk file is a JSON **envelope**. The entire index is encrypted, so executable
paths, script paths, checksums, container IDs, key names, and secret metadata are not
visible in the clear. Conceptually, after outer decryption, the structure is:

```text
TPM.bin
└── AES-256-GCM(master_key, outer AAD)
    └── VaultIndex
        └── containers[full_container_id]
            ├── manifest
            │   ├── executable: canonical path + BLAKE3(file contents)
            │   └── scripts[]: canonical path + BLAKE3(file contents), sorted by path
            ├── script_checksum: first 4 bytes of BLAKE3(sorted script manifest)
            └── encrypted_blob
                └── AES-256-GCM(container_key, manifest digest as AAD)
                    └── entries (BTreeMap, therefore key names are sorted)
                        ├── key_name -> { kind, value: Base64(secret) }
                        └── key_name -> { kind, value: Base64(secret) }
```

The outer JSON file contains only `format`, `version`, `nonce`, and `ciphertext`.
The per-container `container_key` is derived as a keyed BLAKE3 PRF:

```text
container_key = BLAKE3_keyed(master_key,
    "Psudo-TPM container encryption key v1" || manifest_digest)
```

The master key is random 256-bit key material, not a human password. For this input,
keyed BLAKE3 is being used as a deterministic PRF/KDF; it is not being used as a
password-hardening function. If you later derive the master from a password, use a
memory-hard password KDF such as Argon2id instead.

### Why JSON instead of SQLite?

For this format the service encrypts and authenticates the entire logical index as one
unit. JSON is simpler, portable, and avoids exposing SQLite page structure, freelist,
WAL, and metadata. SQLite would become attractive for large vaults or concurrent
partial updates, but it should then be paired with a well-supported encrypted-database
layer and a deliberate WAL/backup design. JSON here is the smaller and easier-to-audit
choice.

### Why two checksums?

The requested 4-byte BLAKE3 script checksum is retained as a compact fingerprint. It
is **not** used as the container ID or key input because 32-bit collisions are easy to
produce at scale. The actual container ID and KDF input are the complete 32-byte
manifest digest. The digest commits to the canonical executable path, executable
contents, sorted script paths, and script contents. Windows paths are case-normalized;
Linux paths retain case.

## Process and script identification

* Windows IPC uses an explicit owner-and-SYSTEM-only DACL on the named pipe and obtains the connected client PID with `GetNamedPipeClientProcessId`.
  `QueryFullProcessImageNameW` obtains its executable path. The implementation calls
  `NtQueryInformationProcess` using `ProcessCommandLineInformation` to obtain the
  command line and then fingerprints absolute script arguments.
* Linux obtains PID/UID/GID with `SO_PEERCRED`, verifies that the peer UID matches the
  service UID, and examines `/proc/<pid>/exe`, `cmdline`, open file descriptors, and
  memory maps.
* Both sides fingerprint files by streaming their full contents through BLAKE3 and
  sorting detected scripts by canonical path before constructing the manifest.

**Detection is best-effort, not a complete script-load monitor.** Process metadata APIs
cannot guarantee discovery of every script a runtime imported, especially scripts that
were opened and closed before inspection, dynamically generated code, code loaded from
memory, archive members, or files accessed through custom loaders. On Windows, relative
script arguments are currently not resolved. For comprehensive monitoring, a later
version needs OS-level file telemetry (e.g. ETW plus a minifilter or an audited file
access broker on Windows; eBPF/audit/fanotify or an LSM-based broker on Linux) and a
policy for how to handle files that change after being loaded. The manifest identifies
the files observed at connection time, not a perfect record of every byte ever executed.

This is a **per-process key namespace**, not an OS sandbox. It does not isolate process
memory, filesystem access, networking, or child processes. For actual execution
containment, combine it with Windows AppContainer/lowbox tokens and job objects, or
Linux namespaces, seccomp, Landlock, and cgroups. A process that can connect to the
same user-level service and satisfy the OS peer checks can request operations for its
own detected manifest; add an explicit allowlist/approval policy if arbitrary programs
must not be able to create containers.

## Key exposure limitations

The Windows RSA private key is never exported by this code. `NCrypt` performs the
private RSA operation through a persisted provider key handle. With the Microsoft
Platform Crypto Provider, the TPM protects the private key. However, the 32-byte master
key is unwrapped into the Rust service process so that Rust's AES-GCM implementation
can encrypt/decrypt `TPM.bin`, and each active container key and plaintext necessarily
exist in process memory during use. `zeroize` is used for several buffers, but this
cannot erase compiler copies, allocator remnants, kernel buffers, or crash dumps.

Linux `keyctl` is not an enclave: a permitted process under the same user may be able
to access user keyring material, and this implementation also reads the master key into
the service to perform AEAD. If you require a stricter boundary, move all AEAD operations
into an isolated broker/provider that never returns keys, restrict its IPC with OS ACLs,
and consider hardware-backed symmetric-key operations where available. RSA wrapping
alone cannot make a user-space AES key remain hidden while the user-space AES operation
runs.

## Build and run

Requires Rust 1.88 or newer and a supported OS.

```bash
cargo build --release
cargo run --release
```

Default storage directories:

* Windows: `%LOCALAPPDATA%\Psudo-TPM\`
* Linux: `$XDG_STATE_HOME/psudo-tpm/`, otherwise `~/.local/state/psudo-tpm/`

IPC endpoints:

* Windows: `\\.\pipe\tpm`
* Linux: `$XDG_RUNTIME_DIR/psudo-tpm.sock`; if `XDG_RUNTIME_DIR` is unset,
  `/tmp/psudo-tpm-<uid>/psudo-tpm.sock` (directory/socket permissions are user-only).

Linux needs an unlocked Secret Service on first run. Windows needs a TPM and the
Microsoft Platform Crypto Provider available. If key material is missing while
`TPM.bin` exists, startup fails closed rather than silently creating a new master key.

## Python client example

```python
from TPM_client import TPMClient

client = TPMClient()
client.create_aes_key("database")
ciphertext = client.encrypt_gcm("database", b"secret", aad=b"context")
assert client.decrypt_gcm("database", ciphertext, aad=b"context") == b"secret"
```

The Python client opens a fresh IPC connection per request. Keep the Rust daemon running
as the same user as the client.

## Compatibility and migration notes

This is a new v2 on-disk format and a new JSON IPC protocol. It does **not** read the old
Python pickle-based `TPM.bin`, DPAPI key file, or old `Encryption.py` ciphertexts. Make a
separate, explicitly reviewed migration/export path before replacing an existing vault;
never point this service at an old vault and expect automatic conversion. The old
Ed25519 helper operations and TLS private-key/certificate helpers are not yet included
in this first port; current IPC implements named byte secrets, AES-GCM, and
ChaCha20-Poly1305.

The original repository is GPL-3.0; see `LICENSE`.
