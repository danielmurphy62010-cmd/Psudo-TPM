# TPM Cryptographic Service (Windows Only)

A **Windows-only** Python cryptographic service for encrypted key storage, symmetric encryption, digital signatures, and local inter-process communication (IPC). The server relies on Windows DPAPI and Windows named pipes; Linux and macOS are not supported.

## Features

- Persistent encrypted storage for AES keys, ChaCha20 keys, Ed25519/Ed448 key material, and arbitrary byte values.
- AES and AES-GCM encryption/decryption through the compiled `Encryption` module.
- ChaCha20 encryption/decryption.
- Ed25519/Ed448 key generation or import of supplied private and/or public key bytes.
- Separate delete operations for AES, ChaCha20, byte entries, and Ed25519 key pairs. The current server handler only deletes Ed25519 entries containing both private and public keys.
- A main vault file plus a rolling backup grid containing up to 10 versions across 5 backup slots.
- Local request/response IPC using Windows named pipes and a 4-byte, big-endian length prefix.
- Optional Zstandard compression when the `zstandard` package is installed.

## How storage protection works

The service creates a random 32-byte storage key and writes a protected copy to `TPM/storage_key.bin`. Vault data is serialized, encrypted with AES-GCM using that storage key, and saved to `TPM/TPM.bin` with rolling backup copies.

**Important implementation detail:** the code uses Windows DPAPI (`CryptProtectData` and `CryptUnprotectData`) to protect the storage key. It does not call TPM 2.0 APIs directly, so this implementation alone does not guarantee that the key is protected by a physical TPM. DPAPI protection is tied to the Windows user context by default; whether additional hardware-backed protection is involved depends on the Windows configuration.

## Requirements

- **Windows only** — the server requires Windows DPAPI and Windows named pipes. Linux and macOS are unsupported.
- A Python version and architecture compatible with the compiled `Encryption` extension (`Encryption.pyd`).
- `pywin32` for named-pipe IPC.
- The dependencies required by `Encryption.pyd`, including `cryptography` and `argon2-cffi` if used by that build.
- `zstandard` is optional; without it, IPC payloads are sent without Zstandard compression.

Install the Python-side packages in the environment used to run or build the project. For example:

```powershell
python -m pip install pywin32 cryptography argon2-cffi zstandard
```

Keep the matching `Encryption.pyd` beside `TPM.py` when running from source. If using PyInstaller, bundle the compiled extension and its runtime dependencies. Build and run the application on Windows with a compatible Python version and architecture.

## Running

Start the server in a Windows terminal:

```powershell
python TPM.py
```

The server stores its files in the current user's home directory under the `TPM` folder. Its main vault is `TPM.bin`; the DPAPI-protected storage key is `storage_key.bin`.

Use `TPM_client.py` from a client script or import `TPMClient`:

```python
from TPM_client import TPMClient

client = TPMClient()
result = client.create_AES_key("app_aes_key")
print(result)
```

## Client examples

### AES-GCM

```python
from TPM_client import TPMClient

client = TPMClient()
result = client.create_AES_key("app_aes_key")

if result.get("status") == "ok":
    encrypted = client.encryptGCM(b"Confidential payload", key_id="app_aes_key")
    if encrypted.get("status") == "ok":
        decrypted = client.decryptGCM(encrypted["ciphertext"], key_id="app_aes_key")
        print(decrypted)
    client.delete_AES_key("app_aes_key")
```

### Import supplied symmetric key bytes

```python
client.create_AES_key("imported_aes", key=b"\x01" * 64)
client.create_chacha20_key("imported_chacha", key=b"\x02" * 32)
```

Use key lengths supported by your compiled `Encryption` implementation. Avoid hard-coding production keys in source code.

### Ed25519 key management

Generate a key pair:

```python
client.gen_ed25519("signing_key")
```

Import a key pair or only one side of it:

```python
client.gen_ed25519("imported_pair", private=private_bytes, public=public_bytes)
client.gen_ed25519("private_only", private=private_bytes)
client.gen_ed25519("public_only", public=public_bytes)
```

Only the supplied key material is stored when importing keys. A private-only entry can be used for signing, and a public-only entry can be used for verification, assuming the key format matches the `Encryption` implementation.

## Storage layout

The service creates the following files under the user's `TPM` directory:

- `storage_key.bin` — DPAPI-protected storage key.
- `TPM.bin` — primary encrypted vault.
- `TPM version-<version> backup-<slot>.bin` — rolling encrypted backups, up to 10 versions and 5 slots.

Keep these files together. Losing `storage_key.bin`, or losing access to the Windows account context that can unprotect it, can make the vault unrecoverable. Backing up the files does not remove the need to preserve the DPAPI recovery context.

## Security notes

- **Treat IPC clients as trusted.** The protocol deserializes requests with Python `pickle`; untrusted pickle data can execute code. Do not expose the pipe to untrusted local users or processes. For a stronger security boundary, replace pickle with a non-executable serialization format and add appropriate client authentication and pipe access controls.
- Protect the Windows account used by the service and restrict access to the storage directory.
- Keep `Encryption.pyd` and its dependencies trusted and up to date.
- The backup grid provides recovery from some damaged or unreadable vault copies; it is not a substitute for an independently stored backup.
- Cryptographic behavior and supported key sizes depend on the compiled `Encryption` module.
