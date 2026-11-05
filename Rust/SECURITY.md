# Security notes and threat model

This implementation protects vault data at rest and gives different executable/script
manifests separate key namespaces. It is not a hardware-isolated execution sandbox.

## Covered

- AES-256-GCM authenticates the outer vault and each inner container.
- The Windows RSA private key is persisted in the Microsoft Platform Crypto Provider
  and no private-key export operation is implemented.
- Linux stores the master key in Secret Service and caches it in the user's kernel keyring.
- IPC uses OS peer identity, bounded length-prefixed JSON, and no `pickle` deserialization.
- Executable/script file contents and canonical paths contribute to a full 256-bit ID.

## Not covered

- Plaintext/derived symmetric keys are not kept out of the Rust daemon's memory. `zeroize`
  reduces some residue but is not a hard guarantee against dumps, snapshots, compiler
  copies, swap, kernel copies, or hostile same-user code.
- Script discovery is incomplete without OS file-access telemetry. A process can import
  or generate code that is invisible to command-line, open-fd, and mapping inspection.
- The same OS account is not a strong isolation boundary. Linux user keyrings and a
  same-user IPC endpoint are available to same-user processes within their permissions.
- File hashing at connection time does not attest that the process executed those exact
  bytes or prevent a file from being replaced after hashing.
- No remote attestation, measured boot, TPM PCR policy, anti-rollback counter, or
  multi-user authorization policy is implemented.

Treat the service as a local encrypted key broker, not a complete TPM-backed sandbox.
