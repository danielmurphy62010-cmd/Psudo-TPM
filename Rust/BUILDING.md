# Build notes

The project is split into platform-specific providers selected with `cfg`:

- `src/platform/windows.rs`: direct CNG `NCrypt` FFI; links `ncrypt`, `kernel32`,
  and `advapi32`.
- `src/platform/linux.rs`: Secret Service via the Rust `keyring` v1 API and Linux
  `add_key` / `keyctl` syscalls via `libc`.
- `src/identity.rs`: Windows process lookup and Linux `/proc` process lookup.
- `src/ipc.rs`: owner/SYSTEM protected Windows named pipe and user-only Linux Unix
  domain socket.

Build from the project root with `cargo build --release`. Linux needs development
libraries required by the selected `keyring` Secret Service backend and an unlocked
D-Bus Secret Service at runtime. Windows needs the Windows SDK toolchain and a
functional Microsoft Platform Crypto Provider/TPM.

This source package was assembled without a Rust compiler in the build environment.
The package has therefore **not been compiled or tested** here. Run `cargo fmt --check`,
`cargo check`, and OS-specific integration tests on the intended build hosts before use.
