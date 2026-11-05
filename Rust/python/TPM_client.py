"""Small Python client for the Rust Psudo-TPM service.

Wire protocol: 4-byte big-endian length followed by one UTF-8 JSON request;
response uses the same framing. Secret/data values are Base64 strings.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import struct
from typing import Any

MAX_FRAME = 16 * 1024 * 1024
PIPE_NAME = r"\\.\pipe\tpm"


class TPMError(RuntimeError):
    pass


class TPMClient:
    def __init__(self, endpoint: str | None = None, timeout: float = 30.0):
        self.endpoint = endpoint
        self.timeout = timeout

    def _open(self):
        if os.name == "nt":
            # Python's built-in open() supports Win32 named-pipe paths.
            return open(self.endpoint or PIPE_NAME, "r+b", buffering=0)
        path = self.endpoint or os.path.join(
            os.environ.get("XDG_RUNTIME_DIR", f"/tmp/psudo-tpm-{os.geteuid()}"),
            "psudo-tpm.sock",
        )
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(path)
        return s

    @staticmethod
    def _read_exact(stream: Any, count: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            part = stream.recv(count - len(chunks)) if hasattr(stream, "recv") else stream.read(count - len(chunks))
            if not part:
                raise TPMError("connection closed before complete response")
            chunks.extend(part)
        return bytes(chunks)

    def request(self, action: str, **fields: Any) -> dict[str, Any]:
        payload = json.dumps({"action": action, **fields}, separators=(",", ":")).encode("utf-8")
        if not payload or len(payload) > MAX_FRAME:
            raise ValueError("request exceeds the 16 MiB IPC frame limit")
        frame = struct.pack(">I", len(payload)) + payload
        stream = self._open()
        try:
            if hasattr(stream, "sendall"):
                stream.sendall(frame)
            else:
                stream.write(frame)
                stream.flush()
            length = struct.unpack(">I", self._read_exact(stream, 4))[0]
            if not 0 < length <= MAX_FRAME:
                raise TPMError(f"invalid response frame length: {length}")
            response = json.loads(self._read_exact(stream, length).decode("utf-8"))
        finally:
            stream.close()
        if response.get("status") != "ok":
            raise TPMError(response.get("message", "unknown service error"))
        return response

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    @staticmethod
    def _unb64(value: str | None) -> bytes:
        return base64.b64decode(value or "", validate=True)

    def ping(self) -> bool:
        return self.request("ping")["status"] == "ok"

    def container_id(self) -> tuple[str, str]:
        response = self.request("container_id")
        return response["key_id"], response.get("message", "").removeprefix("script_checksum=")

    def list_keys(self) -> list[str]:
        return self.request("list_keys").get("keys", [])

    def create_aes_key(self, key_id: str) -> None:
        self.request("create_AES_key", key_id=key_id)

    def create_chacha20_key(self, key_id: str) -> None:
        self.request("create_chacha20_key", key_id=key_id)

    def create_bytes(self, key_id: str, value: bytes | None = None, length: int = 32) -> None:
        fields: dict[str, Any] = {"key_id": key_id}
        if value is None:
            fields["length"] = length
        else:
            fields["secret"] = self._b64(value)
        self.request("create_bytes", **fields)

    def put_secret(self, key_id: str, value: bytes) -> None:
        self.request("put_secret", key_id=key_id, secret=self._b64(value))

    def get_bytes(self, key_id: str) -> bytes:
        return self._unb64(self.request("get_bytes", key_id=key_id).get("data"))

    def get_secret(self, key_id: str) -> bytes:
        return self.get_bytes(key_id)

    def delete(self, key_id: str) -> bool:
        return self.request("delete", key_id=key_id).get("message") == "deleted"

    def encrypt_gcm(self, key_id: str, plaintext: bytes, aad: bytes = b"") -> bytes:
        response = self.request("encryptGCM", key_id=key_id, data=self._b64(plaintext), aad=self._b64(aad))
        return self._unb64(response.get("data"))

    def decrypt_gcm(self, key_id: str, ciphertext: bytes, aad: bytes = b"") -> bytes:
        response = self.request("decryptGCM", key_id=key_id, data=self._b64(ciphertext), aad=self._b64(aad))
        return self._unb64(response.get("data"))

    def encrypt_chacha(self, key_id: str, plaintext: bytes, aad: bytes = b"") -> bytes:
        response = self.request("encrypt_chacha", key_id=key_id, data=self._b64(plaintext), aad=self._b64(aad))
        return self._unb64(response.get("data"))

    def decrypt_chacha(self, key_id: str, ciphertext: bytes, aad: bytes = b"") -> bytes:
        response = self.request("decrypt_chacha", key_id=key_id, data=self._b64(ciphertext), aad=self._b64(aad))
        return self._unb64(response.get("data"))


# Compatibility spelling for code that previously imported TPM_client.
Client = TPMClient
