import os, pickle, struct, ctypes, Encryption, traceback, time, win32file, win32pipe, pywintypes
try:import zstandard as zstd
except:zstd=None
from pathlib import Path
from typing import Dict, Any, Tuple
ZSTD_LEVEL=3
MAX_IPC_MESSAGE = 16 * 1024 * 1024
def pickle_dump(data):
    if zstd!=None:return zstd.compress(pickle.dumps(data), ZSTD_LEVEL)
    else:return pickle.dumps(data)
def pickle_load(data):
    try:data=zstd.decompress(data)
    except:pass
    return pickle.loads(data)
class TPMHardwareCrypto:
    MAGIC = b"TPMDP1"
    class DATA_BLOB(ctypes.Structure):_fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte)), ]
    def __init__(self, tpm_dir:Path):
        self.tpm_dir = Path(tpm_dir)
        self.tpm_dir.mkdir(parents=True, exist_ok=True)
        self.key_file = self.tpm_dir / "storage_key.bin"
        self.key:bytes | None = None
        self.crypt32 = ctypes.WinDLL("crypt32.dll")
        self.kernel32 = ctypes.WinDLL("kernel32.dll")
        self.crypt32.CryptProtectData.argtypes = [ctypes.POINTER(self.DATA_BLOB), ctypes.c_wchar_p, ctypes.POINTER(self.DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(self.DATA_BLOB), ]
        self.crypt32.CryptProtectData.restype = ctypes.c_int
        self.crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(self.DATA_BLOB), ctypes.POINTER(ctypes.c_wchar_p), ctypes.POINTER(self.DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(self.DATA_BLOB), ]
        self.crypt32.CryptUnprotectData.restype = ctypes.c_int
        self.kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self.kernel32.LocalFree.restype = ctypes.c_void_p
        self._load_or_create()
    def _protect(self, data:bytes) -> bytes:
        src_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        src = self.DATA_BLOB(len(data), src_buf)
        dst = self.DATA_BLOB()
        if not self.crypt32.CryptProtectData(ctypes.byref(src), "TPM storage key", None, None, None, 0, ctypes.byref(dst)):raise ctypes.WinError()
        try:return bytes(ctypes.string_at(dst.pbData, dst.cbData))
        finally:self.kernel32.LocalFree(dst.pbData)
    def _unprotect(self, data:bytes) -> bytes:
        src_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        src = self.DATA_BLOB(len(data), src_buf)
        dst = self.DATA_BLOB()
        desc = ctypes.c_wchar_p()
        if not self.crypt32.CryptUnprotectData(ctypes.byref(src), ctypes.byref(desc), None, None, None, 0, ctypes.byref(dst)):raise ctypes.WinError()
        try:return bytes(ctypes.string_at(dst.pbData, dst.cbData))
        finally:
            self.kernel32.LocalFree(dst.pbData)
            if desc:self.kernel32.LocalFree(desc)
    def _load_or_create(self):
        if self.key_file.exists():
            blob = self.key_file.read_bytes()
            if not blob.startswith(self.MAGIC):raise RuntimeError("Invalid storage key file")
            self.key = self._unprotect(blob[len(self.MAGIC):])
            if len(self.key) != 32:raise RuntimeError("Invalid storage key length")
            return
        self.key = os.urandom(32)
        protected = self._protect(self.key)
        tmp = self.key_file.with_suffix(".tmp")
        tmp.write_bytes(self.MAGIC + protected)
        os.replace(tmp, self.key_file)
        print("[TPM] Initialized new protected storage key")
    def encrypt(self, data:bytes) -> bytes:
        if self.key is None:raise RuntimeError("Storage key unavailable")
        return Encryption.encryptGCM(bytes(data), self.key)
    def decrypt(self, blob:bytes) -> bytes:
        if self.key is None:raise RuntimeError("Storage key unavailable")
        return Encryption.decryptGCM(bytes(blob), self.key)
    def close(self):self.key = None
    def __enter__(self):return self
    def __exit__(self, *_):self.close()
class TPMStorageGrid:
    def __init__(self, tpm_dir:Path, crypto_provider:TPMHardwareCrypto):
        self.tpm_dir = tpm_dir
        self.tpm_dir.mkdir(parents=True, exist_ok=True)
        self.crypto = crypto_provider
        self.main_file = self.tpm_dir / "TPM.bin"
    def get_filename(self, version_idx:int, backup_idx:int) -> Path:return self.tpm_dir / f"TPM version-{version_idx} backup-{backup_idx}.bin"
    def save(self, store_data:Dict[str, Any]):
        payload = pickle_dump(store_data)
        encrypted_blob = self.crypto.encrypt(payload)
        for v in range(10, 1, -1):
            for b in range(1, 6):
                src_file = self.get_filename(v - 1, b)
                dst_file = self.get_filename(v, b)
                if src_file.exists():dst_file.write_bytes(src_file.read_bytes())
        for b in range(1, 6):self.get_filename(1, b).write_bytes(encrypted_blob)
        self.main_file.write_bytes(encrypted_blob)
    def load(self) -> Tuple[Dict[str, Any], Path]:
        candidates = []
        if self.main_file.exists():candidates.append(self.main_file)
        for v in range(1, 11):
            for b in range(1, 6):candidates.append(self.get_filename(v, b))
        for path in candidates:
            if not path.exists():continue
            try:return pickle_load(self.crypto.decrypt(path.read_bytes())), path
            except Exception:continue
        raise RuntimeError("Failed to decrypt any store file in matrix.")
class TPMEngine:
    def __init__(self, storage:TPMStorageGrid):
        self.storage = storage
    def _get_store(self) -> Dict[str, Any]:
        try:
            data, _ = self.storage.load()
            return data
        except RuntimeError:return {"AES":{}, 'chacha20':{}, 'ed25519':{}, "bytes":{}, "data":{}}
    def process_request(self, req:Dict[str, Any]) -> Dict[str, Any]:
        action = req.get("action")
        store = self._get_store()
        store.setdefault("AES", {})
        store.setdefault("chacha20", {})
        store.setdefault("ed25519", {})
        store.setdefault("bytes", {})
        store.setdefault("data", {})
        try:
            if action == "create_AES_key":
                key_id = req["id"]
                if 'data' in req:raw_key=req['data']
                else:raw_key = os.urandom(64)
                store["AES"][key_id] = raw_key
                self.storage.save(store)
                return {"status":"ok", "id":key_id, "length":len(raw_key)}
            elif action == "delete_AES_key":
                key_id = req["id"]
                if key_id in store["AES"]:
                    del store["AES"][key_id]
                    self.storage.save(store)
                    return {"status":"ok", "deleted":key_id}
                return {"status":"error", "message":f"Key ID '{key_id}' not found."}
            elif action == "create_chacha20_key":
                key_id = req["id"]
                password = req.get("password")
                if 'data' in req:key=req['data']
                else:key = Encryption.gen_chacha20(password)
                store["chacha20"][key_id] = key
                self.storage.save(store)
                return {"status":"ok", "id":key_id}
            elif action == "delete_chacha20_key":
                key_id = req["id"]
                if key_id in store["chacha20"]:
                    del store["chacha20"][key_id]
                    self.storage.save(store)
                    return {"status":"ok", "deleted":key_id}
                return {"status":"error", "message":f"Key ID '{key_id}' not found."}
            elif action == "create_bytes":
                bytes_id = req["id"]
                data_bytes = req.get("data") if isinstance(req.get("data"), bytes) else os.urandom(req.get("length", 64))
                store["bytes"][bytes_id] = data_bytes
                self.storage.save(store)
                return {"status":"ok", "id":bytes_id, "length":len(data_bytes)}
            elif action == "delete_bytes":
                bytes_id = req["id"]
                if bytes_id in store["bytes"]:
                    del store["bytes"][bytes_id]
                    self.storage.save(store)
                    return {"status":"ok", "deleted":bytes_id}
                return {"status":"error", "message":f"Bytes ID '{bytes_id}' not found."}
            elif action in ("get_bytes", "get"):
                target = req.get("id") or req.get("key")
                if target in store["bytes"]:return {"status":"ok", "type":"bytes", "value":store["bytes"][target]}
                elif target in store["data"]:return {"status":"ok", "type":"data", "value":store["data"][target]}
                return {"status":"error", "message":f"Item '{target}' not found."}
            elif action == "encrypt":
                secure_kdf = req.get("secure_kdf", False)
                key_bytes = self._resolve_key(req, store, 'AES')
                plaintext = req["data"]
                ct = Encryption.encrypt(plaintext, key_bytes, secure_kdf=secure_kdf)
                return {"status":"ok", "ciphertext":ct}
            elif action == "decrypt":
                secure_kdf = req.get("secure_kdf", False)
                key_bytes = self._resolve_key(req, store, 'AES')
                ciphertext = req["ciphertext"]
                pt = Encryption.decrypt(ciphertext, key_bytes, secure_kdf=secure_kdf)
                return {"status":"ok", "plaintext":pt}
            elif action == "encryptGCM":
                secure_kdf = req.get("secure_kdf", False)
                key_bytes = self._resolve_key(req, store, 'AES')
                plaintext = req["data"]
                ct = Encryption.encryptGCM(plaintext, key_bytes, secure_kdf=secure_kdf)
                return {"status":"ok", "ciphertext":ct}
            elif action == "decryptGCM":
                secure_kdf = req.get("secure_kdf", False)
                key_bytes = self._resolve_key(req, store, 'AES')
                ciphertext = req["ciphertext"]
                pt = Encryption.decryptGCM(ciphertext, key_bytes, secure_kdf=secure_kdf)
                return {"status":"ok", "plaintext":pt}
            elif action == "encrypt_chacha":
                key_bytes = self._resolve_key(req, store, 'chacha20')
                plaintext = req["data"]
                ct = Encryption.encrypt_chacha(plaintext, key_bytes, auth=req.get("auth", True))
                return {"status":"ok", "ciphertext":ct}
            elif action == "decrypt_chacha":
                key_bytes = self._resolve_key(req, store, 'chacha20')
                ciphertext = req["ciphertext"]
                pt = Encryption.decrypt_chacha(ciphertext, key_bytes, auth=req.get("auth", True))
                return {"status":"ok", "plaintext":pt}
            elif action == "gen_ed25519":
                key_id = req["id"]
                prv, pub = req.get("private", req.get("prv")), req.get("public", req.get("pub"))
                if prv is None and pub is None:prv, pub = Encryption.gen_ed25519(overkill=req.get("overkill", False))
                key = {}
                if prv is not None:key["private"] = prv
                if pub is not None:key["public"] = pub
                store["ed25519"][key_id] = key
                self.storage.save(store)
                return {"status":"ok", "id":key_id}
            elif action == "delete_ed25519":
                key_id = req["id"]
                key = store["ed25519"].get(key_id)
                if isinstance(key, dict) and "private" in key and "public" in key:
                    del store["ed25519"][key_id]
                    self.storage.save(store)
                    return {"status":"ok", "deleted":key_id}
                return {"status":"error", "message":f"Ed25519 key ID '{key_id}' not found."}
            elif action == "ed25519_sign":
                prv = self._resolve_key(req, store, 'ed25519', key_type="private")
                data = req["data"]
                sig = Encryption.ed25519_sign(prv, data)
                return {"status":"ok", "signature":sig}
            elif action == "ed25519_verify":
                pub = self._resolve_key(req, store, 'ed25519', key_type="public")
                data = req["data"]
                verified_data = Encryption.ed25519_verify(pub, data)
                return {"status":"ok", "data":verified_data}
            return {"status":"error", "message":f"Unknown action '{action}'"}
        except Exception as err:
            traceback.print_exception(err)
            return {"status":"error", "message":str(err)}
    def _resolve_key(self, req:Dict[str, Any], store:Dict[str, Any], algorithm, key_type:str = "symmetric") -> Any:
        kid = req.get("key_id") or req.get("id")
        if kid:
            if kid not in store[algorithm]:raise ValueError(f"Key ID '{kid}' does not exist in TPM store.")
            val = store[algorithm][kid]
            if isinstance(val, dict):
                if key_type == "private":return val.get("private", val)
                elif key_type == "public":return val.get("public", val)
            return val
        elif "key" in req and isinstance(req["key"], bytes):return req["key"]
        elif "prv" in req and isinstance(req["prv"], bytes):return req["prv"]
        elif "pub" in req and isinstance(req["pub"], bytes):return req["pub"]
        raise ValueError("Must specify 'key_id', 'id', or raw key bytes.")
class TPMIPCServer:
    def __init__(self, engine:TPMEngine, pipe_name=r"\\.\pipe\tpm"):
        self.engine, self.pipe_name = engine, pipe_name
        self._stop = False
    def _create_pipe(self):return win32pipe.CreateNamedPipe(self.pipe_name, win32pipe.PIPE_ACCESS_DUPLEX,win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_NOWAIT,1, 65536, 65536, 0, None)
    def stop(self):self._stop = True
    def _read(self, pipe, n):
        data = bytearray()
        while len(data) < n and not self._stop:
            try:
                _, part = win32file.ReadFile(pipe, n - len(data))
                if not part:return None
                data.extend(part)
            except pywintypes.error as e:
                if e.winerror == 232:time.sleep(0.01); continue
                if e.winerror in (109, 233):return None
                raise
        return bytes(data) if len(data) == n else None
    def _write(self, pipe, data):
        offset = 0
        while offset < len(data) and not self._stop:
            try:
                _, n = win32file.WriteFile(pipe, data[offset:])
                offset += n
            except pywintypes.error as e:
                if e.winerror == 232:time.sleep(0.01); continue
                raise
        if self._stop:raise KeyboardInterrupt
    def _recv(self, pipe):
        head = self._read(pipe, 4)
        if head is None:return None
        n = struct.unpack(">I", head)[0]
        if not 0 < n <= MAX_IPC_MESSAGE:raise ValueError(f"Invalid IPC message size:{n}")
        return self._read(pipe, n)
    def start(self):
        print(f"[IPC] Listening on {self.pipe_name}; Ctrl+C to stop.", flush=True)
        try:
            while not self._stop:
                pipe = None
                try:
                    pipe = self._create_pipe()
                    while not self._stop:
                        try:
                            win32pipe.ConnectNamedPipe(pipe, None)
                            break
                        except pywintypes.error as e:
                            if e.winerror == 535:break
                            if e.winerror == 536:time.sleep(0.02); continue
                            raise
                    if self._stop:break
                    raw = self._recv(pipe)
                    if raw is None:continue
                    payload = pickle_dump(self.engine.process_request(pickle_load(raw)))
                    self._write(pipe, struct.pack(">I", len(payload)) + payload)
                    win32file.FlushFileBuffers(pipe)
                except KeyboardInterrupt:
                    self.stop()
                    break
                except Exception:
                    traceback.print_exc()
                    time.sleep(0.1)
                finally:
                    if pipe is not None:
                        try:win32pipe.DisconnectNamedPipe(pipe)
                        except pywintypes.error:traceback.print_exc()
                        try:win32file.CloseHandle(pipe)
                        except Exception:traceback.print_exc()
        finally:print("[IPC] Stopped.", flush=True)
def main():
    tpm_dir = Path.home() / "TPM"
    crypto = TPMHardwareCrypto(tpm_dir)
    try:TPMIPCServer(TPMEngine(TPMStorageGrid(tpm_dir, crypto))).start()
    finally:crypto.close()
if __name__ == "__main__":main()