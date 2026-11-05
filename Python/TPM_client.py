import os, socket, struct, pickle, tempfile, time
if os.name == "nt":import win32file, pywintypes
from pathlib import Path
from typing import Any, Optional
try:import zstandard as zstd
except:zstd=None
ZSTD_LEVEL=3
def pickle_dump(data):
    if zstd!=None:return zstd.compress(pickle.dumps(data),ZSTD_LEVEL)
    else:return pickle.dumps(data)
def pickle_load(data):
    try:data=zstd.decompress(data)
    except:pass
    return pickle.loads(data)
MAX_IPC_MESSAGE = 16 * 1024 * 1024
PIPE_NAME = r"\\.\pipe\tpm"
def send_framed_msg(conn, msg:bytes) -> None:
    if len(msg) > MAX_IPC_MESSAGE:raise ValueError("IPC message too large")
    packet = struct.pack(">I", len(msg)) + msg
    if os.name == "nt":
        offset = 0
        while offset < len(packet):
            _, written = win32file.WriteFile(conn, packet[offset:])
            offset += written
    else:conn.sendall(packet)
def recv_exact(conn, n:int) -> Optional[bytes]:
    data = bytearray()
    while len(data) < n:
        if os.name == "nt":
            try:_, part = win32file.ReadFile(conn, n - len(data))
            except pywintypes.error as e:
                if e.winerror == 109:return None
                raise
        else:part = conn.recv(n - len(data))
        if not part:return None
        data.extend(part)
    return bytes(data)
def recv_framed_msg(conn) -> Optional[bytes]:
    raw = recv_exact(conn, 4)
    if raw is None:return None
    n = struct.unpack(">I", raw)[0]
    if n > MAX_IPC_MESSAGE:raise ValueError("IPC message too large")
    return recv_exact(conn, n)
def close_connection(conn) -> None:
    if os.name == "nt":win32file.CloseHandle(conn)
    else:conn.close()
class TPMClient:
    def __init__(self,sock_path:Optional[Path] = None,pipe_name:str = PIPE_NAME):
        self.sock_path = Path(sock_path or Path(tempfile.gettempdir()) / "tpm.sock")
        self.pipe_name = pipe_name
    def _connect(self):
        if os.name == "nt":
            start=time.monotonic()
            while True:
                try:return win32file.CreateFile(self.pipe_name, win32file.GENERIC_READ | win32file.GENERIC_WRITE,0, None, win32file.OPEN_EXISTING, 0, None)
                except pywintypes.error as e:
                    if e.winerror not in (2, 231):raise
                    time.sleep(0.05)
                if time.monotonic()-start>5:raise ConnectionError("Couldn't connect to TPM.exe")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(str(self.sock_path))
        return s
    def send_request(self, req:dict[str, Any]) -> dict[str, Any]:
        conn = self._connect()
        try:
            send_framed_msg(conn,pickle_dump(req))
            raw = recv_framed_msg(conn)
            if raw is None:raise RuntimeError("No response received")
            resp = pickle_load(raw)
            if not isinstance(resp, dict):raise RuntimeError("Invalid server response")
            return resp
        finally:close_connection(conn)
    def create_AES_key(self, key_id:str, key:Optional[bytes] = None) -> dict[str, Any]:
        req = {"action":"create_AES_key", "id":key_id}
        if key is not None:req["data"] = key
        return self.send_request(req)
    def create_chacha20_key(self, key_id:str, password:Optional[bytes] = None, key:Optional[bytes] = None) -> dict[str, Any]:
        if key is not None and password is not None:raise ValueError("Specify key or password, not both.")
        req = {"action":"create_chacha20_key", "id":key_id}
        if key is not None:req["data"] = key
        elif password is not None:req["password"] = password
        return self.send_request(req)
    def delete_AES_key(self,key_id:str) -> dict[str, Any]:return self.send_request({"action":"delete_AES_key","id":key_id,})
    def delete_chacha20_key(self,key_id:str) -> dict[str, Any]:return self.send_request({"action":"delete_chacha20_key","id":key_id,})
    def create_bytes(self,bytes_id:str,data:Optional[bytes] = None,length:int = 64) -> dict[str, Any]:
        req = {"action":"create_bytes","id":bytes_id,"length":length,}
        if data is not None:req["data"] = data
        return self.send_request(req)
    def delete_bytes(self,bytes_id:str) -> dict[str, Any]:return self.send_request({"action":"delete_bytes","id":bytes_id,})
    def get_bytes(self,bytes_id:str) -> dict[str, Any]:return self.send_request({"action":"get_bytes","id":bytes_id,})
    def encrypt(self,data:bytes,key_id:Optional[str] = None,key:Optional[bytes] = None,secure_kdf:bool = False) -> dict[str, Any]:return self._crypto("encrypt",data,key_id,key,secure_kdf)
    def decrypt(self,ciphertext:bytes,key_id:Optional[str] = None,key:Optional[bytes] = None,secure_kdf:bool = False) -> dict[str, Any]:
        req = {"action":"decrypt","ciphertext":ciphertext,"secure_kdf":secure_kdf,}
        self._key(req, key_id, key)
        return self.send_request(req)
    def encryptGCM(self,data:bytes,key_id:Optional[str] = None,key:Optional[bytes] = None,secure_kdf:bool = False) -> dict[str, Any]:return self._crypto("encryptGCM",data,key_id,key,secure_kdf)
    def decryptGCM(self,ciphertext:bytes,key_id:Optional[str] = None,key:Optional[bytes] = None,secure_kdf:bool = False) -> dict[str, Any]:
        req = {"action":"decryptGCM","ciphertext":ciphertext,"secure_kdf":secure_kdf,}
        self._key(req, key_id, key)
        return self.send_request(req)
    def encrypt_chacha(self,data:bytes,key_id:Optional[str] = None,key:Optional[bytes] = None,auth:bool = True,secure_kdf:bool = False,password:Optional[bytes] = None) -> dict[str, Any]:
        req = {"action":"encrypt_chacha","data":data,"auth":auth,"secure_kdf":secure_kdf,}
        self._key(req, key_id, key)
        if password is not None:req["password"] = password
        return self.send_request(req)
    def decrypt_chacha(self,ciphertext:bytes,key_id:Optional[str] = None,key:Optional[bytes] = None,auth:bool = True,secure_kdf:bool = False,password:Optional[bytes] = None) -> dict[str, Any]:
        req = {"action":"decrypt_chacha","ciphertext":ciphertext,"auth":auth,"secure_kdf":secure_kdf,}
        self._key(req, key_id, key)
        if password is not None:req["password"] = password
        return self.send_request(req)
    def gen_ed25519(self, key_id:str, overkill:bool = False, private:Optional[bytes] = None, public:Optional[bytes] = None) -> dict[str, Any]:
        req = {"action":"gen_ed25519", "id":key_id, "overkill":overkill}
        if private is not None:req["private"] = private
        if public is not None:req["public"] = public
        return self.send_request(req)
    def delete_ed25519(self, key_id:str) -> dict[str, Any]:return self.send_request({"action":"delete_ed25519", "id":key_id})
    def ed25519_sign(self,data:bytes,key_id:Optional[str] = None,prv:Optional[bytes] = None) -> dict[str, Any]:
        req = {"action":"ed25519_sign","data":data,}
        self._key(req,key_id,prv,"prv")
        return self.send_request(req)
    def ed25519_verify(self,data:bytes,key_id:Optional[str] = None,pub:Optional[bytes] = None) -> dict[str, Any]:
        req = {"action":"ed25519_verify","data":data,}
        self._key(req,key_id,pub,"pub")
        return self.send_request(req)
    def _key(self,req:dict[str, Any],key_id:Optional[str],raw:Optional[bytes],name:str = "key") -> None:
        if key_id is not None:req["key_id"] = key_id
        elif raw is not None:req[name] = raw
    def _crypto(self,action:str,data:bytes,key_id:Optional[str],key:Optional[bytes],secure_kdf:bool) -> dict[str, Any]:
        req = {"action":action,"data":data,"secure_kdf":secure_kdf,}
        self._key(req, key_id, key)
        return self.send_request(req)
if __name__ == "__main__":
    c = TPMClient()
    try:
        print("--- 1. Creating AES Key ---")
        r = c.create_AES_key("app_aes_key")
        print(r)
        if r.get("status") == "ok":
            print("\n--- 2. AES-GCM ---")
            x = c.encryptGCM(b"Confidential TPM Payload", key_id="app_aes_key")
            print("Encrypt:", x)
            if x.get("status") == "ok":print("Decrypt:", c.decryptGCM(x["ciphertext"], key_id="app_aes_key"))
        print("\n--- 3. Bytes ---")
        r = c.create_bytes("session_token", data=b"XYZ-TOKEN-998877")
        print("Store:", r)
        if r.get("status") == "ok":print("Retrieve:", c.get_bytes("session_token"))
        print("Key export:", c.get_bytes("app_aes_key"))
        print("\n--- 4. ChaCha20 ---")
        r = c.create_chacha20_key("chacha_key")
        print("Generate:", r)
        if r.get("status") == "ok":
            x = c.encrypt_chacha(b"ChaCha test", key_id="chacha_key")
            print("Encrypt:", x)
            if x.get("status") == "ok":print("Decrypt:", c.decrypt_chacha(x["ciphertext"], key_id="chacha_key"))
        print("\n--- 5. Ed25519 ---")
        r = c.gen_ed25519("auth_key")
        print("Generate:", r)
        if r.get("status") == "ok":
            s = c.ed25519_sign(b"Document to sign", key_id="auth_key")
            print("Sign:", s)
            if s.get("status") == "ok":print("Verify:", c.ed25519_verify(s["signature"], key_id="auth_key"))
    finally:
        print("\n--- Cleanup ---")
        c.delete_AES_key('app_aes_key')
        c.delete_bytes('session_token')
        c.delete_chacha20_key('chacha_key')
        c.delete_ed25519('auth_key')
