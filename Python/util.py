BUFFER_SIZE=1048576
def to_hex(data):
    import binascii, pickle
    if isinstance(data, str):data = str_to_bytes(data)
    if not isinstance(data, (bytes, bytearray)):data = pickle.dumps(data)
    chunk_size = BUFFER_SIZE
    return ''.join([binascii.hexlify(data[i:i + chunk_size]).decode('utf-8') for i in range(0, len(data), chunk_size)])
def str_to_bytes(data):
    import numpy as np
    if isinstance(data,bytes):return data
    return bytes(np.frombuffer(data.encode('latin1'), dtype=np.uint8))
