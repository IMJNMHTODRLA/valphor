import base64
import secrets
import hashlib

def salt(length: int = 16, cost: int = 12) -> bytes:
    length_byte: bytes = str(length).encode()

    salt: bytes = secrets.token_bytes(length)
    for i in range(cost):
        salt = hashlib.shake_256(length_byte + salt + secrets.token_bytes(int(length * length))).digest(length)

    return_str = f"$vp$v1$c{cost}${base64.b64encode(salt).rstrip(b'=').decode()}"

    return return_str.encode()
