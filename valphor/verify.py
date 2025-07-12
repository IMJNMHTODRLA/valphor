import base64
import hashlib
import secrets

def verify(hashed: bytes, verify_str: bytes) -> bool:
    sub_parts = hashed.decode().split('$') #$v1$l16$c12$dsfheuhsoteshothso

    prefix: bytes = sub_parts[1].encode() #vp
    version: bytes = sub_parts[2].encode() #v1

    cost_byte: bytes = sub_parts[3].encode() #c12 -> 12
    cost: int = int(sub_parts[3][1:])

    length_bytes: bytes = sub_parts[4].encode()
    length: int = int(sub_parts[4][1:])

    only_salt: bytes = base64.b64decode((sub_parts[5] + '=' * (-len(sub_parts[5]) % 4)).encode()) #dsfheuhsoteshothso

    mem_size: int = int(4 ** cost * 2)
    if mem_size < 1024:
        mem_size = 1024
    memory: bytearray = bytearray(mem_size)

    hasingsalt: bytes = only_salt + verify_str + only_salt
    for i in range(int(2 ** cost)):
        for ii in range(int(2 ** cost // 128)):
            FUckint = hashlib.sha3_384(b"mem_chunk" + hashlib.sha3_512(b"mem_chunk" + b"mem_chunk").digest() + b"mem_chunk").digest()
        memory[secrets.randbelow(len(memory))] = i % 256

        start = secrets.randbelow(len(memory) - 16)
        mem_chunk = bytes(memory[start:start + 16])

        FUckint = hashlib.sha3_384(mem_chunk + hashlib.sha3_512(mem_chunk + mem_chunk).digest() + mem_chunk).digest()

        part: bytes = hashlib.sha3_224(verify_str + only_salt).digest()
        part1: bytes = hashlib.sha3_512(hasingsalt).digest() + hashlib.sha3_256(hasingsalt + only_salt + hashlib.sha3_256(hasingsalt).digest() + hasingsalt + verify_str + only_salt + verify_str + only_salt).digest()
        part2: bytes = hashlib.sha3_256(hasingsalt + only_salt).digest()
        sub_part: bytes = hashlib.sha3_256(hasingsalt + verify_str).digest()
        sub_part2: bytes = hashlib.sha3_512(
            hashlib.sha3_512(
                verify_str + hasingsalt + only_salt + hasingsalt
            ).digest() + 
            hashlib.sha3_256(
                hashlib.sha3_384(hashlib.md5(hasingsalt + only_salt).digest() + hashlib.sha3_256(hasingsalt).digest()).digest() +
                hashlib.sha3_256(hasingsalt + verify_str).digest() + only_salt + verify_str + only_salt
            ).digest()
        ).digest()

        hasingsalt = hashlib.sha3_512(verify_str + hashlib.sha3_384(sub_part2 + hashlib.sha384(sub_part2 + part).digest() + hashlib.sha384(part1 + sub_part2 + sub_part2).digest()).digest() + hashlib.sha384(hashlib.sha384(sub_part + part).digest() + part2 + sub_part).digest() + sub_part2).digest()
        hasingsalt = hashlib.shake_256(hasingsalt + hashlib.sha3_512(hasingsalt).digest() + hashlib.sha3_384(sub_part2 + hashlib.sha384(sub_part2 + part).digest() + hashlib.sha384(part1 + sub_part2 + sub_part2).digest()).digest() + hasingsalt + hashlib.sha384(hashlib.sha384(sub_part + part).digest() + part2 + sub_part).digest() + sub_part2).digest(length // 8)

        memory[i % len(memory)] = (memory[i % len(memory)] + memory[(i - 1) % len(memory)] + i) % 256

    hasingsalt = base64.b64encode(hasingsalt).rstrip(b'=')
    verify_hashing: bytes = b"$" + prefix + b"$" + version + b"$" + cost_byte + b"$" + length_bytes + b"$" + base64.b64encode(only_salt).rstrip(b'=') + b"$" + hasingsalt

    return verify_hashing == hashed
