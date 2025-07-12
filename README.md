# valphor
A hashing algorithm that is slower and more secure than bcrypt.

## Installation

```bash
#!/bin/bash
pip install valphor
```

## Usage

```py
import valphor

hashed = valphor.hash(b"password", valphor.salt())
is_valid = valphor.verify(hashed, b"password")
print(is_valid)
```

## Functions
- ### salt(length: int = 16, cost: int = 12) -> bytes  
    Generates a cryptographically secure salt of the specified length.  
    The `cost` parameter controls the computational complexity, increasing resistance against brute-force attacks.

---
- ### hash(verify_str: bytes, salt: bytes, length: int = 512) -> bytes  
    Generates a secure hash of the input `verify_str` using the Valphor algorithm with the provided `salt`.  
    The `length` parameter defines the length of the resulting hash in bits, enhancing flexibility for different security needs.

---
- ### verify(hashed: bytes, verify_str: bytes) -> bool  
    Checks whether the provided `verify_str` matches the given `hashed` value using the Valphor verification process.  
    Returns `True` if the verification succeeds, otherwise `False`.
