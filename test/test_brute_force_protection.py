import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import itertools
import string
import time
import valphor

password = b"bb"
hashed = valphor.hash(password, valphor.salt())

charset = string.ascii_lowercase #abcdefghijklmnopqrstuvwxyz

# 최대 길이 설정
max_length = 8

start_time = time.time()
found = False
attempts = 0

for length in range(1, max_length + 1):
    for guess_tuple in itertools.product(charset, repeat=length):
        guess = ''.join(guess_tuple).encode()
        attempts += 1
        print(guess.decode())
        if valphor.verify(hashed, guess):
            print(f"Password found: {guess.decode()} (attempts {attempts})")
            found = True
            break
    if found:
        break

print(f"Elapsed time: {time.time() - start_time:.2f} seconds")
