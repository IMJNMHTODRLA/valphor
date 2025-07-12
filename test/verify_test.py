import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import valphor

hashed = valphor.hash(b"password", valphor.salt())

if valphor.verify(hashed, b"password"):
    print("Correct password")
else:
    print("Incorrect password")