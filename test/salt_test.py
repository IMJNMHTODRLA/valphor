import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import valphor

print("salt: " + valphor.salt().decode())
