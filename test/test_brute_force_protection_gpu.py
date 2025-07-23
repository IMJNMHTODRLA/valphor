import pycuda.autoinit
import pycuda.driver as cuda
from pycuda.compiler import SourceModule
import numpy as np
import string
import time
import valphor
from concurrent.futures import ThreadPoolExecutor

charset = string.ascii_lowercase
charset_size = len(charset)

kernel_code = """
__device__ char charset[26] = {'a','b','c','d','e','f','g','h','i','j','k','l','m',
                              'n','o','p','q','r','s','t','u','v','w','x','y','z'};

__global__ void generate_candidates(int length, unsigned long long start_index,
                                    unsigned long long total_candidates,
                                    char *out_buffer) {
    unsigned long long idx = threadIdx.x + blockIdx.x * blockDim.x;
    unsigned long long candidate_idx = start_index + idx;
    
    if (candidate_idx >= total_candidates) return;

    for (int i = 0; i < length; i++) {
        unsigned long long div = 1;
        for (int j = 0; j < i; j++) {
            div *= 26;
        }
        int char_index = (candidate_idx / div) % 26;
        out_buffer[idx * length + i] = charset[char_index];
    }
}
"""

mod = SourceModule(kernel_code)
generate_candidates = mod.get_function("generate_candidates")

def verify_candidate(password_hash, candidate):
    try:
        if valphor.verify(password_hash, candidate):
            return candidate.decode()
    except Exception:
        pass
    return None

def gpu_bruteforce_valphor(password_hash, max_length=4):
    block_size = 256

    for length in range(1, max_length + 1):
        total_candidates = charset_size ** length
        grid_size = (total_candidates + block_size - 1) // block_size

        out_buffer = cuda.mem_alloc(block_size * length)
        host_buffer = np.empty(block_size * length, dtype=np.uint8)

        start_idx = 0
        found_password = None

        with ThreadPoolExecutor(max_workers=8) as executor:
            while start_idx < total_candidates and found_password is None:
                current_chunk = min(block_size, total_candidates - start_idx)

                generate_candidates(np.int32(length),
                                    np.uint64(start_idx),
                                    np.uint64(total_candidates),
                                    out_buffer,
                                    block=(block_size,1,1), grid=(grid_size,1))

                cuda.memcpy_dtoh(host_buffer, out_buffer)

                # CPU 멀티스레드로 검증 병렬 처리
                futures = []
                for i in range(current_chunk):
                    candidate_bytes = bytes(host_buffer[i*length:(i+1)*length])
                    futures.append(executor.submit(verify_candidate, password_hash, candidate_bytes))

                for future in futures:
                    result = future.result()
                    if result:
                        found_password = result
                        break

                start_idx += current_chunk

        if found_password:
            print(f"Password found: {found_password}")
            return found_password

    print("Password not found")
    return None


if __name__ == "__main__":
    password = b"bb"
    hashed = valphor.hash(password, valphor.salt())
    start_time = time.time()
    gpu_bruteforce_valphor(hashed, max_length=4)
    print(f"Elapsed: {time.time() - start_time:.2f} seconds")
