import multiprocessing as mp
import itertools
import string
import time

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import valphor

def worker(args):
    hashed, guesses = args
    for guess in guesses:
        if valphor.verify(hashed, guess):
            return guess  # 찾으면 문자열 반환
    return None

def chunked_iterable(iterable, size):
    """이터러블을 size 단위 청크로 나눔"""
    it = iter(iterable)
    while True:
        chunk = list(itertools.islice(it, size))
        if not chunk:
            return
        yield chunk

def main():
    password = b"bbbb"
    hashed = valphor.hash(password, valphor.salt(cost=12))

    charset = string.ascii_lowercase
    max_length = 4

    processes = 6  # 필요하면 숫자 직접 조절 가능
    chunk_size = 250  # 청크 크기 조절

    start_time = time.time()

    pool = mp.Pool(processes=processes)
    found = None
    attempts = 0

    try:
        for length in range(1, max_length + 1):
            guesses_gen = (''.join(chars).encode() for chars in itertools.product(charset, repeat=length))
            # 청크 단위로 묶기
            for guess_chunks in chunked_iterable(guesses_gen, chunk_size):
                # pool.map은 리스트를 넣어야 하므로 리스트로 감싸고, 각각의 청크마다 병렬 작업 요청
                args_list = [(hashed, [guess]) for guess in guess_chunks]

                results = pool.map(worker, args_list)
                attempts += len(guess_chunks)

                # 결과 중 비밀번호 찾았는지 검사
                for res in results:
                    if res is not None:
                        found = res
                        break
                if found:
                    break
            if found:
                break
    finally:
        pool.close()
        pool.join()

    if found:
        print(f"Password found: {found.decode()} (attempts {attempts})")
    else:
        print("Password not found.")

    print(f"Elapsed time: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()