import random
import string
import sys
import time

import bcrypt
from passlib.hash import pbkdf2_sha256, pbkdf2_sha512

SAMPLES = 10

def benchmark_bcrypt(rounds: int) -> float:
    """Benchmark bcrypt"""
    password = ''.join(random.choices(string.ascii_letters, k=64))
    start = time.time()
    bcrypt.hashpw(bytes(password, encoding='utf8'), bcrypt.gensalt(rounds=rounds))
    end = time.time() - start
    return end

def benchmark_pbkdf2_256(rounds: int) -> float:
    """Benchmark pbkdf2 with SHA 256 digest"""
    password = ''.join(random.choices(string.ascii_letters, k=64))
    start = time.time()
    pbkdf2_sha256.using(rounds=rounds, salt_size=16).hash(password)
    end = time.time() - start
    return end

def benchmark_pbkdf2_512(rounds: int) -> float:
    """Benchmark pbkdf2 with SHA 512 digest"""
    password = ''.join(random.choices(string.ascii_letters, k=64))
    start = time.time()
    pbkdf2_sha512.using(rounds=rounds, salt_size=16).hash(password)
    end = time.time() - start
    return end

def get_algorithm(algorithm: string) -> 'function':
    """Get the algorithm function"""
    if algorithm == 'bcrypt':
        return benchmark_bcrypt
    elif algorithm == 'pbkdf2_256':
        return benchmark_pbkdf2_256
    elif algorithm == 'pbkdf2_512':
        return benchmark_pbkdf2_512
    else:
        raise ValueError(f'Unknown algorithm: {algorithm}')

def calculate_average_time(samples: int, algorithm: 'function', rounds: int) -> float:
    """Calculate the average time for a given algorithm and rounds."""
    total_time = 0
    for _ in range(samples):
        total_time += algorithm(rounds)
    return (total_time / SAMPLES) * 1000 # Average and return in milliseconds

def main(algorithm: string, rounds_list) -> None:
    """Main driver function"""
    algo = get_algorithm(algorithm)
    times = {}
    for rounds in rounds_list:
        times[rounds] = calculate_average_time(SAMPLES, algo, rounds)
    print(times)

if __name__=='__main__':
    if len(sys.argv) < 3:
        print('Usage: python3 metrics.py <algorithm> <rounds> [<rounds>...]')
        sys.exit(1)
    rounds_to_test = [int(i) for i in sys.argv[2:]]
    main(sys.argv[1], rounds_to_test)
