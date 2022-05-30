import argparse
import math
import multiprocessing
import random
import string
import time

import bcrypt
from passlib.hash import pbkdf2_sha256, pbkdf2_sha512

# Number of samples to take to average the time
SAMPLES = 10

def benchmark_algorithm(callback: 'function', rounds: int) -> float:
    password = ''.join(random.choices(string.ascii_letters, k=64))
    start = time.time()
    callback(password, rounds)
    end = time.time() - start
    return end

def calculate_average_time(samples: int, algorithm: 'function', rounds: int) -> float:
    """Calculate the average time for a given algorithm and rounds."""
    total_time = 0
    for _ in range(samples):
        total_time += benchmark_algorithm(algorithm, rounds)
    return (total_time / SAMPLES) * 1000 # Average and return in milliseconds

def find_params_bcrypt(time_cost: float) -> dict:
    """Find the best params for bcrypt"""
    time_cost_ms = time_cost * 1000
    initial_guess = 10
    bcrypt_hash = lambda p, r: bcrypt.hashpw(bytes(p, encoding='utf8'), bcrypt.gensalt(rounds=r))
    avg_time = calculate_average_time(SAMPLES, bcrypt_hash, initial_guess)
    return {
        'rounds': round(math.log(time_cost_ms / avg_time, 2)) + initial_guess
    }

def find_params_pbkdf2_256(time_cost: float) -> dict:
    """Find the best params for bcrypt"""
    time_cost_ms = time_cost * 1000
    initial_guess = 10000
    pbkdf2_256_hash = lambda p, r: pbkdf2_sha256.using(rounds=r, salt_size=16).hash(p)
    avg_time = calculate_average_time(SAMPLES, pbkdf2_256_hash, initial_guess)
    return {
        'rounds': round(time_cost_ms / avg_time) * initial_guess
    }

def find_params_pbkdf2_512(time_cost: float) -> dict:
    """Find the best params for bcrypt"""
    time_cost_ms = time_cost * 1000
    initial_guess = 10000
    pbkdf2_512_hash = lambda p, r: pbkdf2_sha512.using(rounds=r, salt_size=16).hash(p)
    avg_time = calculate_average_time(SAMPLES, pbkdf2_512_hash, initial_guess)
    return {
        'rounds': round(time_cost_ms / avg_time) * initial_guess
    }

def find_params_argon2(time_cost: float) -> dict:
    """Find the best params for argon2"""
    # TODO: Implement this, using method: find amount of available compute available on server.
    return {
        'parallelism': multiprocessing.cpu_count() * 2,
        'memory_cost': 2**21,
        'time_cost': time_cost
    }

ALGORITHMS = {
    'bcrypt': find_params_bcrypt,
    'pbkdf2_256': find_params_pbkdf2_256,
    'pbkdf2_512': find_params_pbkdf2_512,
    'argon2': find_params_argon2
}

def find_best_params(algorithm: string, time_cost: 0.25) -> int:
    """Find the best possible params for the given algorithm given the time cost"""
    return ALGORITHMS[algorithm](time_cost)

if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Find the best parameters for a given algorithm', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('algorithm', help='Algorithm to benchmark', choices=ALGORITHMS.keys())
    parser.add_argument('--time_cost', help='Time cost in milliseconds', type=float, default=0.25)

    args = parser.parse_args()

    params = find_best_params(args.algorithm, args.time_cost)
    print(params)
