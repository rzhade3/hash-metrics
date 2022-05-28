import argparse
import math
import random
import string
import sys
import time

import bcrypt
from passlib.hash import pbkdf2_sha256, pbkdf2_sha512

# Number of samples to take to average the time
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

ALGORITHMS = {
    'bcrypt': {
        'fn': benchmark_bcrypt,
        'scaling': 'exponential',
        'default_rounds': 12
    },
    'pbkdf2_256': {
        'fn': benchmark_pbkdf2_256,
        'scaling': 'linear',
        'default_rounds': 10000
    },
    'pbkdf2_512': { 
        'fn': benchmark_pbkdf2_512,
        'scaling': 'linear',
        'default_rounds': 10000
    }
}

def get_algorithm(algorithm: string) -> 'function':
    """Get the algorithm function"""
    if algorithm not in ALGORITHMS:
        raise ValueError(f'Unknown algorithm: {algorithm}')
    return ALGORITHMS[algorithm]

def calculate_average_time(samples: int, algorithm: 'function', rounds: int) -> float:
    """Calculate the average time for a given algorithm and rounds."""
    total_time = 0
    for _ in range(samples):
        total_time += algorithm(rounds)
    return (total_time / SAMPLES) * 1000 # Average and return in milliseconds

def run_benchmarks(algorithm: string, rounds_list) -> None:
    """Run the benchmarks"""
    algo = get_algorithm(algorithm)['fn']
    times = {}
    for rounds in rounds_list:
        times[rounds] = calculate_average_time(SAMPLES, algo, rounds)
    return times

def find_best_params(algorithm: string, time_cost: 0.25) -> int:
    """Find the best params for the given algorithm given the time cost"""
    time_cost_ms = time_cost * 1000
    algo = get_algorithm(algorithm)
    avg_time = calculate_average_time(SAMPLES, algo['fn'], algo['default_rounds'])
    if algo['scaling'] == 'exponential':
        # Exponential scaling means we add the logarithmic increase
        return round(math.log(time_cost_ms / avg_time, 2)) + algo['default_rounds']
    elif algo['scaling'] == 'linear':
        return round(time_cost_ms / avg_time) * algo['default_rounds']
    return

if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Benchmark password hashing algorithms')
    subparsers = parser.add_subparsers(help='Mode of operation', dest='mode')

    benchmark_parser = subparsers.add_parser('benchmark', help='Run benchmarks for a given algorithm and parameters')
    benchmark_parser.add_argument('algorithm', help='Algorithm to benchmark', choices=ALGORITHMS.keys())
    benchmark_parser.add_argument('rounds', help='Number of rounds to use', type=int, default=None, nargs='+')

    find_best_parser = subparsers.add_parser('find_best_params', help='Find the best parameters for a given algorithm', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    find_best_parser.add_argument('algorithm', help='Algorithm to benchmark', choices=ALGORITHMS.keys())
    find_best_parser.add_argument('--time_cost', help='Time cost in milliseconds', type=float, default=0.25)

    args = parser.parse_args()

    if args.mode == 'benchmark':
        if args.rounds is None:
            parser.print_help()
            sys.exit(1)
        times = run_benchmarks(args.algorithm, args.rounds)
        print(times)
    elif args.mode == 'find_best_params':
        params = find_best_params(args.algorithm, args.time_cost)
        print(params)
    else:
        parser.print_help()
        sys.exit(1)
