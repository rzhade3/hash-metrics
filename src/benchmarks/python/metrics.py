import random
import string
import time

import bcrypt

def calculate_average_hashing_time(rounds):
    samples = 10
    total_time = 0
    for _ in range(samples):
        password = ''.join(random.choices(string.ascii_letters, k=64))
        start = time.time()
        _ = bcrypt.hashpw(bytes(password, encoding='utf8'), bcrypt.gensalt(rounds=rounds))
        end = time.time() - start
        total_time += end
    return (total_time / samples) * 1000 # Average and return in milliseconds

if __name__=='__main__':
    salt_rounds_to_eval = [8, 10, 12, 15]
    for rounds in salt_rounds_to_eval:
        avg = calculate_average_hashing_time(rounds)
        print(f"{rounds},{avg} ms")
