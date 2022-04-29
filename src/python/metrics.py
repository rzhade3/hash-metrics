import random
import string
import time

import bcrypt

def calculate_average_hashing_time(rounds):
  samples = 5
  total_time = 0
  for i in range(samples):
    password = ''.join(random.choices(string.ascii_letters, k=64))
    start = time.time()
    hashed = bcrypt.hashpw(bytes(password, encoding='utf8'), bcrypt.gensalt(rounds=rounds))
    end = time.time() - start
    total_time += end
  return total_time / samples

if __name__=='__main__':
  salt_rounds_to_eval = [8, 10, 12, 15, 20]
  for rounds in salt_rounds_to_eval:
    avg = calculate_average_hashing_time(rounds)
    print(f"Average hashing time for {rounds} rounds: {avg} seconds")
