import time
from hashlib import sha256
from itertools import permutations
from string import ascii_letters, digits, punctuation

charset = ascii_letters + digits + punctuation

if __name__ == "__main__":
    start_time = time.time()
    timer = 300
    maximum_zero_prefix = 0
    maximum_zero_prefix_candidate = ""
    maximum_zero_prefix_hash = ""
    time_limit_reached = False
    for length in range(1, len(charset) + 1):
        for permutation in permutations(charset, length):
            now = time.time()
            if now - start_time > timer:
                print(f"[*] Time limit of {timer} seconds reached. Stopping search.")
                time_limit_reached = True
                break
            candidate = "".join(permutation)
            hash = sha256(candidate.encode()).hexdigest()
            zero_prefix_count = len(hash) - len(hash.lstrip("0"))
            if zero_prefix_count > maximum_zero_prefix:
                maximum_zero_prefix = zero_prefix_count
                maximum_zero_prefix_candidate = candidate
                maximum_zero_prefix_hash = hash
                print(
                    f"[*] New maximum leading zeros found: {maximum_zero_prefix} with candidate: {candidate} and hash: 0x{hash}"
                )

        if time_limit_reached:
            break

    print(
        f"[*] Maximum leading zeros found: {maximum_zero_prefix} with candidate: {maximum_zero_prefix_candidate} and hash: 0x{maximum_zero_prefix_hash}"
    )
