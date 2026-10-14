from hashlib import sha256
from itertools import permutations
from string import ascii_letters, digits, punctuation

charset = ascii_letters + digits + punctuation

def generate_hash_file(prefix_zero_count: int):
    """
    生成一个符合题目要求哈希的文本文件
    
    prefix_zero_count:  哈希值前缀零的数量
    """
    found = False
    for length in range(1, len(charset) + 1):
        for permutation in permutations(charset, length):
            candidate = ''.join(permutation)
            hash = sha256(candidate.encode()).hexdigest()
            if hash.startswith('0' * prefix_zero_count):
                with open(f'作业7代码/hash_{prefix_zero_count}.txt', 'w') as f:
                    f.write(candidate)
                    print(f"[*] Found candidate: {candidate} with hash 0x{hash}!")
                    found = True
                    break
        if found:
            break
        
if __name__ == "__main__":
    print("学号: 3124004333")
    zero_counts = [1, 2, 3]
    for count in zero_counts:
        print(f"[*] Generating hash file with {count} leading zeros...")
        generate_hash_file(count)
    print("[+] Done.")
