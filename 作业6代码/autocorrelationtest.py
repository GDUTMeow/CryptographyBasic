import random

def autocorrelation(array: list[int]) -> list[float]:
    N = len(array)
    result: list[float] = []
    for k in range(N):
        s = 0
        for i in range(N):
            a = 1 if array[i] == 0 else -1
            b = 1 if array[(i + k) % N] == 0 else -1
            s += a * b
        result.append(s / N)
    return result

if __name__ == "__main__":
    print("学号: 3124004333")
    array = [random.randint(0, 1) for _ in range(50)]
    print("Generated sequence:", "".join(map(str, array)))
    result = autocorrelation(array)
    print("Autocorrelation result:", result)