DEFAULT = 0b0001
GX = 0b10011


def linear_left_rotate(state: int, g: int) -> tuple[int, int]:
    """线性移位寄存器函数
    g(x) = g_n * x^n + g_(n-1) * x^(n-1) + ... + g_1 * x + g_0
    根据书上的图，规定寄存器只有 4 位，s3 -> s0 分别代表最高位到最低位

    Args:
        state: 当前状态
        g: 本源多项式 10011 => g(x) = x^4 + x + 1
    """
    feedback = 0
    for i in range(4):
        if (g >> i) & 1:
            feedback ^= (state >> i) & 1
    output = feedback
    newstate = (state >> 1) | (feedback << 3)
    return newstate, output


if __name__ == "__main__":
    print("学号: 3124004333")
    state = DEFAULT
    print(f"Initial State: {bin(state)[2:].zfill(4)}, Polynomial: {bin(GX)[2:].zfill(5)}")
    for i in range(20):
        state, out = linear_left_rotate(state, GX)
        print(
            f"Step {str(i+1).zfill(2)}: State: {bin(state)[2:].zfill(4)}, Output: {out}"
        )
