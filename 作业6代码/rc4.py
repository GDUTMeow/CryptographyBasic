from autocorrelationtest import autocorrelation
from runtest import runtest

trace: list[list[int]] = []


class rc4cipher:
    def __init__(
        self,
        key: str,
        s_box: list[int] | None = None,
        rotate_table: list[int] | None = None,
    ):
        if len(key) != 32:
            raise ValueError("Key must be 32 characters (256 bits) long.")
        self.key = key
        self.key_length = len(key)
        self.s_box = (
            [i for i in range(256)] if not s_box else s_box
        )  # S 盒，书上直接填充的线性的
        self.rotate_table = (
            self.generate_rotate_table() if not rotate_table else rotate_table
        )
        self.shuffle_sbox()

    def generate_rotate_table(self) -> list[int]:
        # 生成置换表
        rotate_table = [0 for _ in range(256)]
        for i in range(256):
            rotate_table[i] = ord(self.key[i % self.key_length])
        return rotate_table

    def shuffle_sbox(self):
        j = 0
        for i in range(256):
            j = (j + self.s_box[i] + self.rotate_table[i]) % 256
            self.s_box[i], self.s_box[j] = self.s_box[j], self.s_box[i]

    def generate_keystream(self, length: int = 256) -> bytearray:
        keystream = bytearray()
        s = self.s_box.copy()
        i = 0
        j = 0
        for _ in range(length):
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            s[i], s[j] = s[j], s[i]
            h = (s[i] + s[j]) % 256
            keystream.append(s[h])
            trace.append([i, j, h])
        return keystream

    def encrypt(self, plain: bytes) -> bytes:
        cipher = bytearray()
        keystream = self.generate_keystream()
        for i in range(len(plain)):
            cipher.append((plain[i] + keystream[i]) % 2)
            # 书上 P176 写的 mod 2，这里实际上标准的应该写的是 plain[i] ^ keystream[i]，不知道为啥书上这样搞了
        return bytes(cipher)


if __name__ == "__main__":
    key = "0123456789DEADBEEF0123456789ABCD"
    cipher = rc4cipher(key)
    plain = "Hello World!"
    cipher_text = cipher.encrypt(plain.encode())
    print("学号: 3124004333")
    print(f"Plain: {plain}")
    print(f"Cipher: {cipher_text.hex()}")
    with open(r"作业6代码/trace.csv", "w") as f:
        f.write("i,j,h\n")
        f.writelines(f"{i},{j},{h}\n" for i, j, h in trace)
    # 1000 字节密钥流
    trace = []
    cipher.generate_keystream(1000)
    trace_i = [_[0] for _ in trace]
    trace_j = [_[1] for _ in trace]
    trace_h = [_[2] for _ in trace]
    # 游程
    run_result_i = runtest(trace_i)
    with open(r"作业6代码/run_result_i.csv", "w") as f:
        f.write("游程,类型,长度\n")
        f.writelines(f"{run},{typ},{length}\n" for run, typ, length in run_result_i)
    run_result_j = runtest(trace_j)
    with open(r"作业6代码/run_result_j.csv", "w") as f:
        f.write("游程,类型,长度\n")
        f.writelines(f"{run},{typ},{length}\n" for run, typ, length in run_result_j)
    run_result_h = runtest(trace_h)
    with open(r"作业6代码/run_result_h.csv", "w") as f:
        f.write("游程,类型,长度\n")
        f.writelines(f"{run},{typ},{length}\n" for run, typ, length in run_result_h)
    # 自相关
    autocorr_i = autocorrelation(trace_i)
    autocorr_j = autocorrelation(trace_j)
    autocorr_h = autocorrelation(trace_h)
    with open(r"作业6代码/autocorr.csv", "w") as f:
        f.write("i,j,h\n")
        f.writelines(f"{autocorr_i},{autocorr_j},{autocorr_h}\n")
