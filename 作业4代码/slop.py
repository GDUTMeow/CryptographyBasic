# analysis.py
# 学号: 3124004333
# DES 差分海明重量统计分析（情况A、情况B，逐轮1~16）

import random
import sys
from prettytable import PrettyTable
from core import des_encrypt_rounds, hamming_distance


def random_bits(n=64):
    return [random.randint(0, 1) for _ in range(n)]


def flip_n_bits(bits, n):
    result = bits[:]
    positions = random.sample(range(len(bits)), n)
    for p in positions:
        result[p] ^= 1
    return result


# ==================== 情况A ====================

def analyze_case_A(num_groups=5):
    print("=" * 70)
    print("情况A：固定密钥，明文差分海明重量 vs 密文海明距离（逐轮）")
    print("=" * 70)

    results = {}

    for hw in range(1, 65):
        round_dists = [0.0] * 16

        for _ in range(num_groups):
            key = random_bits(64)
            m1 = random_bits(64)
            m2 = flip_n_bits(m1, hw)

            _, states1 = des_encrypt_rounds(m1, key)
            _, states2 = des_encrypt_rounds(m2, key)

            for r in range(1, 17):
                round_dists[r - 1] += hamming_distance(states1[r], states2[r])

        results[hw] = [d / num_groups for d in round_dists]
        sys.stdout.write(f"\r情况A: 差分重量 {hw}/64 已完成")
        sys.stdout.flush()

    print("\n情况A 完成。\n")
    return results


# ==================== 情况B ====================

def analyze_case_B(num_groups=5):
    print("=" * 70)
    print("情况B：固定明文，密钥差分海明重量 vs 密文海明距离（逐轮）")
    print("=" * 70)

    results = {}

    for hw in range(1, 65):
        round_dists = [0.0] * 16

        for _ in range(num_groups):
            m  = random_bits(64)
            k1 = random_bits(64)
            k2 = flip_n_bits(k1, hw)

            _, states1 = des_encrypt_rounds(m, k1)
            _, states2 = des_encrypt_rounds(m, k2)

            for r in range(1, 17):
                round_dists[r - 1] += hamming_distance(states1[r], states2[r])

        results[hw] = [d / num_groups for d in round_dists]
        sys.stdout.write(f"\r情况B: 差分重量 {hw}/64 已完成")
        sys.stdout.flush()

    print("\n情况B 完成。\n")
    return results


# ==================== PrettyTable 输出 ====================

def make_table(results, title):
    """生成 prettytable 对象"""
    table = PrettyTable()
    table.title = title

    # 字段名：差分重量 + R1~R16
    field_names = ["差分重量"] + [f"R{i}" for i in range(1, 17)]
    table.field_names = field_names

    # 对齐方式：全部居中
    table.align = "c"

    # 填数据
    for hw in range(1, 65):
        row = [hw] + [f"{results[hw][r]:.1f}" for r in range(16)]
        table.add_row(row)

    return table


def print_and_save(results, title, filename):
    """打印到控制台 + 保存到文件"""
    table = make_table(results, title)

    # 控制台打印
    print(table)
    print()

    # 保存到文件（prettytable 的 get_string 不带颜色，直接存）
    with open(filename, "w", encoding="utf-8") as f:
        f.write(title + "\n\n")
        f.write(table.get_string())
        f.write("\n")
    print(f"已保存: {filename}\n")


# ==================== 主程序 ====================

if __name__ == "__main__":
    print("学号: 3124004333")
    print("DES 差分海明重量统计分析（情况A / 情况B，逐轮 1~16）\n")

    N = 5   # 每组重复次数，可以改成 10 让平均值更平滑

    # 情况 A
    res_A = analyze_case_A(N)
    print_and_save(res_A, "情况A：固定密钥，明文差分（逐轮 1~16）", "results_A.txt")

    # 情况 B
    res_B = analyze_case_B(N)
    print_and_save(res_B, "情况B：固定明文，密钥差分（逐轮 1~16）", "results_B.txt")

    print("全部完成！")