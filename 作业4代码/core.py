from const import (
    IP_TABLE,
    IP_INVERSE_TABLE,
    SUBSTITUTION_BOX,
    ROTATES,
    PC1,
    PC2,
    E_TABLE,
    P_TABLE,
)


def permute(bits, table):
    # 按置换表重排位串
    return [bits[i - 1] for i in table]


def xor_bits(a, b):
    # 逐位异或
    return [x ^ y for x, y in zip(a, b)]


def bits_to_int(bits):
    # 位列表转整数
    result = 0
    for b in bits:
        result = (result << 1) | b
    return result


def int_to_bits(n, length=64):
    # 整数转固定长度位列表
    return [(n >> (length - 1 - i)) & 1 for i in range(length)]


def hamming_weight(bits):
    # 海明重量
    return sum(bits)


def hamming_distance(bits1, bits2):
    # 海明距离
    return sum(a != b for a, b in zip(bits1, bits2))


def bytes_to_bits(data, n_bytes=8):
    # 字节串转位列表
    bits = []
    for byte in data[:n_bytes]:
        bits.extend([(byte >> (7 - i)) & 1 for i in range(8)])
    # 不足补零
    while len(bits) < n_bytes * 8:
        bits.append(0)
    return bits


def bits_to_bytes(bits):
    # 位列表转字节串
    result = bytearray()
    for i in range(0, len(bits), 8):
        val = 0
        for j in range(8):
            val = (val << 1) | bits[i + j]
        result.append(val)
    return bytes(result)


def generate_subkeys(key_bits):
    key56 = permute(key_bits, PC1)
    C, D = key56[:28], key56[28:]

    subkeys = []
    for shift in ROTATES:
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]
        subkeys.append(permute(C + D, PC2))
    return subkeys


def feistel_f(R, subkey):
    expanded = permute(R, E_TABLE)
    xored = xor_bits(expanded, subkey)
    s_out = []
    for i in range(8):
        block = xored[i * 6 : (i + 1) * 6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        val = SUBSTITUTION_BOX[i][row * 16 + col]
        s_out.extend([(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1])
    return permute(s_out, P_TABLE)


def des_encrypt_rounds(plaintext_bits, key_bits):
    assert len(plaintext_bits) == 64, "Plaintext must be 64 bits"
    assert len(key_bits) == 64, "Key must be 64 bits"

    state = permute(plaintext_bits, IP_TABLE)
    rounds = [state[:]]

    L, R = state[:32], state[32:]
    subkeys = generate_subkeys(key_bits)

    for i in range(16):
        new_L = R[:]
        f_out = feistel_f(R, subkeys[i])
        new_R = xor_bits(L, f_out)
        L, R = new_L, new_R
        rounds.append(L + R)

    pre_output = R + L
    cipher = permute(pre_output, IP_INVERSE_TABLE)
    return cipher, rounds


def des_encrypt(plaintext_bytes, key_bytes):
    pt_bits = bytes_to_bits(plaintext_bytes, 8)
    key_bits = bytes_to_bits(key_bytes, 8)
    cipher_bits, _ = des_encrypt_rounds(pt_bits, key_bits)
    return bits_to_bytes(cipher_bits)


def des_decrypt_rounds(cipher_bits, key_bits):
    assert len(cipher_bits) == 64
    assert len(key_bits) == 64

    state = permute(cipher_bits, IP_TABLE)
    rounds = [state[:]]

    L, R = state[:32], state[32:]
    subkeys = generate_subkeys(key_bits)[::-1]

    for i in range(16):
        new_L = R[:]
        f_out = feistel_f(R, subkeys[i])
        new_R = xor_bits(L, f_out)
        L, R = new_L, new_R
        rounds.append(L + R)

    pre_output = R + L
    plaintext = permute(pre_output, IP_INVERSE_TABLE)
    return plaintext, rounds


def des_decrypt(cipher_bytes, key_bytes):
    ct_bits = bytes_to_bits(cipher_bytes, 8)
    key_bits = bytes_to_bits(key_bytes, 8)
    pt_bits, _ = des_decrypt_rounds(ct_bits, key_bits)
    return bits_to_bytes(pt_bits)
