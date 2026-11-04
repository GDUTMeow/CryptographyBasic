def expmod(b: int, n: int, m: int) -> int:
    """
    快速模指运算
    
    b(int): 底数
    n(int): 指数
    m(int): 模数
    
    return(int): (b^n) mod m
    """
    result = 1
    base = b % m
    while n > 0:
        if n & 1:
            result = (result * base) % m
        base = (base * base) % m
        n >>= 1
    return result

def invmod(a: int, m: int) -> int:
    """
    模逆运算
    
    a(int): 数字
    m(int): 模数
    
    return(int): a 在模 m 下的逆元
    """
    old_r, r = a, m
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    
    return old_s % m

def dh_exchange(p: int, g: int, a: int, b: int):
    """
    模拟 Diffie-Hellman 密钥交换

    p(int): 公开大素数
    g(int): 公开生成元
    a(int): 私钥 A
    b(int): 私钥 B

    return(tuple): (A, B, K) A 和 B 为公开密钥，K 为共享密钥
    """

    A = expmod(g, a, p)
    B = expmod(g, b, p)

    ka = expmod(B, a, p)
    kb = expmod(A, b, p)
    
    if ka != kb:
        raise ValueError("共享密钥未匹配")
    K = ka

    return A, B, K

