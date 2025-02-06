from Crypto.Util.number import getPrime
from Crypto.Random.random import randint
from math import gcd

def main():
    primeBits = 1024 # need to take use input, support up to 2048 bits
    
    keys = getKeys(primeBits)
    e = keys[0][0]
    n = keys[0][1]
    d = keys[1][0]

    message = "Helo, world!"
    print("message:", message)
    
    ciphertext = encrypt(message, e, n)
    print("ciphertext:", ciphertext)

    plaintext = decrypt(ciphertext, d, n)
    print("plaintext:", plaintext)


def getKeys(primeBits):
    # 1. select p and q
    q = getPrime(primeBits)
    p = q
    while(p == q):
        p = getPrime(primeBits)
    print(f"p = {p}")
    print(f"q = {q}")

    # 2. calculate p * q = n
    n = p * q
    print(f"n = {n}")

    # 3. calculate phi(n) = (p-1)(q-1)
    phi = (p-1) * (q-1)
    print(f"phi(n) = {phi}")

    # 4. select integer e such that gcd(phi(n), e) = 1 and 1 < e < phi(n)
    # in other words, e is relatively prime to phi(n) and e < phi(n)
    # while True:
    #     e = randint(1, n - 1)
    #     if gcd(phi, e) == 1:
    #         break
    e = 65537 # set constant per lab procedure
    print(f"e = {e}")

    # 5. calculate d such that d * e mod phi(n) = 1
    d = 1 
    # ... not sure how to calculate...

    # 6. private key = {e, n}
    # 7. public key = {d, n}
    return ((e, n), (d, n))


def encrypt(M, e, n):
    c = pow(M, e, n)
    print(f"c: {c}")
    return c


def decrypt(C, d, n):
    M = pow(C, d, n)
    print(f"M: {M}")
    return M


if __name__ == "__main__":
    main()