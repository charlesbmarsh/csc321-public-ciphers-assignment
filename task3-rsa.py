from Crypto.Util.number import getPrime
# from Crypto.Random.random import randint
import math

def main():
    primeBits = 1024 # need to take user input, support up to 2048 bits

    keys = getKeys(primeBits)
    e = keys[0][0]
    n = keys[0][1]
    d = keys[1][0]

    message = "Helo, world!"
    input = int(message.encode('latin-1').hex(), 16)
    print("message:", input, "(type", type(input), ")")
    print("message < n?", input < n)
    if(input >= n):
        print("message too long!")
        return
    
    ciphertext = encrypt(input, e, n)
    print("ciphertext:", ciphertext)

    ciphertext_modified = (ciphertext * pow(ciphertext - 1, e, n)) % n

    plaintext_modified = decrypt(ciphertext_modified, d, n)
    plaintext = (plaintext_modified * modular_inverse(ciphertext - 1, n)) % n
    # print("plaintext:", plaintext)
    print("successfully decrypted?", plaintext == input)


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
    e = 65537 # set constant per lab procedure
    print(f"e = {e}")

    # 5. calculate d such that d * e mod phi(n) = 1
    d = modular_inverse(e, phi)
    print(f"d = {d}")

    # 6. private key = {e, n}
    # 7. public key = {d, n}
    return ((e, n), (d, n))


def extended_gcd(a, b):
    """Computes the Greatest Common Divisor (GCD) of a and b,
    as well as the coefficients (x, y) that satisfy the equation:
    ax + by = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    else:
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

def modular_inverse(e, phi):
    """Finds the modular inverse of e modulo phi using the Extended Euclidean Algorithm."""
    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("e and phi must be coprime")
    else:
        return x % phi  # Ensure d is positive


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