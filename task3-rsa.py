from sys import argv
from Crypto.Util.number import getPrime
import math

def main():
    if len(argv) < 2:
        print("task3: please provide a prime length between 3 and 2048.")
        print("task3: usage: task3-rsa.py <prime length> ")
        exit()
	
	# take user input to determine length of primes
    primeBits = int(argv[1], 10) # base 10 integer input
    if primeBits > 2048 or primeBits < 3:
        print("please provide a prime length between 2 and 2048")
        exit()

    keys = getKeys(primeBits)
    e = keys[0][0]
    n = keys[0][1]
    d = keys[1][0]

    message = "Hi Bob!"
    print("message:", message)
    input = int(message.encode('latin-1').hex(), 16)
    print(f"input = {input}")
    print("input < n?", input < n)
    if(input >= n):
        print("\nmessage too long!!")
        exit()
    
    ciphertext = encrypt(input, e, n)
    print("ciphertext:", ciphertext)

    output = decrypt(ciphertext, d, n)
    print(f"output = {output}")
    plaintext = bytes.fromhex(hex(output)[2:]).decode('latin-1')
    print("plaintext:", plaintext)
    print("successfully decrypted?", "yes!" if plaintext == message else "no :(")



    print(f"\n\nMITM attack!!\n")
    
    k = 3
    if math.gcd(k, n) != 1:
        print("selected k not coprime!!")
        exit()
    
    ciphertext_modified = (ciphertext * pow(k, e)) % n
    print(f"modified ciphertext = {ciphertext_modified}")

    output_modified = decrypt(ciphertext_modified, d, n)
    print(f"modified output = {output_modified}")
    output = (output_modified * modular_inverse(k, n)) % n
    print(f"fixed output = {output}")
    plaintext = bytes.fromhex(hex(output)[2:]).decode('latin-1')
    print("plaintext:", plaintext)
    print("successfully decrypted?", "yes!" if plaintext == message else "no :(")


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
    """Computes the Greatest Common Divisor (GCD) of a and b and 
    the coefficients (x, y) that satisfy the equation ax + by = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    else:
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y


def modular_inverse(e, phi):
    # uses the extended euclidean algorithm
    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("e and phi must be coprime")
    else:
        return x % phi  # Ensure d is positive


def encrypt(M, e, n):
    c = pow(M, e, n)
    return c


def decrypt(C, d, n):
    M = pow(C, d, n)
    return M


if __name__ == "__main__":
    main()