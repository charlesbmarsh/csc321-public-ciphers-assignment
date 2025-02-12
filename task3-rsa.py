from sys import argv
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
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

    Akeys = getKeys(primeBits)
    e = Akeys[0][0]
    n = Akeys[0][1]
    dA = Akeys[1][0]

    message = "Hi Bob!"
    print("message:", message)
    input = int(message.encode('latin-1').hex(), 16)
    print(f"input = {input}")
    print("input < n? ", "yes" if input < n else "no")
    if(input >= n):
        print("\nmessage too long!!")
        exit()
    
    ciphertext = encrypt(input, e, n)
    print("ciphertext:", ciphertext)

    output = decrypt(ciphertext, dA, n)
    print(f"output = {output}")
    plaintext = bytes.fromhex(hex(output)[2:]).decode('latin-1')
    print("plaintext:", plaintext)
    print("successfully decrypted? ", "yes!" if plaintext == message else "no :(")



    print(f"\n\nMITM attack!!\n")
    # note: have n and e already
    
    # Bob
    sB = getPrime(n.bit_length() - 1)
    print(f"sB = {sB}")
    print(f"sB < n ? " "yes" if sB < n else "no")
    if sB >= n: exit()
    c = pow(sB, e, n)
    print(f"c = {c}")

    # Mallory
    c_modified = 1

    # Alice
    sA = pow(c_modified, dA, n)
    hashA = SHA256.new()
    length = math.ceil(sA.bit_length() / 8)
    hashA.update(sA.to_bytes(length, "big"))
    kA = hashA.digest()
    print(f"kA = {kA}")
    iv=b"0000000000000000"
    cbc_cipherA = AES.new(kA, AES.MODE_CBC, iv = iv)
    newC = cbc_cipherA.encrypt(pad(message.encode('latin-1'), AES.block_size))

    # Mallory
    hashM = SHA256.new()
    sM = 1
    length = math.ceil(sM.bit_length() / 8)
    hashM.update(sM.to_bytes(length, "big"))
    kM = hashM.digest()
    print(f"kM = kA? " "yes" if kM == kA else "no")
    cbc_cipherM = AES.new(kM, AES.MODE_CBC, iv = iv)
    decrypted = unpad(cbc_cipherM.decrypt(newC), AES.block_size).decode('latin-1')
    print("Mallory decrypted:", decrypted)


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
    """Computes the gcd of a and b and finds
    the coefficients x and y that satisfy the equation ax + by = gcd(a, b)
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
        print("e and phi are not coprime!")
        exit()
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