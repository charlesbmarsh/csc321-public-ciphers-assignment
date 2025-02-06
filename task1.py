"""
" Assignment 2, Task 1
"
" Charlie Marsh, Gavin Ruane, and Michael Wilson
" CSC 321-03
"
"""

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from sys import argv
import typing
from random import randint
import math
from diffiehellman import *

"""
" main()
"
" main() function for task1 
"
" @return  None
"""
def main():
	# Check command-line arguments
	if len(argv) < 2:
		print("task2: please provide a plaintext string.")
		print("task2: usage: task2.py <plaintext>")
		exit()
	
	# Obtain plaintext and pad it
	plaintext: str = argv[1]
	padded_plaintext: bytes = pad(plaintext.encode("ascii"), AES.block_size)
	
	# Create an initial vector from random bytes
	iv: bytes = get_random_bytes(AES.block_size)

	# Define q and alpha
	q_str: bytes = (
		b"B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61"
		b"6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF"
		b"ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
		b"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"
	)
	q: int = int(q_str, 16)


	alpha_str: bytes = (
		b"B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
		b"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
		b"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
		b"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
		b"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
		b"DF1FB2BC2E4A4371"
	)
	alpha: int = int(alpha_str, 16)

#	q = 37
#	alpha = 5

	# Initialize two diffie_hellman instances and create their public and
	# private "items" (X and Y)
	alice = diffie_hellman(q, alpha)
	alice.create_items()
	bob = diffie_hellman(q, alpha)
	bob.create_items()

	# With public and private "items" created, create the unhashed keys
	alice.create_unhashed_key(bob.public_item)
	bob.create_unhashed_key(alice.public_item)

	# Create the (hashed) keys
	alice.create_key()
	bob.create_key()

	# Encrypt the ciphertext using Alice's key
	ciphertext: bytes = encrypt_cbc(padded_plaintext, iv, alice.key)

	# Decrypt the ciphertext using Bob's key
	returned_plaintext: str = decrypt_cbc(ciphertext, iv, bob.key)

	# Display success of program
	print(f"Original plaintext: {plaintext}\n")
	print(f"Alice's hashed key: {alice.key}")
	print(f"Bob's hashed key: {bob.key}")
	print(f"Alice's key == Bob's key: {alice.key == bob.key}\n")
	print(f"Ciphertext (bytes): {ciphertext}")
	print(f"Decrypted ciphertext: {returned_plaintext}")

	return




if __name__ == "__main__":
	main()

