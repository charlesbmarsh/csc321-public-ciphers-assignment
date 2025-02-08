"""
" Assignment 2, Task 2
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
	q = 37
	alpha = 5

	public_items_attack(37, 5, padded_plaintext, iv)
	alpha_attack(q, 1, padded_plaintext, iv)
	alpha_attack(q, q, padded_plaintext, iv)
	alpha_attack(q, q - 1, padded_plaintext, iv)

	return


def public_items_attack(q: int, alpha: int, padded_plaintext: bytes, iv: int):
	# Initialize three diffie_hellman instances and create their public and
	# private "items" (X and Y)
	alice = diffie_hellman(q, alpha)
	bob = diffie_hellman(q, alpha)

	alice.create_items()
	bob.create_items()

	mallory = diffie_hellman(q, alpha)
	# Mallory only needs a private item (doesn't care about public)
	mallory.create_private_item()

	# With public and private "items" created, create the unhashed keys
	alice.create_unhashed_key(mallory.q)
	bob.create_unhashed_key(mallory.q)
	mallory.create_unhashed_key(mallory.q)

	# Create the (hashed) keys
	alice.create_key()
	bob.create_key()
	mallory.create_key()

	# Encrypt the ciphertext using Alice's key
	ciphertext: bytes = encrypt_cbc(padded_plaintext, iv, alice.key)

	# Decrypt the ciphertext using Mallory's key
	returned_plaintext: str = decrypt_cbc(ciphertext, iv, mallory.key)

	# Display success of program
#	print(f"Original plaintext: {plaintext}\n")
	print(f"Alice's hashed key: {alice.key}")
	print(f"Bob's hashed key: {bob.key}")
	print(f"Mallory's hashed key: {mallory.key}\n")
	print(f"Alice's key == Bob's key: {alice.key == bob.key}")
	print(f"Mallory's key == Bob's key: {mallory.key == bob.key}")
	print(f"Mallory's key == Alice's key: {mallory.key == alice.key}\n")
	print(f"Ciphertext (bytes): {ciphertext}")
	print(f"Decrypted ciphertext using MALLORY's key: {returned_plaintext}")


def alpha_attack(q: int, alpha: int, padded_plaintext: bytes, iv: int):
	alice = diffie_hellman(q, alpha)
	bob = diffie_hellman(q, alpha)
	mallory = diffie_hellman(q, alpha)

	alice.create_items()
	bob.create_items()
	mallory.create_private_item()

	# With public and private "items" created, create the unhashed keys
	alice.create_unhashed_key(mallory.q)
	bob.create_unhashed_key(mallory.q)
	mallory.create_unhashed_key(mallory.q)

	# Create the (hashed) keys
	alice.create_key()
	bob.create_key()
	mallory.create_key()

	# Encrypt the ciphertext using Alice's key
	ciphertext: bytes = encrypt_cbc(padded_plaintext, iv, alice.key)

	# Decrypt the ciphertext using Mallory's key
	returned_plaintext: str = decrypt_cbc(ciphertext, iv, mallory.key)

	# Display success of program
	print("ATTACK 2:")
#	print(f"Original plaintext: {plaintext}\n")
	print(f"Alice's hashed key: {alice.key}")
	print(f"Bob's hashed key: {bob.key}")
	print(f"Mallory's hashed key: {mallory.key}\n")
	print(f"Alice's key == Bob's key: {alice.key == bob.key}")
	print(f"Mallory's key == Bob's key: {mallory.key == bob.key}")
	print(f"Mallory's key == Alice's key: {mallory.key == alice.key}\n")
	print(f"Ciphertext (bytes): {ciphertext}")
	print(f"Decrypted ciphertext using MALLORY's key: {returned_plaintext}")




if __name__ == "__main__":
	main()

