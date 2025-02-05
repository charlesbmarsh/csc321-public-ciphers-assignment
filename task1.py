"""
" Assignment 2, Task 1
"
" Charlie Marsh, Gavin Ruane, and Michael Wilson
" CSC 321-03
"
"""

import os
from io import BufferedIOBase
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from sys import argv
import typing
from random import randint
import math

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
	q_str: str = (
		"B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61"
		"6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF"
		"ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
		"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"
	)
	q: int = int(q_str, 16)

	alpha_str: str = (
		"B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
		"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
		"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
		"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
		"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
		"DF1FB2BC2E4A4371"
	)
	alpha: int = int(alpha_str, 16)

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


"""
" class diffie_hellman
"
" main() function for task1 
"
" @return  None
"""
class diffie_hellman:
	def __init__(self, alpha: int, q: int):
		self.alpha: int = alpha
		self.q: int = q

		self.public_item: int = 0
		self.private_item: int = 0
		self.unhashed_key: int = 0
		self.key: bytes = b""

	def create_items(self) -> int:
		# Create the private "item" using a random number
		self.private_item = randint(1, self.q - 1)

		# Create the public "item"
		self.public_item = (self.alpha ** self.private_item) % self.q
		
		return self.public_item

	def create_unhashed_key(self, ext_public_item: int) -> int:
		self.unhashed_key = (ext_public_item ** self.private_item) % self.q

		return self.unhashed_key

	def create_key(self):
		sha256_hash = SHA256.new()

		# Compute the length (in bytes) of the unhashed key
		length = math.ceil(self.unhashed_key.bit_length() / 8)

		# Hash the key and truncate it to 16 bytes
		sha256_hash.update(self.unhashed_key.to_bytes(length, "big"))
		self.key = sha256_hash.digest()[:16]	# [:16] -> truncation

		return self.key


def encrypt_cbc(plaintext: bytes, iv: bytes, key: bytes) -> bytes:
	cipher_cbc = AES.new(key, AES.MODE_ECB)
	i = 0
	blocks = []
	encrypted_blocks = []

	for blk_start in range(0, len(plaintext), AES.block_size):
		new_block = bytearray(b"")
		if blk_start == 0:
			for byte_b, iv_b in zip(plaintext[blk_start:blk_start+128], iv):
				new_block.append(byte_b ^ iv_b)
			blocks.append(new_block)
		else:
			for byte_b, cipher_b in zip(plaintext[blk_start:blk_start+128], encrypted_blocks[i - 1]):
				new_block.append(byte_b ^ cipher_b)
			blocks.append(new_block)

		encrypted_blocks.append(cipher_cbc.encrypt(blocks[i]))
		i += 1

	ciphertext = b"".join(encrypted_blocks)

	return ciphertext

def decrypt_cbc(ciphertext: bytes, iv: bytes, key: bytes) -> str:
	cipher = AES.new(key, AES.MODE_CBC, iv)
	plaintext_padded = cipher.decrypt(ciphertext)
	plaintext = unpad(plaintext_padded, AES.block_size).decode("latin-1")

	return plaintext


if __name__ == "__main__":
	main()

