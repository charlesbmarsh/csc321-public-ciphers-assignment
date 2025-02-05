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

"""
" main()
"
" main() function for task1 
"
" @return  None
"""
def main():
	plaintext = "hello"
	
	iv = get_random_bytes(AES.block_size)
	
	# padded_plaintext = pad(plaintext, AES.block_size)

	alice = diffie_hellman(5, 37)
	alice.get_items()
	alice.get_key()
	alice.get_s(500)

	bob = diffie_hellman(5, 37)
	bob.get_items()
	bob.get_key()
	alice.get_s(400)

	ciphertext = encrypt_cbc(plaintext, iv, alice.key)
	print(ciphertext)

	return

class diffie_hellman:
	def __init__(self, alpha: int, q: int):
		self.public_item: int = 0
		self.private_item: int = 0
		self.alpha: int = alpha
		self.q: int = q
		self.s: str = ""
		self.key: bytes = b""

	def get_items(self) -> int:
		self.private_item = randint(1, self.q - 1)
		self.public_item = (self.alpha ** self.private_item) % self.q
		
		return self.public_item

	def get_s(self, ext_public_item: int) -> int:
		self.s = (ext_public_item ** self.private_item) % self.q

		return self.s

	def get_key(self):
		sha256_hash = SHA256.new()
		self.key = sha256_hash.update(bytes(self.s, "ascii"))

		return self.key


def encrypt_cbc(plaintext_b: bytes, iv: bytes, key: bytes) -> bytes:
	cipher_cbc = AES.new(key, AES.MODE_ECB)
	i = 0
	blocks = []
	encrypted_blocks = []

	for blk_start in range(0, len(plaintext_b), AES.block_size):
		new_block = bytearray(b"")
		if blk_start == 0:
			for byte_b, iv_b in zip(plaintext_b[blk_start:blk_start+128], iv):
				new_block.append(byte_b ^ iv_b)
			blocks.append(new_block)
		else:
			for byte_b, cipher_b in zip(plaintext_b[blk_start:blk_start+128], encrypted_blocks[i - 1]):
				new_block.append(byte_b ^ cipher_b)
			blocks.append(new_block)

		encrypted_blocks.append(cipher_cbc.encrypt(blocks[i]))
		i += 1

	ciphertext = b"".join(encrypted_blocks)

	return ciphertext


if __name__ == "__main__":
	main()

