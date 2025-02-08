""" Diffie-Hellman Module """

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import typing
from random import randint
import math


"""
" class diffie_hellman
"
" Class definition for one party in a Diffie-Hellman key exchange
" scenario. Acts like a "person" in that each instance represents a
" person's secrets and public items.
"
" @param  alpha		Public, randomly-generated number
" @param  q		Public, large prime number
" @param  public_item	Public, number shared between parties
" @param  private_item  Sometimes referred to as "X_k" (where k is a
"			letter unique to a person); random number
" @param  unhashed_key	Known as "s"; symmetric amongst parties but not
"			shared directly
" @param  key		Hashed version of unhashed_key/"s"
"""
class diffie_hellman:
	def __init__(self, q: int, alpha: int) -> None:
		self.alpha: int = alpha
		self.q: int = q

		self.public_item: int = 0
		self.private_item: int = 0
		self.unhashed_key: int = 0
		self.key: bytes = b""

	"""
	" create_items()
	"
	" Creates and stores a random private item (sometimes known as
	" X_A) and a public item using alpha, q, and the public_item.
	"
	" @param   self
	" @return  self.public_item
	"""
	def create_items(self) -> int:
		self.create_public_item()
		self.create_private_item()


	def create_public_item(self) -> int:
		self.public_item = pow(self.alpha, self.private_item, self.q)

		return self.public_item

	def create_private_item(self) -> int:
		self.private_item = randint(1, self.q - 1)

		return self.public_item

	"""
	" create_unhashed_key()
	"
	" Creates an unhashed key using the private item, another party's
	" public item, and q.
	"
	" @param   self
	" @param   ext_public_item
	" @return  self.unhashed_key
	"""
	def create_unhashed_key(self, ext_public_item: int) -> int:
		# Create the unhashed key
		self.unhashed_key = pow(ext_public_item, self.private_item, self.q)

		return self.unhashed_key

	"""
	" create_key()
	"
	" Hashes the unhashed key created with create_unhashed_key().
	" Truncates the hashed key to 16 bytes.
	"
	" @param   self
	" @return  self.key
	"""
	def create_key(self):
		sha256_hash = SHA256.new()

		# Compute the length (in bytes) of the unhashed key
		length = math.ceil(self.unhashed_key.bit_length() / 8)

		# Hash the key and truncate it to 16 bytes
		sha256_hash.update(self.unhashed_key.to_bytes(length, "big"))
		self.key = sha256_hash.digest()[:16]	# [:16] -> truncation

		return self.key


"""
" encrypt_cbc()
" 
" Encrypts a string of any length using AES with Cipher Block Chaining
" (CBC) mode of operation. Requires input strings to be padded to
" conform to AES.block_size.
"
" @param   plaintext_b  plaintext input that is padded and a byte string
" @param   iv           initial vector to use when encrypting
" @param   key          key to use when encrypting
" @return  ciphertext   encrypted byte string
"""
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


"""
" decrypt_cbc()
" 
" Decrypts a string of any length using AES with Cipher Block Chaining
" (CBC) mode of operation. Handles unpadding of plaintext.
"
" @param   ciphertext  plaintext input that is padded and a byte string
" @param   iv          initial vector to use when decrypting
" @param   key         key to use when decrypting
" @return  plaintext   decrypted plaintext
"""
def decrypt_cbc(ciphertext: bytes, iv: bytes, key: bytes) -> str:
	cipher = AES.new(key, AES.MODE_CBC, iv)
	plaintext = cipher.decrypt(ciphertext)

	return unpad(plaintext, AES.block_size).decode("ascii")
