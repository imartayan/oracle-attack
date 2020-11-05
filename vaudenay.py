from sys import argv
from Crypto.Cipher import AES

# Initialization vector and secret key used by AES
aes_iv = "12345678901234567890123456789012"
aes_key = "23456789012345678901234567890123"
iv = bytes.fromhex(aes_iv)
key = bytes.fromhex(aes_key)
block_size = 128 // 8  # size of one block (in bytes)

# Name of the encrypted file
if len(argv) < 2:
    source = "enc.txt"
else:
    source = argv[1]

# List of the encrypted bytes
with open(source, "rb") as f:
    # add the initialization vector at the beginning
    enc = list(iv) + list(f.read())

nb_bytes = len(enc)
nb_blocks = nb_bytes // block_size


def try_decrypt(content):
    """
    Oracle that tries to decrypt the content given in argument
    using AES-128-CBC with a fixed key and initialization vector,
    and returns whether the padding is valid or not.
    """
    aes = AES.new(key, AES.MODE_CBC, iv)
    res = list(aes.decrypt(bytes(content)))
    p = res[-1]
    return res[-p:] == [p] * p


def find_padding(enc):
    """
    Finds the padding size of the message.
    """
    content = enc[:]
    p = block_size
    content[-block_size - p] ^= 1
    while try_decrypt(content):
        p -= 1
        content[-block_size - p] ^= 1
    return p


dec_size = nb_bytes - block_size
dec = [None] * dec_size
padding_size = find_padding(enc)
actual_size = dec_size - padding_size
msg = ["?"] * actual_size


def reverse_last_block(enc):
    """
    Reverses the last block of the message.
    """
    content = enc[:]
    for p in range(1, padding_size + 1):
        dec[-p] = enc[-p - block_size] ^ padding_size
    for p in range(padding_size + 1, block_size + 1):
        i = dec_size - p
        for j in range(1, p):
            content[dec_size - j] ^= (p - 1) ^ p
        for k in range(256):
            content[i] = k
            if try_decrypt(content):
                dec[i] = k ^ p
                msg[i] = chr(dec[i] ^ enc[i])
                break
        else:
            print(f"Failed to reverse byte {i}")
            break
    else:
        print("Reversed last block")


def reverse_block(enc, b):
    """
    Reverses the block number b of the message.
    """
    assert 2 <= b < nb_blocks
    content = enc[: b * block_size]
    for p in range(1, block_size + 1):
        i = (b - 1) * block_size - p
        for j in range(1, p):
            content[(b - 1) * block_size - j] ^= (p - 1) ^ p
        for k in range(256):
            content[i] = k
            if try_decrypt(content):
                dec[i] = k ^ p
                msg[i] = chr(dec[i] ^ enc[i])
                break
        else:
            print(f"Failed to reverse byte {i}")
            break
    else:
        print(f"Reversed block n°{b-1}")


reverse_last_block(enc)
for b in range(nb_blocks - 1, 1, -1):
    reverse_block(enc, b)

print("Decrypted message:")
print("".join(msg))
