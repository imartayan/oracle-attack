from sys import argv
from random import randint
from subprocess import call, DEVNULL

# Initialization vector and secret key used by AES
aes_iv = "12345678901234567890123456789012"
aes_key = "23456789012345678901234567890123"
aes_size = 128  # size of one block (in bits)
block_size = aes_size // 8  # idem (in bytes)

# Name of the encrypted file
if len(argv) < 2:
    source = "enc.txt"
else:
    source = argv[1]

basename = ".".join(source.split(".")[:-1])
extension = "." + source.split(".")[-1]
source_cpy = basename + "_cpy" + extension

# Creating a list with the encrypted bytes
with open(source, "rb") as f:
    enc = list(f.read())

nb_bytes = len(enc)
nb_blocks = nb_bytes // block_size


def try_decrypt(content):
    """
    Oracle that tries to decrypt the content given in argument
    using AES-128-CBC with a fixed key and initialization vector.
    Returns 0 when the content is valid, 1 otherwise.
    """
    with open(source_cpy, "wb") as f:
        f.write(bytes(content))
    # Problem : it is quite slow to rewrite everything
    cmd = [
        "openssl",
        "enc",
        "-d",
        "-aes-128-cbc",
        "-in",
        source_cpy,
        "-iv",
        aes_iv,
        "-K",
        aes_key,
    ]
    return call(cmd, stdout=DEVNULL, stderr=DEVNULL)


content = enc[:]
# Finding the padding size
p = block_size
content[-block_size - p] ^= 1
while try_decrypt(content) == 0:
    p -= 1
    content[-block_size - p] ^= 1
padding_size = p

dec = [None] * nb_bytes
for i in range(1, padding_size + 1):
    dec[-i] = enc[-block_size - i] ^ padding_size

actual_size = nb_bytes - padding_size
msg = [None] * actual_size

content = enc[:]
# Breaking the last block
for i in range(1, block_size - padding_size + 1):
    p = padding_size + i
    for j in range(1, p):
        content[-block_size - j] ^= (p - 1) ^ p
    for k in range(256):
        content[-block_size - p] = k
        if try_decrypt(content) == 0:
            dec[-i] = k ^ p
            msg[-i] = dec[-i] ^ enc[-block_size - p]
            print(f"Found letter {-i}: {chr(msg[-i])}")
            break
    else:
        print(f"Failed to reverse byte {-i}")


with open("msg.txt", "rb") as f:
    sol = list(f.read())
# Expected output, to compare with what we found
