from sys import argv
from random import randint
from subprocess import call, DEVNULL

aes_iv = "12345678901234567890123456789012"
aes_key = "23456789012345678901234567890123"

if len(argv) < 2:
    source = "enc.txt"
else:
    source = argv[1]

basename = ".".join(source.split(".")[:-1])
extension = "." + source.split(".")[-1]
source_cpy = basename + "_cpy" + extension


def try_decrypt(content):
    """
    Black box that tries to decrypt the content given in argument
    using AES-128-CBC with a fixed key and initialization vector.
    Returns 0 when the content is valid, 1 otherwise.
    """
    with open(source_cpy, "wb") as f:
        f.write(bytes(content))
    # Problème : c'est assez lent de tout réécrire à chaque fois
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


with open(source, "rb") as f:
    enc = list(f.read())

nb_bytes = len(enc)
block_size = 128 // 8
nb_blocks = nb_bytes // block_size

content = enc[:]


def find_padding_size():
    p = block_size
    content[-block_size - p] ^= 1
    while try_decrypt(content) == 0:
        content[-block_size - p] ^= 1
        p -= 1
        content[-block_size - p] ^= 1
    content[-block_size - p] ^= 1
    return p


padding_size = find_padding_size()

dec = [0] * (nb_bytes - padding_size)


def find_last_block():
    for i in range(1, block_size - padding_size + 1):
        p = padding_size + i
        for j in range(1, p):
            content[-block_size - j] ^= (p - 1) ^ p
        for j in range(256):
            content[-block_size - p] = j
            if try_decrypt(content) == 0:
                dec[-i] = j ^ p
                print(f"Found the byte {-i}: {dec[-i]}")
                break
        else:
            print(f"Failed to reverse the byte {-i}")
    # Problème : le résultat ne correspond pas avec le message


with open("msg.txt", "rb") as f:
    sol = list(f.read())
# Solution attendue, pour comparer avec "dec"
