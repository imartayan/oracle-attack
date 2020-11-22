from argparse import ArgumentParser
from Crypto.Cipher import AES

parser = ArgumentParser(
    description="Python implementation of Vaudenay's oracle attack on AES-128-CBC"
)
parser.add_argument("file", help="file containing the (encrypted) message")
parser.add_argument("-iv", help="initialization vector")
parser.add_argument("-k", "--key", help="secret key used for encryption/decryption")
parser.add_argument(
    "-s",
    "--size",
    help="AES block size in bits (128 by default)",
    default=128,
    type=int,
)
parser.add_argument(
    "-e",
    "--encrypt",
    help="encrypt the message with iv and secret key",
    default=False,
    action="store_true",
)
args = parser.parse_args()

if args.iv:
    aes_iv = args.iv
else:
    aes_iv = "12345678901234567890123456789012"
iv = bytes.fromhex(aes_iv)

if args.key:
    aes_key = args.key
else:
    aes_key = "23456789012345678901234567890123"
key = bytes.fromhex(aes_key)

# size of one block (in bytes)
block_size = args.size // 8

if args.encrypt:
    with open(args.file, "r") as f:
        content = bytes(f.read(), "utf-8")
    # padding
    r = len(content) % block_size
    p = block_size - r
    padding = p.to_bytes(1, "big") * p
    basename = ".".join(args.file.split(".")[:-1])
    source = basename + "_aes.enc"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(source, "wb") as out:
        out.write(cipher.encrypt(content + padding))
else:
    source = args.file

with open(source, "rb") as f:
    # add the initialization vector at the beginning
    enc = list(iv) + list(f.read())


def oracle(content):
    """
    Oracle that tries to decrypt the message given in argument
    using AES-128-CBC with a fixed key and initialization vector,
    and returns whether the padding is valid or not.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    res = list(cipher.decrypt(bytes(content)))
    p = res[-1]
    return res[-p:] == [p] * p


def find_padding(enc):
    """
    Finds the padding size of the message.
    """
    content = enc[:]
    p = block_size
    content[-block_size - p] ^= 1
    while oracle(content):
        p -= 1
        content[-block_size - p] ^= 1
    return p


nb_bytes = len(enc)
nb_blocks = nb_bytes // block_size
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
            if oracle(content):
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
            if oracle(content):
                dec[i] = k ^ p
                msg[i] = chr(dec[i] ^ enc[i])
                break
        else:
            print(f"Failed to reverse byte {i}")
            break
    else:
        print(f"Reversed block n°{b-1}")


# Vaudenay's attack
reverse_last_block(enc)
for b in range(nb_blocks - 1, 1, -1):
    reverse_block(enc, b)

print("Decrypted message:")
print("".join(msg))
