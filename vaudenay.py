from sys import argv
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

# List of the encrypted bytes
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


def find_padding(enc):
    """
    Finds the padding size of the message.
    """
    content = enc[:]
    p = block_size
    content[-block_size - p] ^= 1
    while try_decrypt(content) == 0:
        p -= 1
        content[-block_size - p] ^= 1
    return p


dec = [None] * nb_bytes
padding_size = find_padding(enc)
actual_size = nb_bytes - padding_size
msg = [None] * actual_size


def reverse_last_block(enc):
    """
    Reverses the last block of the message.
    """
    content = enc[:]
    for p in range(1, padding_size + 1):
        dec[-p] = enc[-p - block_size] ^ padding_size
    for p in range(padding_size + 1, block_size + 1):
        i = nb_bytes - p
        for j in range(1, p):
            content[nb_bytes - block_size - j] ^= (p - 1) ^ p
        for k in range(256):
            content[i - block_size] = k
            if try_decrypt(content) == 0:
                dec[i] = k ^ p
                msg[i] = chr(dec[i] ^ enc[i - block_size])
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
        i = b * block_size - p
        for j in range(1, p):
            content[(b - 1) * block_size - j] ^= (p - 1) ^ p
        for k in range(256):
            content[i - block_size] = k
            if try_decrypt(content) == 0:
                dec[i] = k ^ p
                msg[i] = chr(dec[i] ^ enc[i - block_size])
                break
        else:
            print(f"Failed to reverse byte {i}")
            break
    else:
        print(f"Reversed block n°{b}")


def reverse_first_block(enc):
    """
    Reverses the first block of the message using the IV.
    """
    iv = list(bytes.fromhex(aes_iv))
    content = iv + enc[:block_size]
    for p in range(1, block_size + 1):
        i = block_size - p
        for j in range(1, p):
            content[block_size - j] ^= (p - 1) ^ p
        for k in range(256):
            content[i] = k
            if try_decrypt(content) == 0:
                dec[i] = k ^ p
                msg[i] = chr(dec[i] ^ iv[i])
                break
        else:
            print(f"Failed to reverse byte {i}")
            break
    else:
        print(f"Reversed first block")


reverse_last_block(enc)
for b in range(nb_blocks - 1, 1, -1):
    reverse_block(enc, b)
reverse_first_block(enc)
