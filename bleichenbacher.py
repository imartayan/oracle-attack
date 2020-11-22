from argparse import ArgumentParser
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey.RSA import construct, importKey
from Crypto.Util.number import inverse

parser = ArgumentParser(
    description="Python implementation of Bleichenbacher's oracle attack on RSA PKCS#1 v1.5"
)
parser.add_argument("file", help="file containing the (encrypted) message")
parser.add_argument("-k", "--key", help="file containing the private key")
parser.add_argument(
    "-e",
    "--encrypt",
    help="encrypt the message with private key",
    default=False,
    action="store_true",
)
args = parser.parse_args()

if args.key:
    with open(args.key, "r") as f:
        key = importKey(f.read())
else:
    p = 11201792995931324012013272950175336896908788202447968408429424207812076636563926070123654735189823803846891279528352720272949563135129697494110095639122437
    q = 12781417713775747037727068123145570128249631182737575375399994695663395859430871867605127422779176268198497033603094868069070024963533157740922475694191731
    e = 65537
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    key = construct((n, e, d))

cipher = PKCS1_v1_5.new(key)
B = 1 << 8 * (key.size_in_bytes() - 2)

if args.encrypt:
    with open(args.file, "r") as f:
        content = bytes(f.read(), "utf-8")
    basename = ".".join(args.file.split(".")[:-1])
    source = basename + "_rsa.enc"
    with open(source, "wb") as out:
        out.write(cipher.encrypt(content))
else:
    source = args.file

with open(source, "rb") as f:
    enc = int.from_bytes(f.read(), "big")


def oracle(c, s):
    """
    Oracle that tries to decrypt the message `c' = c * s^e mod n`
    and returns whether the decrypted message is valid or not.
    """
    c = (c * pow(s, key.e, key.n)) % key.n
    content = c.to_bytes(key.size_in_bytes(), "big")
    res = cipher.decrypt(content, "INVALID")
    return res != "INVALID"


def find_first_s(M):
    s = (key.n + M[0][0]) // M[0][1]
    while not oracle(enc, s):
        s += 1
    return s


def search(M, s):
    """
    Step 2b/2c: searching conforming messages.
    """
    if len(M) == 1:
        low, high = M[0]
        k = (2 * high * s - 2 * B - 1) // key.n + 1
        while True:
            s_low = (2 * B + k * key.n - 1) // high + 1
            s_high = (3 * B - 1 + k * key.n) // low
            for s in range(s_low, s_high + 1):
                if oracle(enc, s):
                    return s
            k += 1
    else:
        s += 1
        while not oracle(enc, s):
            s += 1
        return s


def narrow(M, s):
    """
    Step 3: narrowing the solutions.
    """
    M_new = []
    for low, high in M:
        k_low = (low * s - 3 * B) // key.n + 1
        k_high = (high * s - 2 * B) // key.n
        for k in range(k_low, k_high + 1):
            m_low = (2 * B + k * key.n - 1) // s + 1
            m_high = (3 * B - 1 + k * key.n) // s
            if m_low <= high and low <= m_high:
                new_low = max(low, m_low)
                new_high = min(high, m_high)
                if (new_low, new_high) not in M_new:
                    M_new.append((new_low, new_high))
    return M_new


def unique(M):
    if len(M) == 1:
        low, high = M[0]
        return low == high
    return False


# Bleichenbacher's attack
M = [(2 * B, 3 * B - 1)]
print("Looking for a first conforming message")
s = find_first_s(M)
print("First s:", s)
M = narrow(M, s)
while not unique(M):
    s = search(M, s)
    print("New s:", s)
    M = narrow(M, s)
m = M[0][0]
b = m.to_bytes(key.size_in_bytes(), "big")
p = 2 + b[2:].index(0) + 1

print("Decrypted message:")
print(b[p:].decode("utf-8"))
