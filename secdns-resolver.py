import os
import sys
import socket
from typing import Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dnslib import DNSRecord

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 54321
PUBKEY_PATH = "secdns_pubkey.pem"

CMD_INIT = "SECDNS_INIT"
CMD_FETCH = "SECDNS_FETCH"
EXPECT_READY = b"SECDNS_READY"
EXPECT_DATA = "SECDNS_DATA"

def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def rsa_encrypt(pub, key: bytes) -> bytes:
    return pub.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def read_line(conn: socket.socket) -> Optional[bytes]:
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            return None
        data += chunk
    return data

def recv_exact(conn: socket.socket, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python secdns-resolver.py <domain>")
        return
    domain = sys.argv[1]
    pub = load_public_key(PUBKEY_PATH)
    sk = AESGCM.generate_key(bit_length=256)
    wrapped = rsa_encrypt(pub, sk)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_HOST, SERVER_PORT))
    s.sendall(f"{CMD_INIT} {len(wrapped)}\n".encode() + wrapped)
    line = read_line(s)
    if not line or line.strip() != EXPECT_READY:
        print("Handshake failed")
        s.close()
        return
    aes = AESGCM(sk)
    q = DNSRecord.question(domain).pack()
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, q, None)
    blob = nonce + ct[:-16] + ct[-16:]
    s.sendall(f"{CMD_FETCH} {len(blob)}\n".encode() + blob)
    hdr = read_line(s)
    if not hdr:
        print("No response")
        s.close()
        return
    try:
        cmd, size_s = hdr.decode().strip().split()
        if cmd != EXPECT_DATA:
            print("Protocol error")
            s.close()
            return
        size = int(size_s)
    except Exception:
        print("Protocol parse error")
        s.close()
        return
    data = recv_exact(s, size)
    if not data:
        print("Truncated response")
        s.close()
        return
    nonce_r = data[:12]
    tag_r = data[-16:]
    ciphertext_r = data[12:-16]
    try:
        plain = aes.decrypt(nonce_r, ciphertext_r + tag_r, None)
        ans = DNSRecord.parse(plain)
        if not ans.rr:
            print("No answer")
        else:
            for rr in ans.rr:
                print(rr.rname, rr.rdata, "OK")
    except Exception:
        print("Decryption/parse failed")
    s.close()

if __name__ == "__main__":
    main()
