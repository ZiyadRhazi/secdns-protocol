import os
import socket
from typing import Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dnslib import DNSRecord, RR, A

HOST = "0.0.0.0"
PORT = 54321
PRIVKEY_PATH = "secdns_privkey.pem"

SECDNS_ABORT = b"SECDNS_ABORT\n"
SECDNS_READY = b"SECDNS_READY\n"
CMD_INIT = "SECDNS_INIT"
CMD_FETCH = "SECDNS_FETCH"
CMD_DATA = "SECDNS_DATA"

def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def rsa_decrypt(priv, blob: bytes) -> bytes:
    return priv.decrypt(
        blob,
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

def resolve_ipv4(domain: str) -> Optional[str]:
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        return infos[0][4][0] if infos else None
    except Exception:
        return None

def send_enc(conn: socket.socket, aes: AESGCM, payload: bytes) -> None:
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, payload, None)
    blob = nonce + ct[:-16] + ct[-16:]
    conn.sendall(f"{CMD_DATA} {len(blob)}\n".encode() + blob)

def handle_fetch(conn: socket.socket, aes: AESGCM) -> bool:
    header = read_line(conn)
    if not header:
        return False
    try:
        cmd, size_s = header.decode().strip().split()
        if cmd != CMD_FETCH:
            return False
        size = int(size_s)
    except Exception:
        return False
    blob = recv_exact(conn, size)
    if not blob:
        return False
    nonce = blob[:12]
    tag = blob[-16:]
    ciphertext = blob[12:-16]
    try:
        qraw = aes.decrypt(nonce, ciphertext + tag, None)
    except Exception:
        return False
    req = DNSRecord.parse(qraw)
    domain = str(req.q.qname).rstrip(".")
    ip = resolve_ipv4(domain)
    rep = req.reply()
    if ip:
        rep.add_answer(RR(domain, rdata=A(ip), ttl=60))
    send_enc(conn, aes, rep.pack())
    return True

def handle_client(conn: socket.socket, priv) -> None:
    try:
        header = read_line(conn)
        if not header:
            return
        try:
            cmd, klen_s = header.decode().strip().split()
            if cmd != CMD_INIT:
                conn.sendall(SECDNS_ABORT)
                return
            klen = int(klen_s)
        except Exception:
            conn.sendall(SECDNS_ABORT)
            return
        blob = recv_exact(conn, klen)
        if not blob:
            conn.sendall(SECDNS_ABORT)
            return
        try:
            sk = rsa_decrypt(priv, blob)
        except Exception:
            conn.sendall(SECDNS_ABORT)
            return
        conn.sendall(SECDNS_READY)
        aes = AESGCM(sk)
        while handle_fetch(conn, aes):
            pass
    finally:
        conn.close()

def main() -> None:
    priv = load_private_key(PRIVKEY_PATH)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(16)
    print(f"[SECDNS] Server listening on {HOST}:{PORT}")
    while True:
        conn, _ = s.accept()
        handle_client(conn, priv)

if __name__ == "__main__":
    main()
