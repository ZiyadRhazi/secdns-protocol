# SECDNS — Secure DNS Resolution Protocol

SECDNS is a lightweight cryptographic enhancement to DNS that ensures:
- **Confidentiality** (AES-256-GCM encrypted queries)
- **Integrity** (GCM authentication tags)
- **Server Authenticity** (RSA-2048 OAEP handshake)

This project implements both:
- `secdns-server.py` — The SECDNS authoritative server
- `secdns-resolver.py` — The SECDNS client resolver


---

## 🔐 Features

- RSA-based session initialization (public key handshake)
- AES-GCM encrypted DNS queries and responses
- Replay protection using unique nonces
- End-to-end confidentiality and integrity
- TCP transport to eliminate side-channel leaks
- Small and practical proof-of-concept implementation

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/secdns.git
cd secdns
