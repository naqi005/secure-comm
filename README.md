# Secure-Comm
A secure communication model that sends and receives encrypted messages, verifies authenticity, confidentiality, integrity and decrypts it.
# SecureComm

A two-party, end-to-end encrypted desktop messaging application built in Python. Every message is encrypted, integrity-checked, and digitally signed before it leaves the sender's machine. A built-in six-step **Envelope Inspector** lets you peel back each cryptographic layer in real time — designed as both a functional secure messenger and an educational tool for understanding applied cryptography.

---

## Features

- **RSA-2048 key exchange** — each session generates a fresh key pair; public keys are exchanged over the wire, private keys never leave the originating machine
- **AES-256-CBC message encryption** — a fresh 256-bit session key and a unique 16-byte IV per message prevent pattern analysis across traffic
- **RSA-OAEP key wrapping** — the AES session key is protected with OAEP+SHA-256, immune to Bleichenbacher-style chosen-ciphertext attacks
- **SHA-256 integrity verification** — every message carries a hash of the original plaintext; tampering is detected on receipt
- **RSA-PSS digital signatures** — the sender signs each message with their private key; recipients verify authenticity without a trusted third party
- **Six-step Envelope Inspector** — interactively decrypt and verify any received message layer by layer
- **Local file encryption** — encrypt and decrypt files on disk using the active AES session key
- **Wireshark-verifiable** — all TCP payload bytes are opaque binary; no plaintext is recoverable from a packet capture

---

## Requirements

- Python 3.9 or later
- [`cryptography`](https://cryptography.io/) library

```
pip install cryptography
```

Tkinter is included with the standard Python installer on Windows. On Linux install it with `sudo apt install python3-tk`.

---

## Usage

Both participants run the same file. No installation or server setup is required beyond allowing the port through the firewall.

### 1 — Launch and generate keys

```
python securecomm.py
```

On the startup screen click **Generate Keys**. Your RSA-2048 public key appears for inspection. Optionally click **Save Keys** to write `private_key.pem` and `public_key.pem` to a folder of your choice — you will need `private_key.pem` later for the Envelope Inspector.

Enter a display name and click **Continue**.

### 2 — Choose a role

**Machine A (Server)**
1. Select **Server**
2. Note the LAN IP shown on screen (e.g. `10.1.170.112`) — share it with the other participant
3. Click **Start as Server** — the status bar shows `Listening on :65432...`

**Machine B (Client)**
1. Select **Client**
2. Enter Machine A's IP address
3. Click **Connect as Client**

Both machines show `Connected ●` and the Send button enables once the full cryptographic handshake completes (usually under two seconds).

> **Firewall note:** On Windows, allow TCP inbound on port 65432 for the server machine. Run in an elevated PowerShell:
> ```
> netsh advfirewall firewall add rule name="SecureComm" dir=in action=allow protocol=TCP localport=65432
> ```

### 3 — Send messages

Type in the text field and press **Enter** or click **Send**. Each received message shows a green ✔ if both the SHA-256 integrity check and the RSA-PSS signature passed.

---

## Envelope Inspector

Switch to the **Envelope Inspector** tab after a message arrives. Work through the six sequential steps:

| Step | Action | What it shows |
|------|--------|---------------|
| 1 | Inspect Raw Envelope | Full JSON — all fields base64/hex encoded, no plaintext visible |
| 2 | Provide Private Key | Paste `private_key.pem` content (bare base64 is accepted too) |
| 3 | Decrypt AES Key | RSA-OAEP decryption → 64-character hex session key |
| 4 | Decrypt Message | AES-256-CBC + PKCS7 unpadding → original plaintext |
| 5 | Verify Integrity | SHA-256 recomputed → **MATCH** or **MISMATCH** |
| 6 | Verify Signature | RSA-PSS verify → **SIGNATURE VALID** or **SIGNATURE INVALID** |

---

## How It Works

```
Alice (Server)                          Naqi (Client)
──────────────────────────────────────────────────────
Generate RSA-2048 key pair              Generate RSA-2048 key pair
Bind TCP :65432, listen
                                        connect() → TCP 3-way handshake
Send { public_key, name } ──────────────────────────►
                ◄──────────────────────── Send { public_key, name }
                                        os.urandom(32) → AES session key
                                        RSA-OAEP wrap with Alice's pubkey
                ◄──────────────────────── Send wrapped AES key
Unwrap with private key
══════════════ Shared AES-256 session key established ══════════════

For each message:
  plaintext → SHA-256 hash
  plaintext → RSA-PSS sign (sender privkey)
  plaintext → AES-256-CBC encrypt (session key + fresh IV)
  session key → RSA-OAEP wrap (recipient pubkey)
  → JSON envelope → 4-byte length prefix → TCP send
```

All wire traffic is opaque binary. Wireshark or any packet capture tool will see only the length-prefixed ciphertext blobs.

---

## Security Notes

| Control | Status |
|---------|--------|
| Confidentiality (AES-256-CBC) | Fully addressed |
| Integrity (SHA-256) | Fully addressed |
| Sender authentication (RSA-PSS) | Fully addressed |
| Man-in-the-Middle (no PKI) | **Partial** — compare key fingerprints out-of-band |
| Replay attacks | **Partial** — timestamps present but no rejection window |
| Private key at rest | **Not addressed** — PEM files are unencrypted |

This application is designed for educational use on a trusted LAN. It is not a production messaging system.

---

## Project Structure

```
securecomm.py          Single-file application (crypto + networking + GUI)
private_key.pem        Generated on first run — keep this private
public_key.pem         Your RSA-2048 public key
```

---

## Built With

- [cryptography](https://cryptography.io/) — RSA-2048, AES-256-CBC, RSA-PSS, RSA-OAEP, SHA-256
- [Tkinter](https://docs.python.org/3/library/tkinter.html) — GUI
- Python standard library: `socket`, `threading`, `queue`, `json`, `hashlib`

---

## Authors

Muhammad Abdullah Kaleem · Muhammad Haris Zafar · Muhammad Ibrahim Gulzar · Muhammad Naqi Afaq

CY201 — Cybersecurity Principles · Ghulam Ishaq Khan Institute of Engineering Sciences and Technology · Spring 2025

## 👥 Group Members

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/mhariszaffar">
        <img src="https://github.com/mhariszaffar.png" width="100px;" alt="Haris"/>
        <br />
        <b>Muhammad Haris Zafar</b>
      </a>
      <br />
      <a href="https://github.com/mhariszaffar">github.com/mhariszaffar</a>
    </td>
    <td align="center">
      <a href="https://github.com/ibrahimcys">
        <img src="https://github.com/ibrahimcys.png" width="100px;" alt="Ibrahim"/>
        <br />
        <b>Muhammad Ibrahim</b>
      </a>
      <br />
      <a href="https://github.com/ibrahimcys">github.com/ibrahimcys</a>
    </td>
    <td align="center">
      <a href="https://github.com/naqi005">
        <img src="https://github.com/naqi005.png" width="100px;" alt="Naqi"/>
        <br />
        <b>Muhammad Naqi Afaq</b>
      </a>
      <br />
      <a href="https://github.com/naqi005">github.com/naqi005</a>
    </td>
    <td align="center">
      <a href="https://github.com/ibrahim-gulzar-11">
        <img src="https://github.com/ibrahim-gulzar-11.png" width="100px;" alt="Gulzar"/>
        <br />
        <b>Muhammad Ibrahim Gulzar</b>
      </a>
      <br />
      <a href="https://github.com/ibrahim-gulzar-11">github.com/ibrahim-gulzar-11</a>
    </td>
  </tr>
</table>
