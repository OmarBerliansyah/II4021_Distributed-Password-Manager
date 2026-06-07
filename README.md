# II4021 Distributed Password Manager

A distributed password manager with client-server architecture implementing zero-knowledge principles.

## Description

This is a CLI-based password manager that stores encrypted vaults on a server while keeping all cryptographic operations on the client side. The master key is split using Shamir Secret Sharing (2,3) scheme for enhanced security and backup recovery.

## Features

- **Zero-Knowledge Architecture**: Server only stores encrypted data, never sees plaintext
- **AES-128-GCM Encryption**: For vault and local share encryption
- **Shamir Secret Sharing (2,3)**: Master key split into 3 shares with threshold 2
- **PBKDF2 Key Derivation**: For deriving secondary key from master password
- **CSPRNG Password Generator**: For secure automatic password generation
- **Two Access Modes**:
  - **Normal Mode**: Using Local Share + Server Share
  - **Backup Mode**: Using Local Share + Recovery Share (read-only)
- **Bonus**: Visual Cryptography for Recovery Share (optional)

## Tech Stack

- **Language**: Python 3.11+
- **CLI Framework**: Typer + Rich
- **Server**: FastAPI + Uvicorn
- **Database**: SQLite3
- **Cryptography**: `cryptography` library

## Project Structure

```
distributed-password-manager/
├── client/                 # Client-side code
│   ├── __init__.py
│   ├── main.py            # CLI entry point
│   ├── api_client.py      # HTTP client for server
│   ├── crypto_utils.py    # Cryptographic utilities
│   ├── shamir.py          # Shamir Secret Sharing implementation
│   ├── local_store.py     # Local file storage handler
│   ├── vault.py           # Vault operations
│   ├── password_generator.py
│   └── visual_crypto.py   # Bonus: Visual cryptography
├── server/                 # Server-side code
│   ├── __init__.py
│   ├── app.py             # FastAPI application
│   ├── db.py              # Database operations
│   └── schema.sql         # Database schema
├── tests/                  # Test suite
│   ├── test_crypto.py
│   ├── test_shamir.py
│   ├── test_vault.py
│   └── test_integration.py
├── requirements.txt
├── README.md
└── laporan/               # Report deliverables
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Start the Server

```bash
uvicorn server.app:app --host 127.0.0.1 --port 8010 --reload
```

### Environment / Configuration

- `DPM_SERVER_URL`: client API base URL. Default: `http://127.0.0.1:8010`.
- `DPM_DB_PATH`: SQLite database path. Default: `server/vaults.db`.

### Client Commands

**Initialize a new vault:**
```bash
python -m client.main init
```

**Login (Normal Mode):**
```bash
python -m client.main login
```

**Add password entry:**
```bash
python -m client.main add
```

**List all entries:**
```bash
python -m client.main list
```

**Edit entry:**
```bash
python -m client.main edit
```

**Delete entry:**
```bash
python -m client.main delete
```

**Generate secure password:**
```bash
python -m client.main generate-password
```

## Security Notes

- Master key is never stored in its entirety
- Server never receives plaintext vault contents
- Recovery share is only displayed once during initialization
- Backup mode is read-only to prevent version conflicts
- Each encryption operation uses a fresh nonce

## Team Members

- Atharizza Muhammad Athaya - 18223075
- Muhammad Omar Berliansyah - 18223055
- Ferro Arka Berlian - 18223027
