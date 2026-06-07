# II4021 Distributed Password Manager

Password manager terdistribusi berbasis CLI dengan arsitektur client-server dan prinsip zero-knowledge.

## Deskripsi

Program ini digunakan untuk menyimpan data akun pengguna di dalam vault terenkripsi. Seluruh proses kriptografi dilakukan di sisi klien, sedangkan server hanya menyimpan data terenkripsi dan data pendukung yang diperlukan untuk akses normal.

Vault dienkripsi menggunakan AES-128-GCM. Master key untuk membuka vault tidak disimpan secara utuh, tetapi dibagi menjadi tiga share menggunakan Shamir Secret Sharing dengan skema ambang batas (2, 3). Dengan skema ini, vault hanya dapat dibuka jika terdapat minimal dua share valid.

## Fitur

- **Arsitektur zero-knowledge**: server hanya menyimpan data terenkripsi dan tidak pernah menerima plaintext vault.
- **Enkripsi AES-128-GCM**: digunakan untuk mengenkripsi dan mendekripsi vault.
- **Shamir Secret Sharing (2, 3)**: master key dibagi menjadi local share, server share, dan recovery share.
- **PBKDF2-HMAC-SHA256**: digunakan untuk menurunkan kunci dari master password.
- **CSPRNG password generator**: digunakan untuk membangkitkan password otomatis yang aman.
- **Mode normal**: membuka vault menggunakan local share dan server share.
- **Mode backup**: membuka vault menggunakan local share dan recovery share ketika server tidak dapat diakses. Mode ini bersifat read-only.
- **Bonus opsional**: kriptografi visual untuk recovery share.

## Teknologi

- **Bahasa pemrograman**: Python 3.11+
- **CLI**: Typer dan Rich
- **Server**: FastAPI dan Uvicorn
- **Basis data**: SQLite3
- **Kriptografi**: pustaka `cryptography`
- **Pengujian**: Pytest

## Struktur Proyek

```text
distributed-password-manager/
|-- client/
|   |-- __init__.py
|   |-- main.py
|   |-- api_client.py
|   |-- crypto_utils.py
|   |-- shamir.py
|   |-- local_store.py
|   |-- vault.py
|   |-- password_generator.py
|   `-- visual_crypto.py
|-- server/
|   |-- __init__.py
|   |-- app.py
|   |-- db.py
|   `-- schema.sql
|-- tests/
|   |-- test_client_workflow.py
|   |-- test_crypto.py
|   |-- test_integration.py
|   |-- test_local_store.py
|   |-- test_password_generator.py
|   |-- test_shamir.py
|   `-- test_vault.py
|-- requirements.txt
`-- README.md
```

## Instalasi

```bash
pip install -r requirements.txt
```

## Konfigurasi

- `DPM_SERVER_URL`: alamat dasar API server. Nilai bawaan: `http://127.0.0.1:8010`.
- `DPM_DB_PATH`: lokasi berkas basis data SQLite. Nilai bawaan: `server/vaults.db`.
- `DPM_CLIENT_DIR`: lokasi penyimpanan data lokal klien. Nilai bawaan: `.vault_client`.

## Cara Menjalankan

### Menjalankan server

```bash
uvicorn server.app:app --host 127.0.0.1 --port 8010 --reload
```

### Membuat vault baru

```bash
python -m client.main init
```

Pada tahap ini, pengguna memasukkan user ID dan master password. Program akan menampilkan recovery share satu kali. Recovery share perlu disimpan secara mandiri oleh pengguna.

### Membuka vault pada mode normal

```bash
python -m client.main login
```

Mode normal menggunakan kombinasi local share dan server share.

### Menambahkan data password

```bash
python -m client.main add
```

Untuk membangkitkan password otomatis, gunakan opsi berikut.

```bash
python -m client.main add --generate --length 20
```

### Menampilkan isi vault

```bash
python -m client.main list
```

Secara bawaan, password tidak ditampilkan secara penuh. Untuk menampilkan password, gunakan opsi berikut.

```bash
python -m client.main list --show-passwords
```

### Mengubah data password

```bash
python -m client.main edit
```

### Menghapus data password

```bash
python -m client.main delete
```

### Membuat password otomatis

```bash
python -m client.main generate-password
```

### Membuka vault pada mode backup

```bash
python -m client.main backup
```

Mode backup menggunakan local share, recovery share, dan backup vault lokal terenkripsi. Mode ini hanya dapat digunakan untuk melihat data.

## Pengujian

Jalankan seluruh test dengan perintah berikut.

```bash
pytest -q
```

Jika Windows menolak akses folder temporary bawaan Pytest, gunakan folder temporary di dalam proyek.

```powershell
New-Item -ItemType Directory -Force .tmp | Out-Null
$env:TEMP=(Resolve-Path .tmp)
$env:TMP=$env:TEMP
pytest -q
```

## Catatan Keamanan

- Master key tidak pernah disimpan secara utuh.
- Server tidak menerima plaintext vault, master key, local share, recovery share, master password, atau kunci turunan.
- Local share disimpan dalam bentuk terenkripsi menggunakan kunci turunan dari master password.
- Recovery share hanya ditampilkan satu kali saat pembuatan vault.
- Setiap proses enkripsi menggunakan nonce baru.
- Mode backup bersifat read-only untuk menghindari konflik versi data.

## Anggota Kelompok

- Atharizza Muhammad Athaya - 18223079
- Muhammad Omar Berliansyah - 18223055
- Ferro Arka Berlian - 18223027
