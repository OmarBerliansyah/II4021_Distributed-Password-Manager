CREATE TABLE IF NOT EXISTS vaults (
    user_id TEXT PRIMARY KEY,
    server_share TEXT NOT NULL,
    vault_ciphertext BLOB NOT NULL,
    vault_nonce TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
