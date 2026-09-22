CREATE TABLE IF NOT EXISTS pii_requests (
    request_id   text PRIMARY KEY,
    init_text    bytea NOT NULL,       -- исходный текст, зашифрован Fernet (ключ не хранится в БД)
    masked_text  text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);
