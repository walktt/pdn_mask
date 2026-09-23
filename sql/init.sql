CREATE SCHEMA IF NOT EXISTS pii_masker;

CREATE TABLE IF NOT EXISTS pii_masker.pii_requests (
    request_id   text PRIMARY KEY,
    init_text    bytea NOT NULL,       -- исходный текст, зашифрован Fernet (ключ не хранится в БД)
    masked_text  text NOT NULL,
    duration_ms  integer NOT NULL DEFAULT 0,  -- время обработки запроса маскирования, целые мс
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- на случай, если таблица уже существовала без этой колонки (безопасно перезапускать)
ALTER TABLE pii_masker.pii_requests ADD COLUMN IF NOT EXISTS duration_ms integer NOT NULL DEFAULT 0;
