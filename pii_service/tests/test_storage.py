"""
Тесты storage.py на отдельной тестовой БД (TEST_DATABASE_URL).
Если переменная не задана, тесты пропускаются.
"""

import os

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet

import config
import storage

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"),
        reason="TEST_DATABASE_URL не задан — тесты storage пропущены",
    ),
]


@pytest_asyncio.fixture(autouse=True)
async def _fresh_storage(monkeypatch):
    """Перед каждым тестом: своя БД-подключение и свой ключ шифрования, таблица очищена."""
    monkeypatch.setenv("DATABASE_URL", os.environ.get("TEST_DATABASE_URL", ""))
    monkeypatch.setenv("PII_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))

    if storage._pool is not None:
        await storage._pool.close()
    storage._pool = None
    storage._fernet = None

    await storage.init_db()
    pool = await storage._get_pool()
    async with pool.connection() as conn:
        await conn.execute("DELETE FROM pii_requests")
        await conn.commit()

    yield

    if storage._pool is not None:
        await storage._pool.close()
    storage._pool = None
    storage._fernet = None


async def test_save_and_load_roundtrip():
    await storage.save_request("req-1", "Иван Петров, ИНН 500100732259", "[ФИО_1], ИНН [ИНН_1]")
    result = await storage.load_request("req-1")
    assert result == "Иван Петров, ИНН 500100732259"


async def test_overwrite_existing_request_id():
    await storage.save_request("req-2", "первый текст", "маска1")
    await storage.save_request("req-2", "второй текст", "маска2")
    result = await storage.load_request("req-2")
    assert result == "второй текст"


async def test_missing_request_returns_none():
    result = await storage.load_request("не-существует")
    assert result is None


async def test_expired_request_returns_none():
    await storage.save_request("req-3", "старый текст", "маска")
    pool = await storage._get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            "UPDATE pii_requests SET created_at = now() - %s * interval '1 day' WHERE request_id = %s",
            (config.RETENTION_DAYS + 1, "req-3"),
        )
        await conn.commit()

    result = await storage.load_request("req-3")
    assert result is None


async def test_delete_expired_counts_and_removes():
    await storage.save_request("req-4", "текст 4", "маска4")
    await storage.save_request("req-5", "текст 5", "маска5")

    pool = await storage._get_pool()
    async with pool.connection() as conn:
        await conn.execute(
            "UPDATE pii_requests SET created_at = now() - %s * interval '1 day' WHERE request_id = %s",
            (config.RETENTION_DAYS + 1, "req-4"),
        )
        await conn.commit()

    deleted = await storage.delete_expired()

    assert deleted >= 1
    assert await storage.load_request("req-4") is None
    assert await storage.load_request("req-5") == "текст 5"
