"""
Хранение пар (исходный текст / маскированный текст) для последующей демаскировки.

init_text шифруется в приложении (cryptography.Fernet, ключ из PII_ENCRYPTION_KEY)
и хранится в БД только в зашифрованном виде; masked_text хранится открытым текстом,
т.к. содержит только токены вида [ФИО_1].
"""

import os
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet, InvalidToken
from psycopg_pool import AsyncConnectionPool

from config import RETENTION_DAYS

_INIT_SQL_PATH = os.path.join(os.path.dirname(__file__), "..", "sql", "init.sql")

_pool = None
_fernet = None


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("Не задана переменная окружения DATABASE_URL")
    return url


async def _get_pool() -> AsyncConnectionPool:
    global _pool
    if _pool is None:
        pool = AsyncConnectionPool(_database_url(), open=False)
        await pool.open()
        _pool = pool
    return _pool


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        key = os.environ.get("PII_ENCRYPTION_KEY")
        if not key:
            raise RuntimeError("Не задана переменная окружения PII_ENCRYPTION_KEY")
        _fernet = Fernet(key.encode("ascii") if isinstance(key, str) else key)
    return _fernet


async def init_db() -> None:
    """Создаёт таблицу pii_requests, если её ещё нет (sql/init.sql)."""
    with open(_INIT_SQL_PATH, "r", encoding="utf-8") as f:
        sql = f.read()

    pool = await _get_pool()
    async with pool.connection() as conn:
        await conn.execute(sql)
        await conn.commit()


async def save_request(request_id: str, init_text: str, masked_text: str) -> None:
    """Сохраняет пару (исходный/маскированный текст). Если request_id уже есть — перезаписывает."""
    encrypted_init_text = _get_fernet().encrypt(init_text.encode("utf-8"))

    pool = await _get_pool()
    try:
        async with pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO pii_requests (request_id, init_text, masked_text, created_at)
                VALUES (%s, %s, %s, now())
                ON CONFLICT (request_id) DO UPDATE
                SET init_text = EXCLUDED.init_text,
                    masked_text = EXCLUDED.masked_text,
                    created_at = EXCLUDED.created_at
                """,
                (request_id, encrypted_init_text, masked_text),
            )
            await conn.commit()
    except Exception as exc:
        raise RuntimeError(f"Не удалось сохранить запись request_id={request_id!r}") from exc


async def load_request(request_id: str) -> str | None:
    """Возвращает расшифрованный исходный текст по request_id, либо None (нет записи или истёк срок хранения)."""
    pool = await _get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT init_text, created_at FROM pii_requests WHERE request_id = %s",
                (request_id,),
            )
            row = await cur.fetchone()
        await conn.commit()

    if row is None:
        return None

    encrypted_init_text, created_at = row
    if created_at < datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS):
        return None

    try:
        decrypted = _get_fernet().decrypt(encrypted_init_text)
    except InvalidToken:
        raise RuntimeError(f"Не удалось расшифровать запись request_id={request_id!r}") from None

    return decrypted.decode("utf-8")


async def delete_expired() -> int:
    """Удаляет записи старше RETENTION_DAYS. Возвращает количество удалённых строк."""
    pool = await _get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "DELETE FROM pii_requests WHERE created_at < now() - %s * interval '1 day'",
                (RETENTION_DAYS,),
            )
            deleted = cur.rowcount
        await conn.commit()
    return deleted


async def ping() -> bool:
    """Проверка доступности БД (для /health). Не бросает исключения — возвращает False при любой ошибке."""
    try:
        pool = await _get_pool()
        async with pool.connection() as conn:
            await conn.execute("SELECT 1")
            await conn.commit()
        return True
    except Exception:
        return False


async def close_pool() -> None:
    """Закрывает пул соединений (вызывается при остановке приложения)."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
