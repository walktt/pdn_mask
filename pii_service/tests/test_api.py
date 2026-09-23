"""
Тесты api.py через TestClient. storage подменяется на in-memory фейк —
реальный Postgres не нужен, проверяется только логика эндпоинта.
NER-модель используется настоящая (она уже локально закэширована).
"""

import pytest
from fastapi.testclient import TestClient

import api
import storage


@pytest.fixture
def client(monkeypatch):
    fake_db = {}

    async def fake_init_db():
        return None

    async def fake_close_pool():
        return None

    async def fake_save_request(request_id, init_text, masked_text, duration_ms=0):
        fake_db[request_id] = init_text

    async def fake_load_request(request_id):
        return fake_db.get(request_id)

    async def fake_ping():
        return True

    monkeypatch.setattr(storage, "init_db", fake_init_db)
    monkeypatch.setattr(storage, "close_pool", fake_close_pool)
    monkeypatch.setattr(storage, "save_request", fake_save_request)
    monkeypatch.setattr(storage, "load_request", fake_load_request)
    monkeypatch.setattr(storage, "ping", fake_ping)

    with TestClient(api.app) as test_client:
        yield test_client


def test_mask_then_unmask_roundtrip(client):
    payload = "Меня зовут Иван Петров, мой email ivan.petrov@example.com"
    payload_id = "test-roundtrip-1"

    first = client.post("/process", json={"payload": payload, "payload_id": payload_id})
    assert first.status_code == 200
    masked = first.json()["result"]
    assert masked != payload
    assert "[ФИО_1]" in masked

    second = client.post("/process", json={"payload": masked, "payload_id": payload_id})
    assert second.status_code == 200
    assert second.json()["result"] == payload


def test_text_without_pii_passes_through(client):
    payload = "Текст без единого ПДн."
    payload_id = "test-no-pii"

    response = client.post("/process", json={"payload": payload, "payload_id": payload_id})
    assert response.status_code == 200
    assert response.json()["result"] == payload


def test_health_ok(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body == {"status": "ok", "model_loaded": True, "database": "ok"}


def test_health_db_down(client, monkeypatch):
    async def fake_ping_fail():
        return False

    monkeypatch.setattr(storage, "ping", fake_ping_fail)

    response = client.get("/health")
    assert response.status_code == 503
    assert response.json()["status"] == "error"


def test_missing_field_returns_422(client):
    response = client.post("/process", json={"payload": "текст"})
    assert response.status_code == 422
