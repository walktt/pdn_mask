"""
FastAPI-сервис: единый эндпоинт POST /process маскирует персональные данные
при первом обращении с новым payload_id и демаскирует — при повторном.
"""

import json
import logging
import time
import uuid
from collections import Counter
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import context
import masking
import ner
import patterns
import storage

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("pii_service")


class ProcessRequest(BaseModel):
    payload: str
    payload_id: str


class ProcessResponse(BaseModel):
    result: str


def run_pipeline(text: str) -> tuple:
    """Полный пайплайн поиска и маскирования ПДн. Возвращает (masked_text, mapping, findings)."""
    regex_findings = patterns.find_regex(text)
    ner_findings = ner.find_ner(text)
    organizations = ner.find_organizations(text)
    addressed = ner.build_addresses(text, regex_findings + ner_findings)
    merged = context.merge(addressed)
    final = context.apply_context(text, merged, organizations)
    masked_text, mapping = masking.mask(text, final)
    return masked_text, mapping, final


def _log_request(endpoint: str, found_types: dict, duration_ms: int) -> None:
    logger.info(json.dumps({
        "request_id": uuid.uuid4().hex,
        "endpoint": endpoint,
        "found_types": found_types,
        "duration_ms": duration_ms,
    }, ensure_ascii=False))


@asynccontextmanager
async def lifespan(app: FastAPI):
    ner.load_ner_model()
    await storage.init_db()
    yield
    await storage.close_pool()


app = FastAPI(title="Модуль безопасности ПДн", lifespan=lifespan)


@app.post("/process", response_model=ProcessResponse)
async def process(body: ProcessRequest) -> ProcessResponse:
    start = time.monotonic()

    existing = await storage.load_request(body.payload_id)
    if existing is not None:
        duration_ms = int((time.monotonic() - start) * 1000)
        _log_request("/process", {}, duration_ms)
        return ProcessResponse(result=existing)

    masked_text, _mapping, findings = run_pipeline(body.payload)
    await storage.save_request(body.payload_id, body.payload, masked_text)

    found_types = dict(Counter(finding["type"] for finding in findings))
    duration_ms = int((time.monotonic() - start) * 1000)
    _log_request("/process", found_types, duration_ms)

    return ProcessResponse(result=masked_text)


@app.get("/health")
async def health():
    model_loaded = ner.is_loaded()
    db_ok = await storage.ping()
    ok = model_loaded and db_ok

    payload = {
        "status": "ok" if ok else "error",
        "model_loaded": model_loaded,
        "database": "ok" if db_ok else "unavailable",
    }
    return JSONResponse(status_code=200 if ok else 503, content=payload)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(json.dumps({"endpoint": request.url.path, "error": type(exc).__name__}, ensure_ascii=False))
    return JSONResponse(status_code=500, content={"detail": "internal error"})
