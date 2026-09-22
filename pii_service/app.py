"""
FastAPI-сервис, реализующий контракт /process (Приложение A ТЗ):
единый эндпоинт, направление (маскирование/демаскирование) определяется
состоянием payload_id в Redis. Идемпотентен по payload_id (ретраи безопасны).
"""

import json
import logging
import os
import sys

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import redis

sys.path.insert(0, os.path.dirname(__file__))
import context
import masking
import ner
import patterns

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("pdn_mask")

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
STATE_TTL_SECONDS = int(os.environ.get("STATE_TTL_SECONDS", "3600"))

app = FastAPI(title="PDN Mask Service")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)


@app.on_event("startup")
def startup() -> None:
    logger.info("Loading NER model...")
    ner.load_ner_model()
    logger.info("NER model loaded")


class ProcessRequest(BaseModel):
    payload: str
    payload_id: str


class ProcessResponse(BaseModel):
    result: str


def run_masking_pipeline(text: str):
    regex_findings = patterns.find_regex(text)
    ner_findings = ner.find_ner(text)
    organizations = ner.find_organizations(text)
    addressed = ner.build_addresses(text, regex_findings + ner_findings)
    merged = context.merge(addressed)
    final = context.apply_context(text, merged, organizations)
    return masking.mask(text, final)


def _state_key(payload_id: str) -> str:
    return f"pdn:{payload_id}"


def _token_types(mapping: dict) -> list:
    types = set()
    for token in mapping.keys():
        inner = token.strip("[]")
        types.add(inner.rsplit("_", 1)[0])
    return sorted(types)


@app.post("/process", response_model=ProcessResponse)
def process(req: ProcessRequest):
    key = _state_key(req.payload_id)
    raw = redis_client.get(key)

    if raw is None:
        # Первый запрос с этим payload_id -> маскирование
        try:
            masked_text, mapping = run_masking_pipeline(req.payload)
        except Exception:
            logger.exception("mask_error payload_id=%s", req.payload_id)
            raise HTTPException(status_code=500, detail="internal masking error")

        logger.info(
            "payload_id=%s step=mask types=%s entities=%d",
            req.payload_id, _token_types(mapping), len(mapping),
        )

        state = {"status": "masked", "result": masked_text, "mapping": mapping}
        redis_client.setex(key, STATE_TTL_SECONDS, json.dumps(state))
        return ProcessResponse(result=masked_text)

    state = json.loads(raw)

    if state["status"] == "masked":
        if req.payload == state["result"]:
            # ретрай шага маскирования — отдаём тот же результат
            return ProcessResponse(result=state["result"])

        # Второй запрос с этим payload_id -> демаскирование
        try:
            unmasked_text = masking.unmask(req.payload, state["mapping"])
        except Exception:
            logger.exception("unmask_error payload_id=%s", req.payload_id)
            raise HTTPException(status_code=500, detail="internal unmasking error")

        logger.info("payload_id=%s step=unmask", req.payload_id)
        state["status"] = "unmasked"
        state["result"] = unmasked_text
        redis_client.setex(key, STATE_TTL_SECONDS, json.dumps(state))
        return ProcessResponse(result=unmasked_text)

    # status == "unmasked" -> ретрай шага демаскирования
    return ProcessResponse(result=state["result"])


@app.exception_handler(Exception)
def unhandled_exception_handler(request, exc):
    logger.exception("unhandled_error path=%s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "internal error"})


@app.get("/health")
def health():
    try:
        redis_client.ping()
    except Exception:
        raise HTTPException(status_code=503, detail="redis unavailable")
    return {"status": "ok"}
