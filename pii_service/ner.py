"""
Поиск ФИО и адресов локальной BERT-моделью (NER) и сборка полного адреса
из находок regex (POSTCODE/STREET/HOUSE/FLAT) и NER (CITY/COUNTRY).

Модель работает офлайн, загружается один раз через load_ner_model().
"""

import re

from transformers import pipeline

from config import COUNTRIES, NER_MAX_TOKENS, NER_MIN_SCORE, NER_MODEL_NAME, get_pii_type

# части, из которых собирается ADDRESS в build_addresses
_ADDRESS_PART_TYPES = {"COUNTRY", "POSTCODE", "CITY", "STREET", "HOUSE", "FLAT"}

_SENTENCE_END_RE = re.compile(r"[.!?]+(?=\s|$)|\n")

_ner_pipeline = None


# --------------------------------------------------------------- загрузка модели

def load_ner_model():
    """Загружает NER-модель один раз и кэширует её в модуле; повторные вызовы отдают кэш."""
    global _ner_pipeline
    if _ner_pipeline is None:
        _ner_pipeline = pipeline(
            "ner",
            model=NER_MODEL_NAME,
            aggregation_strategy="simple",
        )
    return _ner_pipeline


def is_loaded() -> bool:
    """Загружена ли модель (для /health)."""
    return _ner_pipeline is not None


# ------------------------------------------------------------ разбиение на куски

def split_sentences(text: str) -> list:
    """Границы предложений в исходном тексте (по .!? и переносам строк), без пропусков."""
    sentences = []
    start = 0
    for match in _SENTENCE_END_RE.finditer(text):
        end = match.end()
        if text[start:end].strip():
            sentences.append((start, end))
        start = end
    if start < len(text) and text[start:].strip():
        sentences.append((start, len(text)))
    return sentences


def split_into_chunks(text: str, max_tokens: int = NER_MAX_TOKENS) -> list:
    """Группирует предложения в куски не длиннее ~max_tokens слов.

    Возвращает список (chunk_text, offset), где offset — позиция куска в исходном тексте
    (нужна, чтобы пересчитать start/end находок модели обратно в координаты text).
    """
    sentences = split_sentences(text)
    if not sentences:
        return [(text, 0)] if text.strip() else []

    chunks = []
    chunk_start = sentences[0][0]
    chunk_end = chunk_start
    chunk_word_count = 0

    for start, end in sentences:
        words = len(text[start:end].split())
        if chunk_word_count and chunk_word_count + words > max_tokens:
            chunks.append((text[chunk_start:chunk_end], chunk_start))
            chunk_start = start
            chunk_word_count = 0
        chunk_word_count += words
        chunk_end = end

    chunks.append((text[chunk_start:chunk_end], chunk_start))
    return chunks


# --------------------------------------------------------------------- находки

def _word_stem(word: str) -> str:
    """Отбрасывает окончание слова (1-3 символа), чтобы сравнивать разные падежи ("России" ~ "Россия")."""
    word = word.strip(",.;:!?").lower()
    if len(word) > 6:
        return word[:-3]
    if len(word) > 4:
        return word[:-2]
    return word


def is_country(value: str) -> bool:
    """Похоже ли значение LOC-сущности на название страны из COUNTRIES (с учётом падежа)."""
    value_stems = [_word_stem(word) for word in value.split()]
    if not value_stems:
        return False
    for country in COUNTRIES:
        country_stems = [_word_stem(word) for word in country.split()]
        if len(country_stems) != len(value_stems):
            continue
        if all(v.startswith(c) or c.startswith(v) for v, c in zip(value_stems, country_stems)):
            return True
    return False


def find_ner(text: str) -> list:
    """Ищет ФИО и адреса моделью: PER -> FULL_NAME, LOC -> CITY/COUNTRY. ORG пропускает."""
    ner_pipeline = load_ner_model()
    full_name_type = get_pii_type("FULL_NAME")
    city_type = get_pii_type("CITY")
    country_type = get_pii_type("COUNTRY")

    findings = []
    for chunk_text, offset in split_into_chunks(text):
        for entity in ner_pipeline(chunk_text):
            if entity["score"] < NER_MIN_SCORE:
                continue

            group = entity["entity_group"]
            if group not in ("PER", "LOC"):
                continue

            start = offset + entity["start"]
            end = offset + entity["end"]

            if group == "PER":
                pii_type = full_name_type
            else:
                pii_type = country_type if is_country(text[start:end]) else city_type

            findings.append({
                "type": pii_type["type"],
                "start": start,
                "end": end,
                "value": text[start:end],
                "score": float(entity["score"]),
                "source": "ner",
            })

    return findings


def find_organizations(text: str) -> list:
    """Ищет организации (ORG) моделью — для фильтра контекста, не для маскирования."""
    ner_pipeline = load_ner_model()

    findings = []
    for chunk_text, offset in split_into_chunks(text):
        for entity in ner_pipeline(chunk_text):
            if entity["entity_group"] != "ORG" or entity["score"] < NER_MIN_SCORE:
                continue
            start = offset + entity["start"]
            end = offset + entity["end"]
            findings.append({
                "type": "ORG",
                "start": start,
                "end": end,
                "value": text[start:end],
                "score": float(entity["score"]),
                "source": "ner",
            })

    return findings


# ------------------------------------------------------------------- адрес целиком

def is_adjacent(text: str, prev: dict, nxt: dict, max_gap_words: int = 3) -> bool:
    """Не больше max_gap_words слов (в т.ч. знаков препинания) между концом prev и началом nxt."""
    gap = text[prev["end"]:nxt["start"]]
    return len(gap.split()) <= max_gap_words


def build_addresses(text: str, findings: list) -> list:
    """Склеивает соседние части адреса (COUNTRY/POSTCODE/CITY/STREET/HOUSE/FLAT) в находки ADDRESS.

    Части, которые не оказались рядом с другими частями адреса, возвращаются как есть.
    Остальные находки (не относящиеся к адресу) проходят через функцию без изменений.
    """
    address_parts = sorted(
        (f for f in findings if f["type"] in _ADDRESS_PART_TYPES),
        key=lambda f: f["start"],
    )
    other = [f for f in findings if f["type"] not in _ADDRESS_PART_TYPES]

    groups = []
    current_group = []
    for part in address_parts:
        if current_group and not is_adjacent(text, current_group[-1], part):
            groups.append(current_group)
            current_group = []
        current_group.append(part)
    if current_group:
        groups.append(current_group)

    result = list(other)
    for group in groups:
        if len(group) == 1:
            result.append(group[0])
            continue

        start = min(part["start"] for part in group)
        end = max(part["end"] for part in group)
        result.append({
            "type": "ADDRESS",
            "start": start,
            "end": end,
            "value": text[start:end],
            "score": max(part["score"] for part in group),
            "source": "merged",
            "parts": [{"type": part["type"], "value": part["value"]} for part in group],
        })

    result.sort(key=lambda f: f["start"])
    return result
