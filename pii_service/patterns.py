"""
Поиск персональных данных в тексте регулярными выражениями и их валидация.

Основная функция — find_regex(text): прогоняет все "простые" типы из
PII_TYPES (regex + опциональный валидатор + опциональная проверка контекста)
и несколько типов со специальной логикой (даты, кем выдан, место рождения,
гражданство, держатель карты), которые нельзя свести к одному regex.
"""

import re
from datetime import date

from config import COUNTRIES, CONTEXT_BONUS, CONTEXT_WINDOW, MIN_SCORE, PII_TYPES, get_pii_type

# типы, для которых поиск не сводится к find_simple
_CUSTOM_TYPES = {
    "BIRTH_DATE", "PASSPORT_ISSUE_DATE", "PASSPORT_ISSUER",
    "BIRTH_PLACE", "CITIZENSHIP", "CARDHOLDER",
}

_MONTHS_RU = {
    "января": 1, "февраля": 2, "марта": 3, "апреля": 4, "мая": 5, "июня": 6,
    "июля": 7, "августа": 8, "сентября": 9, "октября": 10, "ноября": 11, "декабря": 12,
}

_NUMERIC_DATE_RE = re.compile(r"\b(\d{1,2})[./](\d{1,2})[./](\d{2,4})\b")
_TEXT_DATE_RE = re.compile(
    r"\b(\d{1,2})\s+(" + "|".join(_MONTHS_RU.keys()) + r")\s+(\d{4})\b",
    re.IGNORECASE,
)
_ISSUER_TRIGGER_RE = re.compile(r"выдан[аоы]?\b\s*:?\s*", re.IGNORECASE)
_STOP_AFTER_ISSUER_RE = re.compile(r"\d{1,2}[./]\d{1,2}[./]\d{2,4}|[.,\n]")
_STOP_AT_PUNCT_RE = re.compile(r"[.,\n]")
_CARD_LOOSE_RE = re.compile(r"\d[\d\s\-]{14,22}\d")

_BIRTH_PLACE_TRIGGERS = ["место рождения", "родился в", "родилась в", "уроженец"]
_CITIZENSHIP_TRIGGERS = ["гражданство", "гражданин", "гражданка"]
_CITIZENSHIP_LOOKAHEAD = 40  # символов вперёд от триггера, где ищем страну


# ---------------------------------------------------------------- валидаторы

def luhn_check(value: str) -> bool:
    """Проверка номера карты алгоритмом Луна. value — строка с цифрами (могут быть пробелы/дефисы)."""
    digits = [int(c) for c in value if c.isdigit()]
    if not (16 <= len(digits) <= 19):
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def inn_check(value: str) -> bool:
    """Проверка контрольных цифр 12-значного ИНН физлица."""
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) != 12:
        return False

    def control(weights, nums):
        return sum(w * n for w, n in zip(weights, nums)) % 11 % 10

    n11 = control([7, 2, 4, 10, 3, 5, 9, 4, 6, 8], digits[:10])
    n12 = control([3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8], digits[:11])
    return digits[10] == n11 and digits[11] == n12


def date_check(day: int, month: int, year: int) -> bool:
    """Проверка, что day/month/year — существующая календарная дата в разумном диапазоне лет."""
    if not (1900 <= year <= date.today().year + 1):
        return False
    try:
        date(year, month, day)
    except ValueError:
        return False
    return True


_VALIDATORS = {"luhn_check": luhn_check, "inn_check": inn_check}


# ------------------------------------------------------------------ утилиты

def strip_span(text: str, start: int, end: int) -> tuple:
    """Обрезает пробелы по краям спана, сохраняя text[start:end] корректным."""
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


def get_context(text: str, start: int, end: int, window: int = CONTEXT_WINDOW) -> str:
    """Строка из window слов слева и window слов справа от находки, в нижнем регистре."""
    left_words = text[:start].split()[-window:]
    right_words = text[end:].split()[:window]
    return " ".join(left_words + right_words).lower()


def has_keyword(context: str, keywords: list) -> bool:
    """Есть ли хотя бы одно ключевое слово (без учёта регистра) в строке контекста.

    Совпадение засчитывается, только если слева и справа от найденной подстроки
    нет букв — иначе короткие ключевые слова (например, "ву") ложно находятся
    внутри других слов ("зоВУт").
    """
    for keyword in keywords:
        kw = keyword.lower()
        idx = context.find(kw)
        while idx != -1:
            before_ok = idx == 0 or not context[idx - 1].isalpha()
            after_pos = idx + len(kw)
            after_ok = after_pos >= len(context) or not context[after_pos].isalpha()
            if before_ok and after_ok:
                return True
            idx = context.find(kw, idx + 1)
    return False


def compute_score(base_score: float, matched_keyword: bool) -> float:
    """base_score + бонус за контекст, не больше 1.0."""
    bonus = CONTEXT_BONUS if matched_keyword else 0
    return min(base_score + bonus, 1.0)


def make_finding(pii_type: dict, text: str, start: int, end: int, matched_keyword: bool) -> dict:
    """Собирает словарь-находку по границам спана в исходном тексте."""
    start, end = strip_span(text, start, end)
    value = text[start:end]
    score = compute_score(pii_type["base_score"], matched_keyword)
    return {
        "type": pii_type["type"],
        "start": start,
        "end": end,
        "value": value,
        "score": score,
        "source": "regex",
    }


# ------------------------------------------------------- поиск простых типов

def find_simple(text: str, pii_type: dict) -> list:
    """Общий поиск для типов с обычной regex: находит, валидирует, проверяет контекст, считает score."""
    findings = []
    if not pii_type["pattern"]:
        return findings

    for match in re.finditer(pii_type["pattern"], text, re.IGNORECASE):
        start, end = strip_span(text, match.start(), match.end())
        value = text[start:end]
        if not value:
            continue

        validator_name = pii_type["validator"]
        if validator_name and not _VALIDATORS[validator_name](value):
            continue

        context = get_context(text, start, end)
        matched_keyword = has_keyword(context, pii_type["keywords"])
        if pii_type["needs_context"] and not matched_keyword:
            continue

        score = compute_score(pii_type["base_score"], matched_keyword)
        if score < MIN_SCORE:
            continue

        findings.append({
            "type": pii_type["type"],
            "start": start,
            "end": end,
            "value": value,
            "score": score,
            "source": "regex",
        })

    return findings


# ------------------------------------------------------- поиск сложных типов

def find_dates(text: str) -> list:
    """Ищет даты (числовые и текстовые), по контексту относит их к BIRTH_DATE или PASSPORT_ISSUE_DATE."""
    birth_type = get_pii_type("BIRTH_DATE")
    issue_type = get_pii_type("PASSPORT_ISSUE_DATE")

    candidates = []
    for match in _NUMERIC_DATE_RE.finditer(text):
        day, month, year = int(match.group(1)), int(match.group(2)), int(match.group(3))
        if year < 100:
            current = date.today().year % 100
            year += 2000 if year <= current else 1900
        candidates.append((match.start(), match.end(), day, month, year))

    for match in _TEXT_DATE_RE.finditer(text):
        day = int(match.group(1))
        month = _MONTHS_RU[match.group(2).lower()]
        year = int(match.group(3))
        candidates.append((match.start(), match.end(), day, month, year))

    findings = []
    for start, end, day, month, year in candidates:
        if not date_check(day, month, year):
            continue

        context = get_context(text, start, end)
        is_birth = has_keyword(context, birth_type["keywords"])
        is_issue = has_keyword(context, issue_type["keywords"])
        if not is_birth and not is_issue:
            continue

        pii_type = birth_type if is_birth else issue_type
        finding = make_finding(pii_type, text, start, end, matched_keyword=True)
        if finding["score"] < MIN_SCORE:
            continue
        findings.append(finding)

    return findings


def find_passport_issuer(text: str) -> list:
    """Текст после "выдан" до даты/точки/конца строки, если в нём есть маркер выдавшего органа."""
    pii_type = get_pii_type("PASSPORT_ISSUER")
    findings = []

    for trigger in _ISSUER_TRIGGER_RE.finditer(text):
        tail_start = trigger.end()
        tail = text[tail_start:]
        stop = _STOP_AFTER_ISSUER_RE.search(tail)
        value_end = tail_start + (stop.start() if stop else len(tail))

        start, end = strip_span(text, tail_start, value_end)
        value = text[start:end]
        if not value or not has_keyword(value.lower(), pii_type["keywords"]):
            continue

        finding = make_finding(pii_type, text, start, end, matched_keyword=True)
        if finding["score"] < MIN_SCORE:
            continue
        findings.append(finding)

    return findings


def find_birth_place(text: str) -> list:
    """Текст после "место рождения"/"родился в"/"уроженец" до запятой/точки/конца строки."""
    pii_type = get_pii_type("BIRTH_PLACE")
    findings = []

    for trigger in _BIRTH_PLACE_TRIGGERS:
        trigger_re = re.compile(re.escape(trigger) + r"\s*:?\s*", re.IGNORECASE)
        for match in trigger_re.finditer(text):
            tail_start = match.end()
            tail = text[tail_start:]
            stop = _STOP_AT_PUNCT_RE.search(tail)
            value_end = tail_start + (stop.start() if stop else len(tail))

            start, end = strip_span(text, tail_start, value_end)
            value = text[start:end]
            if not value:
                continue

            finding = make_finding(pii_type, text, start, end, matched_keyword=True)
            if finding["score"] < MIN_SCORE:
                continue
            findings.append(finding)

    return findings


def find_citizenship(text: str) -> list:
    """"Гражданство"/"гражданин"/"гражданка" + ближайшее название страны из COUNTRIES."""
    pii_type = get_pii_type("CITIZENSHIP")
    findings = []

    for trigger in _CITIZENSHIP_TRIGGERS:
        trigger_re = re.compile(re.escape(trigger) + r"\w*", re.IGNORECASE)
        for match in trigger_re.finditer(text):
            tail = text[match.end():match.end() + _CITIZENSHIP_LOOKAHEAD]
            for country in COUNTRIES:
                country_match = re.search(r"\b" + re.escape(country) + r"\b", tail, re.IGNORECASE)
                if not country_match:
                    continue

                start, end = strip_span(text, match.start(), match.end() + country_match.end())
                finding = make_finding(pii_type, text, start, end, matched_keyword=True)
                if finding["score"] < MIN_SCORE:
                    continue
                findings.append(finding)
                break

    return findings


def find_cardholder(text: str) -> list:
    """Два слова латиницей рядом с ключевым словом (держатель/cardholder) или номером карты."""
    pii_type = get_pii_type("CARDHOLDER")
    findings = []

    for match in re.finditer(pii_type["pattern"], text, re.IGNORECASE):
        start, end = strip_span(text, match.start(), match.end())
        context = get_context(text, start, end)
        matched_keyword = has_keyword(context, pii_type["keywords"]) or bool(_CARD_LOOSE_RE.search(context))
        if not matched_keyword:
            continue

        finding = make_finding(pii_type, text, start, end, matched_keyword=True)
        if finding["score"] < MIN_SCORE:
            continue
        findings.append(finding)

    return findings


# --------------------------------------------------------------- точка входа

def find_regex(text: str) -> list:
    """Ищет в тексте все ПДн, обнаруживаемые регулярками. Возвращает список находок, отсортированный по start."""
    findings = []

    for pii_type in PII_TYPES:
        if pii_type["type"] in _CUSTOM_TYPES or not pii_type["pattern"]:
            continue
        findings.extend(find_simple(text, pii_type))

    findings.extend(find_dates(text))
    findings.extend(find_passport_issuer(text))
    findings.extend(find_birth_place(text))
    findings.extend(find_citizenship(text))
    findings.extend(find_cardholder(text))

    findings.sort(key=lambda finding: finding["start"])
    return findings
