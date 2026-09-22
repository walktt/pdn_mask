"""
Объединение находок regex/NER (merge) и фильтр по контексту (apply_context):
решает, действительно ли находка — персональные данные конкретного человека,
или это, например, публичная персона, часть названия улицы или адрес организации.
"""

from config import (
    ADDRESS_NAME_MARKERS,
    ORG_MARKERS,
    PERSONAL_MARKERS,
    PUBLIC_PERSONS,
    PUBLICITY_MARKERS,
)
from ner import is_adjacent
from patterns import get_context, has_keyword

_ADDRESS_TYPES = ("ADDRESS", "CITY", "STREET")


# --------------------------------------------------------------------- merge

def merge(findings: list) -> list:
    """Убирает дубли и пересечения находок.

    Находки рассматриваются от самой длинной к самой короткой (при равной
    длине — от большего score к меньшему); находка остаётся, только если она
    не пересекается ни с одной уже оставленной. Части, вошедшие в ADDRESS,
    всегда лежат внутри его span и поэтому отбрасываются этим же правилом —
    отдельной проверки на "parts" не требуется.
    """
    ordered = sorted(findings, key=lambda f: (-(f["end"] - f["start"]), -f["score"]))
    kept = []
    for finding in ordered:
        overlaps = any(
            finding["start"] < other["end"] and other["start"] < finding["end"]
            for other in kept
        )
        if not overlaps:
            kept.append(finding)
    kept.sort(key=lambda f: f["start"])
    return kept


# --------------------------------------------------------------- apply_context

def _has_personal_marker(text: str, finding: dict) -> bool:
    context = get_context(text, finding["start"], finding["end"])
    return has_keyword(context, PERSONAL_MARKERS)


def _surname(full_name: str) -> str:
    words = full_name.split()
    return words[-1].lower() if words else ""


def _is_public_person(value: str) -> bool:
    value_surname = _surname(value)
    if not value_surname:
        return False
    return any(_surname(person) == value_surname for person in PUBLIC_PERSONS)


def _is_public_person_mention(text: str, finding: dict) -> bool:
    if not _is_public_person(finding["value"]):
        return False
    context = get_context(text, finding["start"], finding["end"])
    return has_keyword(context, PUBLICITY_MARKERS)


def _is_address_name(text: str, finding: dict) -> bool:
    """Стоит ли находка сразу после адресного маркера (ул., пр-т, ...) — тогда это не ФИО."""
    before = text[:finding["start"]].rstrip()
    for marker in ADDRESS_NAME_MARKERS:
        if not before.lower().endswith(marker):
            continue
        prefix_len = len(before) - len(marker)
        if prefix_len == 0 or not before[prefix_len - 1].isalpha():
            return True
    return False


def _near_organization(text: str, finding: dict, org: dict) -> bool:
    if finding["start"] < org["end"] and org["start"] < finding["end"]:
        return True
    if finding["end"] <= org["start"]:
        return is_adjacent(text, finding, org)
    return is_adjacent(text, org, finding)


def _is_organization_context(text: str, finding: dict, organizations: list) -> bool:
    context = get_context(text, finding["start"], finding["end"])
    if has_keyword(context, ORG_MARKERS):
        return True
    return any(_near_organization(text, finding, org) for org in organizations)


def apply_context(text: str, findings: list, organizations: list) -> list:
    """Решает для каждой находки, персональные ли это данные. Порядок проверки строго фиксирован (см. docstring модуля)."""
    result = []

    for finding in findings:
        if _has_personal_marker(text, finding):
            result.append(finding)
            continue

        if finding["type"] == "FULL_NAME":
            if _is_public_person_mention(text, finding):
                continue
            if _is_address_name(text, finding):
                continue
            result.append(finding)
            continue

        if finding["type"] in _ADDRESS_TYPES:
            if _is_organization_context(text, finding, organizations):
                continue
            result.append(finding)
            continue

        result.append(finding)

    return result
