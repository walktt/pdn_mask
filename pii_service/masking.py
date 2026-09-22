"""
Маскирование находок токенами вида [ФИО_1], [ИНН_1] и обратная замена.
"""

from config import get_pii_type


def _normalize(value: str) -> str:
    """Приводит значение к виду для сравнения "одно и то же значение": lower(), без пробелов и дефисов."""
    return value.lower().replace(" ", "").replace("-", "")


def mask(text: str, findings: list) -> tuple:
    """Заменяет находки токенами [МЕТКА_N]. Одинаковое (после нормализации) значение одного типа
    получает один и тот же токен. Возвращает (masked_text, mapping), mapping — {токен: исходное значение}.
    """
    ordered = sorted(findings, key=lambda f: f["start"])

    token_by_key = {}
    counters = {}
    mapping = {}
    token_by_finding_id = {}

    for finding in ordered:
        label = get_pii_type(finding["type"])["label"]
        key = (finding["type"], _normalize(finding["value"]))

        token = token_by_key.get(key)
        if token is None:
            counters[finding["type"]] = counters.get(finding["type"], 0) + 1
            token = f"[{label}_{counters[finding['type']]}]"
            token_by_key[key] = token
            mapping[token] = finding["value"]

        token_by_finding_id[id(finding)] = token

    masked_text = text
    for finding in sorted(ordered, key=lambda f: f["start"], reverse=True):
        token = token_by_finding_id[id(finding)]
        masked_text = masked_text[:finding["start"]] + token + masked_text[finding["end"]:]

    return masked_text, mapping


def unmask(masked_text: str, mapping: dict) -> str:
    """Заменяет токены обратно на исходные значения. Токены не из mapping остаются как есть.
    Работает на любом тексте, содержащем эти токены, не только на результате mask().
    """
    result = masked_text
    for token, value in mapping.items():
        result = result.replace(token, value)
    return result
