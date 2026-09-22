"""
Тесты маскирования: главное проверяемое свойство —
unmask(*mask(text, findings)) == text для любого текста.
"""

import context
import masking
import ner
import patterns


def _build_findings(text):
    """Полный пайплайн поиска ПДн, как в api.py: regex + NER -> адреса -> merge -> фильтр контекста."""
    regex_findings = patterns.find_regex(text)
    ner_findings = ner.find_ner(text)
    organizations = ner.find_organizations(text)
    addressed = ner.build_addresses(text, regex_findings + ner_findings)
    merged = context.merge(addressed)
    return context.apply_context(text, merged, organizations)


TEXTS = [
    "Меня зовут Иван Петров, мой email ivan.petrov@example.com, телефон +7 912 345-67-89.",
    "Заявитель Иван Петрович Петров, ИНН 500100732259, карта 4532 0151 1283 0366, CVV 123.",
    "Проживаю по адресу: г. Москва, ул. Тверская, дом 5, кв. 12, индекс 125009.",
    "Текст без единого ПДн.",
]


def test_roundtrip_various_texts():
    for text in TEXTS:
        findings = _build_findings(text)
        masked_text, mapping = masking.mask(text, findings)
        assert masking.unmask(masked_text, mapping) == text


def test_same_value_gets_same_token():
    text = "Иван Петров и Иван Петров — одно и то же имя дважды."
    findings = _build_findings(text)
    masked_text, mapping = masking.mask(text, findings)

    assert masked_text.count("[ФИО_1]") == 2
    assert "[ФИО_2]" not in masked_text
    assert masking.unmask(masked_text, mapping) == text


def test_unmask_on_different_text():
    text = "Мой ИНН 500100732259."
    findings = _build_findings(text)
    masked_text, mapping = masking.mask(text, findings)
    token = next(iter(mapping))
    value = mapping[token]

    external_response = f"Обработали запрос, ваш номер {token} подтверждён."
    result = masking.unmask(external_response, mapping)

    assert token not in result
    assert value in result


def test_unknown_token_left_as_is():
    text = "Текст с [НЕИЗВЕСТНЫЙ_1] токеном."
    assert masking.unmask(text, {}) == text
