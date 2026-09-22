"""
Ручная проверка сервиса: несколько строк-примеров прогоняются через маскирование.
Запуск: python check.py
"""

import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, "pii_service")

import context
import masking
import ner
import patterns

TEXTS = [
    "Меня зовут Иван Петров, мой email ivan.petrov@example.com, телефон +7 912 345-67-89.",
    "Заявитель Иван Петрович Петров, ИНН 500100732259, карта 4532 0151 1283 0366, CVV 123.",
    "Проживаю по адресу: г. Москва, ул. Тверская, дом 5, кв. 12, индекс 125009.",
    "поэт Александр Пушкин написал много стихов.",
    "отделение банка на ул. Ленина, д. 10.",
]

TEXTS = [
    "я Пушкин Сергей 18.02.1990 рождения",
    "я эм е.ф. 18.02.1990 рождения",
    "я Пушкин А.Ф. 1990.02.18 рождения",
]


def run_pipeline(text: str) -> tuple:
    """Прогоняет текст через весь пайплайн поиска и маскирования ПДн."""
    regex_findings = patterns.find_regex(text)
    ner_findings = ner.find_ner(text)
    organizations = ner.find_organizations(text)
    addressed = ner.build_addresses(text, regex_findings + ner_findings)
    merged = context.merge(addressed)
    final = context.apply_context(text, merged, organizations)
    return masking.mask(text, final)


if __name__ == "__main__":
    print("Загрузка модели...")
    ner.load_ner_model()

    for text in TEXTS:
        masked_text, mapping = run_pipeline(text)
        print("\nИСХОДНЫЙ:  ", text)
        print("МАСКИРОВАН:", masked_text)
        if mapping:
            print("MAPPING:   ", mapping)
