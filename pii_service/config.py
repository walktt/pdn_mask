"""
Конфигурация сервиса маскирования ПДн: типы персональных данных, их регулярки,
ключевые слова контекста, валидаторы и пороги.

Чтобы добавить новый тип ПДн, достаточно добавить словарь в PII_TYPES
(и, при необходимости, функцию-валидатор в patterns.py).
"""

# сколько слов слева и справа от находки учитывается как "контекст"
CONTEXT_WINDOW = 7

# порог score, ниже которого находка отбрасывается
MIN_SCORE = 0.5

# прибавка к base_score, если рядом с находкой встретилось ключевое слово
CONTEXT_BONUS = 0.3

# NER-модель для поиска ФИО и адресов (метки PER/LOC/ORG), уже скачана и офлайн
NER_MODEL_NAME = "Babelscape/wikineural-multilingual-ner"

# порог score модели, ниже которого находка не засчитывается
NER_MIN_SCORE = 0.5

# примерный лимит слов на кусок текста при разбиении для NER
NER_MAX_TOKENS = 400

# устройство для инференса NER-модели: "cpu" (по умолчанию) или "dml" (GPU через DirectML,
# для запуска нужен run_gpu.py и requirements-gpu.txt — см. README по GPU-запуску)
NER_DEVICE = "cpu"

# размер пула соединений к Postgres (storage.py) — под нагрузку с большим RPS
DB_POOL_MIN_SIZE = 4
DB_POOL_MAX_SIZE = 20

# сколько запросов может одновременно считать пайплайн (regex+NER) в threadpool (api.py).
# Проверено нагрузочным тестом на 100 потоках: 64 воркера дали РЕЗУЛЬТАТ ХУЖЕ (8.99 RPS),
# чем дефолт asyncio min(32, cpu_count+4) (11.59 RPS) — узкое место GIL, не размер пула,
# больше потоков просто добавляет накладные расходы на переключение контекста.
PIPELINE_EXECUTOR_WORKERS = 12

# подключение к БД и ключ шифрования (storage.py) — раньше брались из переменных окружения
DATABASE_URL = "postgresql://astro:astro@localhost:5433/astro"
PII_ENCRYPTION_KEY = "RcS8tVtsHahCFUpUaQaMetrYS3mTbye3WLDKAMCaXYY="

# сколько дней хранится запись в pii_requests (storage.py)
RETENTION_DAYS = 30

# страны для типа CITIZENSHIP (в т.ч. варианты написания РФ)
COUNTRIES = [
    "Российская Федерация", "Россия", "РФ",
    "Украина", "Беларусь", "Белоруссия",
    "Казахстан", "Узбекистан", "Таджикистан", "Туркменистан", "Киргизия",
    "Кыргызстан", "Армения", "Азербайджан", "Молдова", "Грузия",
    "Латвия", "Литва", "Эстония",
]

# маркеры "о себе / о конкретном человеке" — при наличии находка остаётся всегда (context.apply_context, п. а)
PERSONAL_MARKERS = [
    "я", "меня", "мне", "мой", "моя", "моё", "мои",
    "зовут", "фио", "клиент", "заявитель", "держатель",
    "проживаю", "зарегистрирован",
]

# стоп-лист публичных персон для FULL_NAME (сравнение без учёта регистра, по фамилии)
PUBLIC_PERSONS = [
    "Александр Пушкин", "Лев Толстой", "Фёдор Достоевский", "Антон Чехов",
    "Сергей Есенин", "Михаил Лермонтов", "Николай Гоголь", "Владимир Маяковский",
    "Юрий Гагарин", "Михаил Ломоносов", "Пётр Чайковский", "Дмитрий Менделеев",
]

# маркеры публичности рядом с ФИО из PUBLIC_PERSONS (context.apply_context, п. б)
PUBLICITY_MARKERS = [
    "поэт", "писатель", "композитор", "памятник", "музей",
    "произведение", "улица имени", "в честь",
]

# адресные маркеры перед именем — значит это часть названия улицы, а не ФИО (context.apply_context, п. в)
ADDRESS_NAME_MARKERS = [
    "ул.", "улица", "пр-т", "проспект", "пер.", "переулок",
    "ш.", "шоссе", "б-р", "бульвар", "пл.", "площадь",
]

# маркеры организации рядом с ADDRESS/CITY/STREET (context.apply_context, п. г)
ORG_MARKERS = ["отделение", "филиал", "офис", "банкомат", "банк", "тц", "магазин", "музей"]

# общая регулярка даты: любой порядок дд/мм/гггг (дд.мм.гггг, мм.дд.гггг, гггг.дд.мм, ...)
# или "12 марта 1990"; конкретную раскладку определяет patterns._interpret_numeric_date
_DATE_PATTERN = (
    r"\b\d{1,4}[./]\d{1,4}[./]\d{1,4}\b"
    r"|"
    r"\b\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|июля|"
    r"августа|сентября|октября|ноября|декабря)\s+\d{4}\b"
)

PII_TYPES = [
    {
        "type": "FULL_NAME",
        "label": "ФИО",
        "pattern": None,  # ищется моделью NER (ner.py)
        "keywords": [],
        "validator": None,
        "base_score": 0.6,
        "needs_context": False,
    },
    {
        "type": "BIRTH_DATE",
        "label": "Дата рождения",
        "pattern": _DATE_PATTERN,
        "keywords": ["родился", "родилась", "д.р.", "дата рождения"],
        "validator": "date_check",
        "base_score": 0.5,
        "needs_context": True,
    },
    {
        "type": "BIRTH_PLACE",
        "label": "Место рождения",
        "pattern": None,  # ищется по триггерам в patterns.find_birth_place
        "keywords": ["место рождения", "родился в", "родилась в", "уроженец"],
        "validator": None,
        "base_score": 0.6,
        "needs_context": True,
    },
    {
        "type": "PASSPORT",
        "label": "Паспорт",
        "pattern": (
            r"\b\d{2}\s?\d{2}\s?\d{6}\b"  # "45 12 345678" / "4512 345678" / "4512345678"
            r"|"
            r"серия\s*№?\s*:?\s*\d{2}\s?\d{2}\s*,?\s*(?:и\s*)?номер\s*№?\s*:?\s*\d{6}"  # "серия XXXX номер XXXXXX"
        ),
        "keywords": ["паспорт", "серия", "номер паспорта"],
        "validator": None,
        "base_score": 0.5,
        "needs_context": True,
    },
    {
        "type": "CITIZENSHIP",
        "label": "Гражданство",
        "pattern": None,  # ищется по триггерам + COUNTRIES в patterns.find_citizenship
        "keywords": ["гражданство", "гражданин", "гражданка"],
        "validator": None,
        "base_score": 0.6,
        "needs_context": True,
    },
    {
        "type": "PASSPORT_ISSUER",
        "label": "Кем выдан",
        "pattern": None,  # ищется по триггеру "выдан" в patterns.find_passport_issuer
        "keywords": ["овд", "увд", "уфмс", "гу мвд", "мвд", "отделом", "отделением"],
        "validator": None,
        "base_score": 0.6,
        "needs_context": True,
    },
    {
        "type": "DIVISION_CODE",
        "label": "Код подразделения",
        "pattern": r"\b\d{3}-\d{3}\b",
        "keywords": ["код подразделения", "к/п"],
        "validator": None,
        "base_score": 0.5,
        "needs_context": True,
    },
    {
        "type": "PASSPORT_ISSUE_DATE",
        "label": "Дата выдачи паспорта",
        "pattern": _DATE_PATTERN,
        "keywords": ["выдан", "дата выдачи"],
        "validator": "date_check",
        "base_score": 0.5,
        "needs_context": True,
    },
    {
        "type": "DRIVER_LICENSE",
        "label": "Водительское удостоверение",
        "pattern": r"\b\d{2}\s?[0-9A-Za-zА-Яа-я]{2}\s?\d{6}\b",
        "keywords": ["ву", "водительское", "удостоверение", "права"],
        "validator": None,
        "base_score": 0.5,
        "needs_context": True,
    },
    {
        "type": "ADDRESS",
        "label": "Адрес",
        "pattern": None,  # собирается из STREET/HOUSE/FLAT в context.py
        "keywords": [],
        "validator": None,
        "base_score": 0.5,
        "needs_context": False,
    },
    {
        "type": "COUNTRY",
        "label": "Страна",
        "pattern": None,  # ищется моделью NER / как часть адреса
        "keywords": [],
        "validator": None,
        "base_score": 0.5,
        "needs_context": False,
    },
    {
        "type": "POSTCODE",
        "label": "Индекс",
        "pattern": r"\b\d{6}\b",
        "keywords": [
            "индекс", "почтовый индекс", "адрес", "город", "область",
            "край", "россия", "ул.", "улица",
        ],
        "validator": None,
        "base_score": 0.4,
        "needs_context": True,
    },
    {
        "type": "CITY",
        "label": "Город",
        "pattern": None,  # ищется моделью NER / как часть адреса
        "keywords": [],
        "validator": None,
        "base_score": 0.5,
        "needs_context": False,
    },
    {
        "type": "STREET",
        "label": "Улица",
        "pattern": (
            r"(?:ул\.|улица|пр-т|проспект|пер\.|переулок|ш\.|шоссе|"
            r"б-р|бульвар|пл\.|площадь)\s+[А-ЯЁA-Z][\wё-]*"
            r"(?:\s+[А-ЯЁA-Zа-яёA-Za-z-]+){0,3}"
        ),
        "keywords": ["адрес", "проживает", "зарегистрирован"],
        "validator": None,
        "base_score": 0.6,
        "needs_context": False,
    },
    {
        "type": "HOUSE",
        "label": "Дом",
        "pattern": r"(?:дом|д\.|корп\.|к\.|стр\.)\s?\d+[а-яА-Я]?",
        "keywords": ["адрес"],
        "validator": None,
        "base_score": 0.5,
        "needs_context": False,
    },
    {
        "type": "FLAT",
        "label": "Квартира",
        "pattern": r"(?:кв\.|квартира)\s?\d+",
        "keywords": ["адрес"],
        "validator": None,
        "base_score": 0.5,
        "needs_context": False,
    },
    {
        "type": "EMAIL",
        "label": "Email",
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "keywords": [],
        "validator": None,
        "base_score": 0.9,
        "needs_context": False,
    },
    {
        "type": "PHONE",
        "label": "Телефон",
        "pattern": (
            r"(?<!\d)(?:\+7|8|7)[\s\-]?\(?\d{3}\)?[\s\-]?"
            r"\d{3}[\s\-]?\d{2}[\s\-]?\d{2}(?!\d)"
        ),
        "keywords": [],
        "validator": None,
        "base_score": 0.85,
        "needs_context": False,
    },
    {
        "type": "INN",
        "label": "ИНН",
        "pattern": r"\b\d{12}\b",
        "keywords": ["инн"],
        "validator": "inn_check",
        "base_score": 0.7,
        "needs_context": False,
    },
    {
        "type": "CARD_NUMBER",
        "label": "Номер карты",
        "pattern": r"\b(?:\d[ \-]?){15,18}\d\b",
        "keywords": ["карта", "card", "номер карты"],
        "validator": "luhn_check",
        "base_score": 0.8,
        "needs_context": False,
    },
    {
        "type": "CVV",
        "label": "CVV",
        "pattern": r"\b\d{3}\b",
        "keywords": ["cvv", "cvc", "cvv2"],
        "validator": None,
        "base_score": 0.3,
        "needs_context": True,
    },
    {
        "type": "PIN",
        "label": "PIN-код",
        "pattern": r"\b\d{4}\b",
        "keywords": ["пин", "pin"],
        "validator": None,
        "base_score": 0.3,
        "needs_context": True,
    },
    {
        "type": "CARDHOLDER",
        "label": "Держатель карты",
        "pattern": r"\b[A-Za-z]{2,}\s+[A-Za-z]{2,}\b",
        "keywords": ["держатель", "cardholder", "имя на карте", "карта"],
        "validator": None,
        "base_score": 0.4,
        "needs_context": True,
    },
]


def get_pii_type(type_code: str) -> dict:
    """Достаёт словарь типа из PII_TYPES по коду типа."""
    for pii_type in PII_TYPES:
        if pii_type["type"] == type_code:
            return pii_type
    raise KeyError(type_code)
