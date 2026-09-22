from transformers import pipeline

# при первом запуске модель скачается автоматически
ner = pipeline(
    "ner",
    model="Babelscape/wikineural-multilingual-ner",
    aggregation_strategy="simple",
)

def mask_pii(text):
    entities = ner(text)
    for ent in sorted(entities, key=lambda e: e["start"], reverse=True):
        if ent["entity_group"] == "PER":
            label = "[ИМЯ]"
        elif ent["entity_group"] == "LOC":
            label = "[АДРЕС]"
        else:
            continue
        text = text[:ent["start"]] + label + text[ent["end"]:]
    return text, entities


if __name__ == "__main__":
    sample = "Меня зовут Иван Петров, я живу в Москве на Тверской улице."
    masked, found = mask_pii(sample)

    print("Найдено:", found)
    print("Результат:", masked)
