import re
import json
from Levenshtein import ratio as levenshtein_distance


def create_json(file_path, title, text):
    json_object = {"title": title, "text": text}

    with open(file_path, "w", encoding='utf-8') as json_file:
        json.dump(json_object, json_file, ensure_ascii=False, indent=4)
