#!/usr/bin/env python3
"""
02 — Карта полей пользовательского ввода.

Читает endpoints.json и для каждого эндпоинта определяет, КУДА можно подать ввод:
  - HTML-формы: <input>/<textarea>/<select> + их name, method, action
  - GET query-параметры: ?a=1&b=2  -> параметры a, b
  - OpenAPI parameters: query/path/header/body-поля из спеки
  - JSON-ответы API: поля верхнего уровня как кандидаты для тела запроса
    (эвристика — проверяется эхо-пробой: отправляем назад с маркером)

Результат: targets.json — плоский список точек инъекции:
  {url, method, param, location, content_type, source}
где location ∈ {query, form, json, path, header, body-sample}.

Запуск:  python 02_input_field_mapper.py
"""
import json
import sys
import time
from urllib.parse import urlparse, parse_qsl, urljoin

import requests
from bs4 import BeautifulSoup

try:
    import config
except ImportError:
    sys.exit("Нет config.py — скопируйте config.example.py в config.py и заполните.")


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


def fetch(session, url, method="GET"):
    time.sleep(config.REQUEST_DELAY)
    try:
        return session.request(method, url, timeout=config.TIMEOUT)
    except requests.RequestException as e:
        print(f"  [!] {method} {url} -> {e}")
        return None


def from_query(url):
    """Параметры из query-строки GET-эндпоинта."""
    targets = []
    q = urlparse(url).query
    for name, _ in parse_qsl(q, keep_blank_values=True):
        targets.append({
            "url": url, "method": "GET", "param": name,
            "location": "query", "content_type": None, "source": "query",
        })
    return targets


def from_forms(session, url):
    """Поля HTML-форм на странице."""
    targets = []
    r = fetch(session, url)
    if not r or "html" not in r.headers.get("Content-Type", "") or r.status_code != 200:
        return targets
    soup = BeautifulSoup(r.text, "lxml")
    for form in soup.find_all("form"):
        action = urljoin(url, form.get("action") or url)
        method = (form.get("method") or "GET").upper()
        enctype = form.get("enctype", "application/x-www-form-urlencoded")
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if not name:
                continue
            ftype = (field.get("type") or field.name).lower()
            if ftype in ("submit", "button", "image", "reset"):
                continue
            targets.append({
                "url": action, "method": method, "param": name,
                "location": "form", "content_type": enctype,
                "field_type": ftype, "source": "form",
            })
    return targets


def from_openapi(rec):
    """Параметры из OpenAPI-описания эндпоинта."""
    targets = []
    spec = rec.get("openapi") or {}
    for p in spec.get("parameters", []):
        loc = p.get("in", "query")
        name = p.get("name")
        if name:
            targets.append({
                "url": rec["url"], "method": rec["method"], "param": name,
                "location": loc, "content_type": None, "source": "openapi",
            })
    body = spec.get("requestBody", {})
    content = body.get("content", {}) if isinstance(body, dict) else {}
    for ctype, media in content.items():
        schema = media.get("schema", {})
        props = schema.get("properties", {})
        for prop in props:
            targets.append({
                "url": rec["url"], "method": rec["method"], "param": prop,
                "location": "json", "content_type": ctype, "source": "openapi",
            })
    return targets


def from_json_response(session, rec):
    """
    Для API-эндпоинта без спеки: берём поля JSON-ответа как кандидаты
    для JSON-тела (их часто принимает тот же роут на POST/PUT).
    """
    targets = []
    r = fetch(session, rec["url"])
    if not r or r.status_code >= 400:
        return targets
    if "json" not in r.headers.get("Content-Type", ""):
        return targets
    try:
        data = r.json()
    except ValueError:
        return targets
    sample = data[0] if isinstance(data, list) and data else data
    if isinstance(sample, dict):
        for key in sample.keys():
            targets.append({
                "url": rec["url"], "method": "POST", "param": key,
                "location": "json", "content_type": "application/json",
                "source": "json-sample",
            })
    return targets


def main():
    session = build_session()
    with open(config.ENDPOINTS_FILE, encoding="utf-8") as f:
        endpoints = json.load(f)

    targets, seen = [], set()

    def add(items):
        for t in items:
            k = (t["url"], t["method"], t["param"], t["location"])
            if k not in seen:
                seen.add(k)
                targets.append(t)

    for rec in endpoints:
        url = rec["url"]
        low = url.lower()
        if any(bad in low for bad in config.DENY_SUBSTRINGS):
            continue

        add(from_query(url))
        if rec.get("source") == "openapi":
            add(from_openapi(rec))

        ctype = (rec.get("content_type") or "")
        if "html" in ctype or rec.get("source") in ("crawl", "seed"):
            add(from_forms(session, url))
        if "json" in ctype or rec.get("source") in ("js", "openapi"):
            add(from_json_response(session, rec))

    with open(config.TARGETS_FILE, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)

    by_loc = {}
    for t in targets:
        by_loc[t["location"]] = by_loc.get(t["location"], 0) + 1
    print(f"[✓] Точек ввода: {len(targets)} -> {config.TARGETS_FILE}")
    print("    по расположению: " + ", ".join(f"{k}={v}" for k, v in by_loc.items()))


if __name__ == "__main__":
    main()
