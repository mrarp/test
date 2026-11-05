#!/usr/bin/env python3
"""
01 — Сбор эндпоинтов Websoft HCM.

Авторизуется Bearer-токеном и собирает поверхность атаки из нескольких источников:
  1. robots.txt / sitemap.xml
  2. Discovery API-спеки: swagger / openapi / api-docs
  3. BFS-обход HTML-страниц: <a href>, <form action>, <link>, <iframe src>
  4. Парсинг JS-бандлов фронта: вытягивает строковые пути и вызовы
     fetch/axios/XMLHttpRequest — там, где у SPA зашиты маршруты API
  5. Проба известных для WebTutor/Websoft HCM путей (кандидаты, помечаются source=seed)

Результат: endpoints.json — список объектов {url, method, source, content_type, status}.

Запуск:  python 01_endpoint_collector.py
"""
import json
import re
import sys
import time
from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup

try:
    import config
except ImportError:
    sys.exit("Нет config.py — скопируйте config.example.py в config.py и заполните.")


# --- Кандидатные пути, типичные для WebTutor / Websoft HCM ------------------
# Это НЕ гарантированный список — платформа конфигурируется под заказчика.
# Коллектор только проверяет, какие из них реально отвечают на вашем инстансе.
SEED_PATHS = [
    "/", "/default.html", "/default.asp", "/index.html",
    "/robots.txt", "/sitemap.xml",
    # Вероятные корни API (Bearer-токен → скорее всего REST/JSON)
    "/api/", "/api/v1/", "/api/v2/", "/rest/", "/odata/",
    # Discovery спеки
    "/swagger", "/swagger/index.html", "/swagger.json",
    "/swagger/v1/swagger.json", "/openapi.json", "/api-docs", "/api/docs",
    # Характерные разделы портала WebTutor
    "/catalog/", "/user/", "/users/", "/profile/",
    "/report/", "/reports/", "/olap/",
    "/search/", "/search.html",
    "/upload/", "/download/", "/file/", "/files/",
    "/news/", "/wiki/", "/forum/", "/poll/", "/test/", "/course/",
    # Служебные/внутренние пространства имён WebTutor вида /_wt/, /_ad/, /_ssp/
    "/_wt/", "/_ssp/", "/_api/",
]

# Регэкспы для вытаскивания путей из JS-бандлов.
_JS_PATH_RE = re.compile(r"""["'`](/(?:api|rest|odata|_wt|_api|_ssp|catalog|user|report|search|file|upload|download)[A-Za-z0-9_\-/.?=&{}:]*)["'`]""")
_JS_FETCH_RE = re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|\.open)\(\s*["'`]([^"'`]+)["'`]""")
_JS_TEMPLATE_RE = re.compile(r"""["'`](https?://[^"'`]+|/[A-Za-z0-9_\-/.]+\$\{[^}]+\}[A-Za-z0-9_\-/.?=&]*)["'`]""")


def build_session() -> requests.Session:
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


def allowed_hosts() -> set:
    hosts = set(h.lower() for h in (config.ALLOWED_HOSTS or []))
    if not hosts:
        hosts.add(urlparse(config.BASE_URL).netloc.lower())
    return hosts


def in_scope(url: str, hosts: set) -> bool:
    try:
        p = urlparse(url)
    except ValueError:
        return False
    if p.scheme not in ("http", "https"):
        return False
    if p.netloc.lower() not in hosts:
        return False
    low = url.lower()
    return not any(bad in low for bad in config.DENY_SUBSTRINGS)


def fetch(session, url, method="GET"):
    time.sleep(config.REQUEST_DELAY)
    try:
        r = session.request(method, url, timeout=config.TIMEOUT, allow_redirects=True)
        return r
    except requests.RequestException as e:
        print(f"  [!] {method} {url} -> {e}")
        return None


def extract_from_html(base_url, html):
    """Ссылки, формы и подключённые скрипты со страницы."""
    found, scripts = set(), set()
    soup = BeautifulSoup(html, "lxml")
    for tag, attr in (("a", "href"), ("form", "action"), ("link", "href"),
                      ("iframe", "src"), ("area", "href")):
        for el in soup.find_all(tag):
            val = el.get(attr)
            if val:
                found.add(urldefrag(urljoin(base_url, val))[0])
    for s in soup.find_all("script", src=True):
        scripts.add(urljoin(base_url, s["src"]))
    return found, scripts


def extract_from_js(base_url, js_text):
    """Пути, зашитые в JS-бандле фронта."""
    found = set()
    for rx in (_JS_PATH_RE, _JS_FETCH_RE, _JS_TEMPLATE_RE):
        for m in rx.findall(js_text):
            path = m if isinstance(m, str) else m[0]
            if path.startswith("http") or path.startswith("/"):
                found.add(urljoin(base_url, urldefrag(path)[0]))
    return found


def try_openapi(session, base, hosts, endpoints):
    """Если найдётся OpenAPI/Swagger — вытащить все пути прямо из спеки."""
    for path in ("/swagger/v1/swagger.json", "/swagger.json",
                 "/openapi.json", "/api-docs", "/v3/api-docs"):
        url = urljoin(base, path)
        if not in_scope(url, hosts):
            continue
        r = fetch(session, url)
        if not r or r.status_code != 200:
            continue
        try:
            spec = r.json()
        except ValueError:
            continue
        paths = spec.get("paths", {})
        if not paths:
            continue
        print(f"  [+] OpenAPI найден: {url} ({len(paths)} путей)")
        server = ""
        if isinstance(spec.get("servers"), list) and spec["servers"]:
            server = spec["servers"][0].get("url", "")
        for p, methods in paths.items():
            full = urljoin(base, (server.rstrip("/") + p) if server else p)
            for method in methods:
                if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    endpoints[(full, method.upper())] = {
                        "url": full, "method": method.upper(),
                        "source": "openapi", "content_type": "application/json",
                        "status": None, "openapi": methods[method],
                    }
        return True
    return False


def main():
    base = config.BASE_URL.rstrip("/")
    hosts = allowed_hosts()
    session = build_session()
    endpoints = {}   # (url, method) -> record

    print(f"[*] Цель: {base}  |  scope: {', '.join(hosts)}")

    # 0) OpenAPI/Swagger — самый богатый источник, если доступен
    try_openapi(session, base, hosts, endpoints)

    # 1) Очередь BFS засеваем base + известными путями
    queue = deque()
    seen = set()
    for p in SEED_PATHS:
        u = urljoin(base + "/", p.lstrip("/"))
        if in_scope(u, hosts):
            queue.append((u, 0))

    js_files = set()
    pages_visited = 0

    while queue and pages_visited < config.CRAWL_MAX_PAGES:
        url, depth = queue.popleft()
        key = url.rstrip("/")
        if key in seen:
            continue
        seen.add(key)

        r = fetch(session, url)
        if r is None:
            continue
        pages_visited += 1
        ctype = r.headers.get("Content-Type", "").split(";")[0].strip()

        endpoints.setdefault((url, "GET"), {
            "url": url, "method": "GET", "source": "crawl",
            "content_type": ctype, "status": r.status_code,
        })
        print(f"  [{r.status_code}] {url}  ({ctype})")

        # robots/sitemap — вытаскиваем Disallow и <loc>
        if url.endswith("robots.txt") and r.status_code == 200:
            for line in r.text.splitlines():
                if ":" in line and line.lower().startswith(("allow", "disallow")):
                    p = line.split(":", 1)[1].strip()
                    if p:
                        cand = urljoin(base, p)
                        if in_scope(cand, hosts) and cand.rstrip("/") not in seen:
                            queue.append((cand, depth + 1))
        if "xml" in ctype and "sitemap" in url:
            for loc in re.findall(r"<loc>([^<]+)</loc>", r.text):
                if in_scope(loc, hosts) and loc.rstrip("/") not in seen:
                    queue.append((loc, depth + 1))

        # HTML — ссылки, формы, скрипты
        if "html" in ctype and r.status_code == 200 and depth < config.CRAWL_MAX_DEPTH:
            links, scripts = extract_from_html(url, r.text)
            js_files |= {s for s in scripts if in_scope(s, hosts)}
            for link in links:
                if in_scope(link, hosts) and link.rstrip("/") not in seen:
                    queue.append((link, depth + 1))

    # 2) Разбор JS-бандлов
    print(f"[*] JS-бандлов к разбору: {len(js_files)}")
    for js_url in sorted(js_files):
        r = fetch(session, js_url)
        if not r or r.status_code != 200:
            continue
        for ep in extract_from_js(base, r.text):
            if in_scope(ep, hosts):
                endpoints.setdefault((ep, "GET"), {
                    "url": ep, "method": "GET", "source": "js",
                    "content_type": None, "status": None,
                })

    records = list(endpoints.values())
    with open(config.ENDPOINTS_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)

    by_src = {}
    for r in records:
        by_src[r["source"]] = by_src.get(r["source"], 0) + 1
    print(f"\n[✓] Собрано {len(records)} эндпоинтов -> {config.ENDPOINTS_FILE}")
    print("    по источникам: " + ", ".join(f"{k}={v}" for k, v in by_src.items()))


if __name__ == "__main__":
    main()
