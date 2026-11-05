#!/usr/bin/env python3
"""
04 — Подготовка целей для sqlmap.

Из targets.json (а при наличии — findings.json) формирует списки, которые
скармливаются sqlmap. Отдельно GET и отдельно POST/JSON, т.к. запускаются
по-разному.

Выходные файлы:
  sqlmap_targets.txt      — GET-URL c параметрами, по одному на строку
                            (для `sqlmap -m sqlmap_targets.txt`)
  sqlmap_post.sh          — готовые команды sqlmap для POST-форм и JSON-тел
                            (точка инъекции помечена '*')
  sqlmap_params.txt       — какие именно параметры тестировать (-p), справочно

Приоритет отдаётся точкам, по которым фаззер уже дал SQLi-кандидата.

Запуск:  python 04_make_sqlmap_targets.py
"""
import json
import os
import sys
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

try:
    import config
except ImportError:
    sys.exit("Нет config.py — скопируйте config.example.py в config.py и заполните.")


def load(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return []


def ensure_query_param(url, param):
    """Гарантируем, что параметр есть в query (иначе sqlmap нечего тестировать)."""
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    if param not in q:
        q[param] = "1"
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


def main():
    targets = load(config.TARGETS_FILE)
    findings = load(config.FINDINGS_FILE)

    # Точки, уже подсвеченные фаззером как SQLi — тестировать в первую очередь.
    hot = {(f["url"], f["method"], f["param"])
           for f in findings if f.get("category", "").startswith("sqli")}

    get_urls, get_params = [], {}
    post_cmds = []
    seen_get = set()

    hdr = f'Authorization: Bearer {config.BEARER_TOKEN}'

    # Сортируем так, чтобы «горячие» шли первыми.
    def is_hot(t):
        return (t["url"], t["method"], t["param"]) in hot
    targets = sorted(targets, key=lambda t: not is_hot(t))

    for t in targets:
        loc = t["location"]
        param = t["param"]
        method = t["method"].upper()
        url = t["url"]
        if any(b in url.lower() for b in config.DENY_SUBSTRINGS):
            continue

        if loc in ("query", "form") and method == "GET":
            full = ensure_query_param(url, param)
            if full not in seen_get:
                seen_get.add(full)
                get_urls.append(full)
            get_params.setdefault(full, set()).add(param)

        elif loc == "form" and method in ("POST", "PUT"):
            data = f"{param}=1*"            # '*' — точка инъекции для sqlmap
            post_cmds.append(_cmd(url, hdr, param, data=data))

        elif loc == "json":
            body = '{"%s": "1*"}' % param
            post_cmds.append(_cmd(url, hdr, param, json_body=body))

    # --- sqlmap_targets.txt (GET) ---
    with open(config.SQLMAP_TARGETS_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(get_urls) + ("\n" if get_urls else ""))

    # --- sqlmap_params.txt ---
    with open("sqlmap_params.txt", "w", encoding="utf-8") as f:
        for u, ps in get_params.items():
            f.write(f"{u}\t-p {','.join(sorted(ps))}\n")

    # --- sqlmap_post.sh ---
    with open("sqlmap_post.sh", "w", encoding="utf-8") as f:
        f.write("#!/usr/bin/env bash\n")
        f.write("# POST/JSON цели для sqlmap. Точка инъекции помечена '*'.\n")
        f.write("set -u\n\n")
        for c in post_cmds:
            f.write(c + "\n\n")
    os.chmod("sqlmap_post.sh", 0o755)

    print(f"[✓] GET-целей:  {len(get_urls)} -> {config.SQLMAP_TARGETS_FILE}")
    print(f"[✓] POST/JSON:  {len(post_cmds)} -> sqlmap_post.sh")
    print(f"[✓] Карта -p:   sqlmap_params.txt")
    if hot:
        print(f"[*] Из них приоритетных (SQLi-кандидаты от фаззера): {len(hot)}")


def _cmd(url, hdr, param, data=None, json_body=None):
    base = (
        f'sqlmap -u "{url}" \\\n'
        f'  --dbms=postgresql --batch --level=3 --risk=2 \\\n'
        f'  -H "{hdr}" \\\n'
        f'  -p "{param}" \\\n'
        f'  --threads=2 --delay={config.REQUEST_DELAY} --time-sec=6'
    )
    if data:
        base += f' \\\n  --data="{data}"'
    if json_body:
        base += (f' \\\n  --data=\'{json_body}\''
                 f' \\\n  -H "Content-Type: application/json"')
    if config.PROXY:
        base += f' \\\n  --proxy="{config.PROXY}"'
    if not config.VERIFY_TLS:
        base += ' \\\n  --force-ssl'
    return base


if __name__ == "__main__":
    main()
