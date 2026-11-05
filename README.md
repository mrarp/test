# Websoft HCM — pentest toolkit

Набор инструментов для **авторизованного** тестирования собственного инстанса Websoft HCM
(ранее WebTutor). Конвейер:

```
01_endpoint_collector.py  →  endpoints.json   (что вообще есть на сервере)
02_input_field_mapper.py  →  targets.json     (где принимается пользовательский ввод)
03_fuzzer.py              →  findings.json    (где ввод отражается / ломает парсер / тайминг)
sqlmap_runner.sh          →  запуск sqlmap по SQLi-кандидатам
```

> ⚠️ **Rules of engagement.** Запускать только против систем, на тестирование которых
> у вас есть письменное разрешение. Фаззинг генерирует аномальный трафик и может
> триггерить алерты SOC/WAF и портить данные (stored-пейлоады). Перед прогоном
> согласуйте окно, снимите бэкап БД тестового стенда и уведомите владельцев.

## Установка

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config.example.py config.py      # впишите BASE_URL и BEARER_TOKEN
```

## Запуск по шагам

```bash
# 1. Собрать поверхность атаки
python 01_endpoint_collector.py

# 2. Выделить точки ввода (формы, query-параметры, JSON-поля)
python 02_input_field_mapper.py

# 3. Прогнать активный фаззинг (безопасные маркеры, без деструктива)
python 03_fuzzer.py --categories xss,sqli,xml,code

# 3b. То же, но с обходом регулярок/WAF (каждый payload в кодировках)
python 03_fuzzer.py --categories xss,sqli,xml,code --mutations

# 4. SQLi — отдельным инструментом
bash sqlmap_runner.sh
```

Все скрипты читают настройки из `config.py` (токен, scope, rate-limit, прокси).
Направляйте трафик через Burp/ZAP, выставив `PROXY` в конфиге — так удобно
реплеить и верифицировать находки руками.

## Про стек Websoft HCM (почему словари такие)

- **Сервер:** Linux, бизнес-логика на **SSJS** (server-side JavaScript —
  собственный движок платформы). Отсюда отдельная категория `code` —
  инъекции в серверный JS; OS-command контекст, если всплывёт, — Linux.
- **БД:** PostgreSQL. SQLi-диалект и слепой тайминг — под Postgres
  (`pg_sleep`), в sqlmap ставим `--dbms=postgresql`.
- **XML/XQuery:** платформа активно использует XML и XQuery → отдельная
  категория `xml` (XXE / XML-инъекции / XQuery-инъекции); цели XXE — Linux
  (`/etc/passwd`, `/etc/hostname`, `/proc/self/environ`).
- **Фронт:** HTML/CSS/JS, местами React/Vue — часть маршрутов API зашита
  в JS-бандлах, поэтому коллектор их парсит.

## Обход регулярок и WAF (обфускация payload'ов)

Два слоя:

**1. Статические варианты в словарях.** В конец каждого `wordlists/*_payloads.txt`
добавлен блок готовых WAF-bypass проб — то, что не выводится автоматически:
полиглоты XSS, разрыв ключевых слов SQL комментариями (`UN/**/ION`), смена
XML-кодировки (`UTF-16`/`UTF-7`), сборка функций через `constructor`/
`fromCharCode` для SSJS, Unicode-гомоглифы и т.п.

**2. Мутатор на лету — `encoders.py` + флаг `--mutations`.** Держим в словарях
«чистые» payload'ы, а представления для обхода фильтров генерим автоматически,
по одному на каждую технику. Так один payload разворачивается в десятки
вариантов без раздувания словарей:

```bash
python 03_fuzzer.py --categories sqli --mutations
python 03_fuzzer.py --categories xss  --mutations --encoders xss_entities,double_url
python encoders.py          # показать все мутаторы и примеры
```

Мутаторы по категориям:
- **общие (транспорт):** `url`, `url_full`, `double_url`, `mixed_case`, `nbsp`
- **sqli:** `sql_comment_spaces` (пробел→`/**/`), `sql_case`, `sql_break_kw`
  (`SEL/**/ECT`), `sql_chr` (строки→`CHR()||CHR()`)
- **xss:** `xss_entities` (`&#NN;`), `xss_entities_hex`, `xss_js_unicode`
  (`\uXXXX`), `xss_tag_case`
- **xml:** `xml_entities`, `xml_cdata`, `xml_utf16`
- **code:** `code_concat` (`'al'+'ert'`), `code_hex` (`\xNN`), `code_unicode`

**Что это даёт для детекта.** Находки помечаются полем `encoding`. Если проба
проходит только через не-`raw` кодировку — в сводке это выводится отдельно
(«обход через кодировки: …»): вы сразу видите, КАКИМ представлением обходится
фильтр/WAF. Детект XSS при этом устойчив к кодированию — перед поиском маркера
ответ разэкранируется (HTML-сущности + URL-декод), регистронезависимо.

> ⚠️ **Объём трафика.** `--mutations` умножает число запросов примерно
> ×(число мутаторов+1) — это заметная нагрузка и много шума в логах/WAF.
> Поднимите `REQUEST_DELAY` в `config.py`, ограничьте `--encoders` нужными
> техниками и/или `--max-targets`, когда гоняете мутации по большому scope.

## Важно по детекту

Фаззер — **детектирующий**, а не эксплуатирующий. Он не несёт деструктивных
команд: признаки находит по отражению уникального маркера, сигнатурам ошибок
парсеров/СУБД и по времени ответа (benign `WAITFOR`/sleep-пейлоады). Любое
срабатывание — это кандидат, который нужно подтвердить вручную.
