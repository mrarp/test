# Как запускать — пошаговая инструкция

Конвейер из 4 шагов. Каждый следующий шаг читает результат предыдущего, поэтому
порядок важен. Всё управляется одним файлом `config.py`.

---

## 0. Предусловия

- Python 3.8+ (`python3 --version`).
- Для шага с SQLi — установленный **sqlmap** (`sqlmap --version`).
- **Письменное разрешение** на тестирование инстанса, согласованное окно и
  бэкап БД тестового стенда. Фаззинг шумный: сработает SOC/WAF, stored-пробы
  могут осесть в данных.

## 1. Установка

```bash
cd websoft-pentest
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Настройка `config.py`

```bash
cp config.example.py config.py
```

Откройте `config.py` и заполните минимум два поля:

```python
BASE_URL     = "https://hcm.corp.local"   # ваш инстанс, без слэша на конце
BEARER_TOKEN = "eyJ..."                    # токен из Authorization: Bearer
```

Где взять токен: откройте приложение в браузере → DevTools (F12) → вкладка
Network → любой запрос к API → заголовок `Authorization: Bearer <...>` →
скопируйте часть после `Bearer`.

Полезно сразу выставить:

```python
PROXY       = "http://127.0.0.1:8080"   # чтобы весь трафик шёл через Burp/ZAP
VERIFY_TLS  = False                     # если на стенде самоподписанный серт
REQUEST_DELAY = 0.3                     # пауза между запросами (щадит стенд/SOC)
ALLOWED_HOSTS = ["hcm.corp.local"]      # жёстко ограничить scope
```

> Токен Websoft HCM обычно живёт недолго. Если на шагах 1–3 посыпались 401 —
> обновите `BEARER_TOKEN` в `config.py` и перезапустите шаг.

## 3. Прогон конвейера

### Шаг 1 — собрать поверхность атаки
```bash
python 01_endpoint_collector.py
```
Результат: `endpoints.json`. Обходит портал, парсит JS-бандлы, ищет
Swagger/OpenAPI. В консоли увидите коды ответов по каждому URL.

### Шаг 2 — выделить точки ввода
```bash
python 02_input_field_mapper.py
```
Результат: `targets.json` — поля форм, query-параметры, JSON-поля.

### Шаг 3 — фаззинг
```bash
# базовый прогон
python 03_fuzzer.py --categories xss,sqli,xml,code

# с обходом регулярок/WAF (каждый payload в кодировках) — трафика в разы больше
python 03_fuzzer.py --categories xss,sqli,xml,code --mutations
```
Результат: `findings.json` — кандидаты. В конце печатается сводка по категориям
и, при `--mutations`, строка «обход через кодировки: …» — какой именно
кодировкой обходится фильтр.

Полезные варианты запуска:
```bash
python 03_fuzzer.py --categories sqli --max-targets 50        # только SQLi, первые 50 точек
python 03_fuzzer.py --categories xss --mutations \
       --encoders xss_entities,double_url                     # только нужные кодировки
python encoders.py                                            # показать все мутаторы и примеры
```

### Шаг 4 — SQLi через sqlmap
```bash
# сгенерить списки целей из targets.json/findings.json
python 04_make_sqlmap_targets.py

# запустить sqlmap (нужен установленный sqlmap в PATH)
export WSHCM_TOKEN="eyJ..."                 # тот же Bearer
export WSHCM_PROXY="http://127.0.0.1:8080"  # необязательно
bash sqlmap_runner.sh                        # GET-цели
bash sqlmap_post.sh                          # POST/JSON-цели (сгенерирован шагом 4)
```
Результаты sqlmap — в каталоге `sqlmap_out/`.

## 4. Разбор результатов

- Откройте `findings.json` — это **кандидаты**, не подтверждённые уязвимости.
- Каждую находку реплейните вручную через Burp/ZAP (трафик уже шёл через прокси,
  если задан `PROXY`): повторите запрос, убедитесь, что маркер реально
  исполняется / ошибка СУБД воспроизводится / тайминг стабилен.
- Поле `encoding` в находке показывает, в каком представлении payload прошёл
  фильтр (`raw` — без обфускации).

---

## Шпаргалка (копипаст целиком)

```bash
cd websoft-pentest
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config.example.py config.py
# -> отредактируйте config.py: BASE_URL, BEARER_TOKEN

python 01_endpoint_collector.py
python 02_input_field_mapper.py
python 03_fuzzer.py --categories xss,sqli,xml,code --mutations
python 04_make_sqlmap_targets.py
export WSHCM_TOKEN="<ваш_bearer>"
bash sqlmap_runner.sh
```

## Если что-то не так

| Симптом | Что делать |
|---|---|
| `Нет config.py` | `cp config.example.py config.py` и заполнить |
| Массовые `401/403` | обновить `BEARER_TOKEN`; проверить, не истёк ли токен |
| `SSLError` на стенде | `VERIFY_TLS = False` в `config.py` |
| `endpoints.json` почти пустой | проверить `BASE_URL` и доступность из вашей сети; поднять `CRAWL_MAX_PAGES` |
| Фаззер «молчит» (0 находок) | это норма, если дырок нет; для проверки связки запустите с `--max-targets 5` и смотрите коды ответов |
| `sqlmap: command not found` | установить sqlmap и добавить в PATH |
| Слишком много трафика с `--mutations` | поднять `REQUEST_DELAY`, сузить `--encoders`, ограничить `--max-targets` |
