#!/usr/bin/env bash
# Тестовая пара RSA-2048 для режима private_key_jwt.
# Использование: ./scripts/gen-keys.sh [каталог=./secrets] [CN=my-service] [дней=365]
set -euo pipefail

OUT="${1:-./secrets}"
CN="${2:-my-service}"
DAYS="${3:-365}"

mkdir -p "$OUT"
chmod 700 "$OUT"

# Приватный ключ (PKCS#8) — остаётся у клиента, никуда не передаётся
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT/private.pem"
chmod 600 "$OUT/private.pem"

# Публичный ключ — для серверов, принимающих «Public Key PEM»
openssl rsa -in "$OUT/private.pem" -pubout -out "$OUT/public.pem"

# Самоподписанный сертификат — для серверов, принимающих «Certificate PEM» (Keycloak и др.)
openssl req -new -x509 -key "$OUT/private.pem" -sha256 -days "$DAYS" -subj "/CN=$CN" -out "$OUT/client.crt"

echo "Готово. Файлы в $OUT:"
echo "  private.pem  — приватный ключ (НЕ коммитить, НЕ передавать)"
echo "  public.pem   — публичный ключ"
echo "  client.crt   — сертификат с публичным ключом (загружается на сервер авторизации)"
