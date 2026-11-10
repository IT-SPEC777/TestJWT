#!/usr/bin/env bash
# Тестовый набор для режима mTLS: корневой СА + клиентский сертификат (clientAuth) + PFX.
# Использование: ./scripts/gen-mtls-certs.sh [каталог=./secrets/mtls] [CN=my-service] [пароль_pfx=changeit]
set -euo pipefail

OUT="${1:-./secrets/mtls}"
CN="${2:-my-service}"
PFX_PASSWORD="${3:-changeit}"

mkdir -p "$OUT"
chmod 700 "$OUT"
cd "$OUT"

# 1. Тестовый корневой СА
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 1825 -subj "/CN=Test M2M Root CA" -out ca.crt

# 2. Клиентский ключ и запрос
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client.key
openssl req -new -key client.key -subj "/CN=$CN" -out client.csr

# 3. Подпись клиентского сертификата нашим СА (EKU = clientAuth)
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n' > client.ext
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 365 -sha256 -extfile client.ext -out client.crt

# 4. PFX для .NET (ключ + сертификат + цепочка)
openssl pkcs12 -export -inkey client.key -in client.crt -certfile ca.crt \
  -out client.pfx -passout "pass:$PFX_PASSWORD"

chmod 600 ./*.key client.pfx
rm -f client.csr client.ext ca.srl

echo "Готово. Файлы в $OUT:"
echo "  ca.crt       — корневой СА: добавить в trust store сервера авторизации"
echo "  client.crt   — клиентский сертификат (subject: CN=$CN)"
echo "  client.key   — приватный ключ клиента (НЕ коммитить)"
echo "  client.pfx   — то же в PFX, пароль: $PFX_PASSWORD"
