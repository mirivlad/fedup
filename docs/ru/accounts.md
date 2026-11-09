# FedUp: управление пользователями (этап 1)

Основной сценарий: администратор создаёт пользователя; в Android человек вводит сервер, логин и пароль. Ручные CA, CSR и PEM скрыты в расширенной диагностике.

**Важно:** сейчас проверяется только пароль. Автоматическая выдача сертификата устройству и полноценное VPN-подключение ещё не реализованы. HTTP 204 не означает, что трафик защищён VPN.

## Сервер

~~~bash
cd /path/to/fedup
cargo build -p fedup-users -p fedup-auth
./target/debug/fedup-users init ./target/fedup-accounts-lab
read -r -s -p 'Пароль от 12 байт: ' FEDUP_PASS; echo
printf '%s\n' "$FEDUP_PASS" |
  ./target/debug/fedup-users add ./target/fedup-accounts-lab vladimir --password-stdin
unset FEDUP_PASS
./target/debug/fedup-users list ./target/fedup-accounts-lab
./target/debug/fedup-users disable ./target/fedup-accounts-lab vladimir
./target/debug/fedup-users enable ./target/fedup-accounts-lab vladimir
~~~

CLI также имеет команды password и check; пароли принимаются только через stdin, не через argv. База SQLite имеет режим 0600 внутри каталога 0700. Сохраняются только индивидуальные Argon2id PHC-хеши: 19 МиБ, два прохода, один поток.

Запуск локального API:

~~~bash
./target/debug/fedup-auth serve ./target/fedup-accounts-lab 47677 --behind-https-proxy
~~~

Сервис слушает только 127.0.0.1 и принимает POST /api/fedup/v1/login с JSON username/password. Возвращает 204 для правильных данных, 401 при отказе и 429 при чрезмерных попытках. Ограничены тело запроса, число попыток и одновременные Argon2-операции.

Пример Caddy для *отдельного тестового домена с корректным HTTPS-сертификатом*:

~~~caddyfile
vpn.example.com {
    @fedup_login {
        method POST
        path /api/fedup/v1/login
    }
    reverse_proxy @fedup_login 127.0.0.1:47677
    respond 404
}
~~~

Это не готовая конфигурация рабочего VPS. Нужны внешний rate limiting, служба с минимумом привилегий и проверка логирования. Никогда не выставляйте локальный HTTP-порт наружу.

## Android

Главный экран: адрес сервера, логин, пароль и «Проверить доступ». Приложение требует HTTPS и стандартную проверку сертификата/имени, не допускает HTTP fallback. После успешного входа сервер и логин сохраняются в настройках, а пароль — только в виде AES-GCM ciphertext с ключом Android Keystore. Если Keystore недоступен, plaintext fallback запрещён. Прежняя ручная регистрация скрыта.

## Тесты и следующие шаги

~~~bash
cargo test --workspace --all-targets
bash tests/users-smoke.sh
~~~

До готового VPN необходимо связать логин с автоматическим выпуском устройства: приватный ключ создаётся на телефоне, сервер подтверждает пользователя, подписывает CSR безопасным делегированным издателем, разрешает сертификат устройства и отзывает уже действующие соединения при блокировке пользователя. Затем нужно проверить настоящую передачу IP-трафика и DNS на тестовом телефоне и отдельном VPS. До этого релиз не выпускается.
