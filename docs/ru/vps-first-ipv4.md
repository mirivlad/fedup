# FedUp: первое подключение Android → VPS → Интернет (IPv4)

**Критерий проверки:** телефон подключается к FedUp на вашем личном VPS, открывает HTTPS-сайты и получает внешний IPv4 **VPS**, а не домашнего или мобильного провайдера. Это **не** проверка незаметности для DPI и **не** готовая версия для защиты конфиденциального трафика.

Состояние реализации: экспериментальный HTTP/2 + TLS 1.3 mTLS переносит реальные IPv4-пакеты; отдельный IPv4 policy разрешает только источник 10.77.0.2 и внешние публичные адреса. На VPS настроена точечная SNAT/masquerade, Android задаёт маршрут 0.0.0.0/0, DNS 1.1.1.1 и блокирует IPv6 через ::/0 с последующим отбрасыванием пакетов в Rust. Проверка Linux CI создаёт три временных namespaces и подтверждает HTTP, ping, UDP/53, смену видимого исходного IP, отзыв доступа.

**Оставшиеся ограничения:** один клиент одновременно, IPv6 отключён, Android Always-on/Lockdown не проверены и выключены, при падении VPN приложения могут перейти на обычный интернет, APK из Actions подписан непостоянным debug-ключом, автоматическое продление сертификата отсутствует. Протокол HTTP/2 и его TLS-отпечаток не доказаны устойчивыми к DPI.

## Подготовить тестовый VPS

Используйте **отдельный одноразовый VPS**, желательно без иных важных сервисов и секретов. Не устанавливайте на сервер, обслуживающий продакшен, потому что для первого приёмочного испытания пока используется **одноразовый лабораторный CA** с plaintext-файлом ключа и явным режимом \`--unsafe-lab-online-ca\`. Долговременный защищённый издатель сертификатов ещё в разработке.

Необходимы: Debian/Ubuntu, публичный IPv4, домен с обычной DNS A-записью, доступность TCP **443** (HTTPS API через Caddy) и TCP **7443** (взаимный TLS / HTTP/2 VPN). Если домен проксируется через сторонний CDN, прямой TCP 7443 может вести не на VPS — для первого испытания используйте DNS-only A-запись.

Установить инструменты в тестовом VPS:

~~~bash
sudo apt update
sudo apt install -y git curl build-essential pkg-config libssl-dev \
  iproute2 nftables openssl ca-certificates
# Rust устанавливается штатным rustup, затем:
git clone https://github.com/mirivlad/fedup.git
cd fedup
cargo build --release -p fedup-users -p fedup-auth -p fedup-tun
sudo install -m 755 target/release/fedup-users target/release/fedup-auth \
  target/release/fedup-tun /usr/local/bin/
~~~

В примерах ниже замените \`vpn.example.com\` на **свой** домен, не используйте этот примерный адрес буквально. Для записей под \`/var/lib/fedup\` нужен root. Все следующие команды выполнять в отдельной root-сессии \`sudo -i\` с \`umask 077\`, за исключением шагов настройки Caddy.

## Одноразовые тестовые сертификаты

~~~bash
sudo -i
umask 077
install -d -m 700 /var/lib/fedup
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -noenc -days 3 \
  -subj '/CN=Disposable FedUp VPN CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout /var/lib/fedup/ca.key -out /var/lib/fedup/ca.pem
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -subj '/CN=vpn.example.com' \
  -keyout /var/lib/fedup/server.key -out /var/lib/fedup/server.csr
printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=serverAuth' \
  'subjectAltName=DNS:vpn.example.com' \
  >/var/lib/fedup/server.ext
openssl x509 -req -in /var/lib/fedup/server.csr \
  -CA /var/lib/fedup/ca.pem -CAkey /var/lib/fedup/ca.key \
  -set_serial 1102 -days 2 -out /var/lib/fedup/server.pem \
  -extfile /var/lib/fedup/server.ext
chmod 600 /var/lib/fedup/*.key
fedup-users init /var/lib/fedup/accounts
read -r -s -p 'Пароль пользователя (>= 12 байт): ' FEDUP_PASS; echo
printf '%s\n' "$FEDUP_PASS" |
  fedup-users add /var/lib/fedup/accounts vladimir --password-stdin
unset FEDUP_PASS
~~~

Измените \`vladimir\` на нужный логин. **Никогда не переносите файл \`ca.key\` на телефон**. Это ключ выпуска сертификатов; здесь он существует только на одноразовом VPS в ограниченном по времени эксперименте.

## Запустить авторизацию и VPN

Временно используем systemd transient units, без установки постоянного системного сервиса:

~~~bash
sudo systemd-run --unit=fedup-auth-test \
  /usr/local/bin/fedup-auth serve-enroll-lab \
  /var/lib/fedup/accounts 47677 \
  /var/lib/fedup/ca.pem /var/lib/fedup/ca.key \
  vpn.example.com --unsafe-lab-online-ca

sudo systemd-run --unit=fedup-vpn-test \
  /usr/local/bin/fedup-tun server-vps-v4 0.0.0.0:7443 \
  futserver /var/lib/fedup/ca.pem /var/lib/fedup/server.pem \
  /var/lib/fedup/server.key /var/lib/fedup/accounts \
  --unsafe-experimental-public-egress
~~~

Проверить:

~~~bash
sudo journalctl -u fedup-auth-test -n 30 --no-pager
sudo journalctl -u fedup-vpn-test -n 30 --no-pager
sudo ip link show futserver
sudo ss -lntp | grep -E ':47677|:7443'
~~~

Если нет \`futserver\`, не переходите к NAT: сначала исправьте ошибку запуска туннеля.

## NAT/маршрутизация

Узнайте интерфейс VPS, через который уходит трафик в интернет:

~~~bash
ip -4 route get 1.1.1.1
~~~

Вместо \`eth0\` далее впишите фактический \`dev\` (например, \`ens3\`, \`enp1s0\`).

Из каталога FedUp на сервере:

~~~bash
sudo bash scripts/vps-egress-v4.sh install futserver eth0 \
  --acknowledge-host-network-changes
sudo bash scripts/vps-egress-v4.sh status
sudo nft list table ip fedup_v4
~~~

Скрипт добавляет \`10.77.0.1/30\` интерфейсу \`futserver\`, включает IPv4 forwarding и создаёт **только отдельную таблицу nftables** с SNAT для \`10.77.0.2\`. Он не меняет default route/SSH, не удаляет существующие правила. **Если другой firewall сбрасывает FORWARD, отдельная таблица не может отменить этот DROP** — правила допуска нужно добавить в уже действующую политику явно. Дополнительный firewall VPS/провайдера должен разрешать входящий **TCP 7443**. Локальный порт 47677 **не открывать**.

## HTTPS API через Caddy

Установите Caddy, настройте отдельный домен (например, \`vpn.example.com\`) и добавьте в его **реальную** конфигурацию, не стирая текущий Caddyfile:

~~~caddyfile
vpn.example.com {
    @fedup_api {
        path /api/fedup/v1/login /api/fedup/v1/config /api/fedup/v1/devices
    }
    reverse_proxy @fedup_api 127.0.0.1:47677
    respond 404
}
~~~

Проверьте Caddyfile и примените обычную процедуру reload, действующую на вашем VPS. У домена должен быть корректный доверенный HTTPS-сертификат. Проверьте наличие публичного CA без логина:

~~~bash
curl -fsS https://vpn.example.com/api/fedup/v1/config \
  -H 'Content-Type: application/json' \
  -d '{"username":"YOUR_USER","password":"YOUR_PASSWORD"}'
~~~

В ответе будет **публичный тестовый CA** и \`server_name\`. Никакого приватного ключа в ответе быть не должно. Прежде чем публично выставлять API, рекомендованы ограничения попыток на edge и отсутствие логирования HTTP-body с паролями. Этот тестовый режим не предназначен для длительной публичной эксплуатации.

## Экспериментальный общий вход HTTPS 443 — не для production

Новый вариант **не требует TLS-клиентский сертификат в публичном рукопожатии**:
Caddy принимает HTTPS/2 на TCP 443 с обычным публично доверенным
сертификатом. Локальный FedUp проверяет одноразовый подписанный challenge
устройства внутри зашифрованного HTTP/2, проверяет сертификат устройства
и живой отзыв аккаунта. Внешний порт TCP 7443 в этом варианте НЕ нужен.

Для отдельного тестового VPS с уже настроенным Caddy:

1. Запустите **вместо** старого процесса шлюза (не одновременно с ним на том же TUN)
   `fedup-tun server-vps-proof-h2c 127.0.0.1:47678 futserver /path/to/ca.pem /path/to/users --behind-trusted-https-proxy`.
   Он откажется слушать не-loopback. Существующий nftables SNAT-скрипт остаётся тем же.
2. В Caddyfile на том же домене сохраняется путь к `fedup-auth` по 127.0.0.1:47677,
   остальные запросы направляются в h2c backend 127.0.0.1:47678.
3. Запускайте `fedup-auth` только с явной переменной
   `FEDUP_VPN_PROOF_EDGE=1` **после** фактической готовности Caddy и шлюза.
   Тогда аутентифицированная конфигурация сообщает Android `transport=app-proof`
   и `tunnel_port=443`. Экран Android по-прежнему требует лишь адрес,
   логин и пароль.

Пример *для одноразового тестового домена*, а не вставка в текущий
Caddyfile без адаптации:

~~~caddyfile
vpn.example.com {
    @fedup_api path /api/fedup/v1/login /api/fedup/v1/config /api/fedup/v1/devices
    handle @fedup_api {
        reverse_proxy 127.0.0.1:47677
    }
    @public_site path / /index.html
    handle @public_site {
        root * /srv/www/my-existing-site
        file_server
    }
    handle {
        # Includes GET /assets/site.js for device-key initiation.
        # Unknown URLs and denied VPN routes share the same 404 handler.
        reverse_proxy h2c://127.0.0.1:47678 {
            flush_interval -1
        }
    }
}
~~~

**Публичная часть:** разместите **собственный настоящий сайт** в `/srv/www/my-existing-site` (с доступом на чтение для Caddy) или адаптируйте `@public_site` к уже работающему сайту. В коде клиента зарезервирован обычный JS-ресурс `/assets/site.js`; не перехватывайте его правилами публичного сайта. Анонимный GET этого ресурса не получает никаких специальных cookie. Backend можно проверять через сравнение четырёх защищённых URL и обычных 404 с `tools/active-probe.py` внутри изолированной сетевой лаборатории. **Не перезаписывайте существующий Caddyfile этим примером.**

**Безопасность и ограничения:** backend h2c не шифрует loopback-трафик
и должен быть доступен только локальному Caddy, без публикации наружу.
Тестовый онлайн CA по-прежнему небезопасен на production VPS;
Android Always-on/Lockdown и IPv6 egress пока не готовы. Полная Caddy
интеграция и физический Android подлежат отдельной приёмке; успешная
компиляция не заменяет end-to-end тест.

## Android и проверка смены IP

Получите APK из последнего успешного GitHub Actions, задание \`android-lab\`, артефакт \`fedup-android-lab-debug\`. На тестовом телефоне в FedUp введите:

- Сервер: \`vpn.example.com\`
- Логин: \`vladimir\`
- Пароль: тот, что создали на VPS

Нажмите **«Подключиться»**. Приложение проверит HTTPS-учётную запись, создаст ключ в Android Keystore, автоматически получит клиентский сертификат, определит IPv4 домена и откроет системный диалог Android VPN. После согласия подключится к TCP 7443 через взаимный TLS / HTTP/2. На одном Android одновременно может быть активен только один VpnService: текущий NaiveProxy/WireGuard будет заменён.

Откройте **https://api.ipify.org/** или **https://ifconfig.me/ip** в браузере телефона и сравните с \`curl -4 https://api.ipify.org\` на VPS. IP должен совпадать с публичным выходом VPS. Проверьте работу нескольких HTTPS-сайтов и DNS. Проверяйте по Wi-Fi и по мобильной сети отдельно. Тест IPv6 (например, test-ipv6.com) должен показать отсутствие IPv6-соединения, **а не реальный IPv6 оператора**.

В журнале VPS:

~~~bash
sudo journalctl -fu fedup-vpn-test
fedup-users devices /var/lib/fedup/accounts vladimir
~~~

Для проверки отзыва (только после завершения функционального теста):

~~~bash
sudo fedup-users disable /var/lib/fedup/accounts vladimir
~~~

Сертификат должен перестать проходить проверку в течение примерно пяти секунд. **Пока Android Always-on/Lockdown не протестированы, после разрыва VPN телефон может автоматически вернуться к обычному интернету с исходным IP** — это известное ограничение, не считать его fail-closed защитой.

## Остановить и убрать тест

**Сначала удалите NAT и адрес при живом интерфейсе**, а уже затем остановите VPN-сервис.

~~~bash
sudo bash scripts/vps-egress-v4.sh remove --acknowledge-host-network-changes
sudo systemctl stop fedup-vpn-test fedup-auth-test
~~~

Глобальный \`net.ipv4.ip_forward\` специально не выключается автоматически: от него могут зависеть Docker, WireGuard и другие компоненты VPS. Если он был выключен раньше, решение о восстановлении прежнего значения принимайте отдельно после проверки работающих сервисов. Временные CA-ключи и базу пользователей удаляйте только после того, как они больше не нужны для анализа теста.

## Не считать готовым без физической приёмки

Успешный CI проверяет реальную передачу пакетов в локальных namespaces, но **не доказывает**, что конкретный телефон/провайдер/VPS уже поддерживают рабочую цепочку, что DPI не обнаружит HTTP/2 mTLS, либо что IPv4/IPv6/DNS не утекут при авариях. Следующий необходимый артефакт — результат испытаний Android на настоящем VPS и корректный управляемый издатель сертификатов вместо \`--unsafe-lab-online-ca\`.
