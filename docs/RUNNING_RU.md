# Запуск socat-rust: TCP, TLS и ГОСТ

Инструкция для Linux x86_64, выпуск v0.1.13. Один процесс обслуживает один
профиль `[[relay]]`. Примеры используют тестовые адреса; замените их своими.

С v0.1.13 в TLS-бинарниках также есть [встроенный генератор ключей, CSR и сертификатов](PKI_RU.md).

## Выбор бинарника и режима

| Бинарник из v0.1.13 | TCP | TLS 1.2/1.3 | ГОСТ TLS 1.2 |
|---|---|---|---|
| `socat-rust-linux-amd64-static` | Да | Нет | Нет |
| `socat-rust-linux-amd64-tls-static` | Да | Да | Нет |
| `socat-rust-linux-amd64-tls-gost-static` | Да | Да | Да |

Последний бинарник позволяет переключать все три режима конфигурацией,
без замены исполняемого файла. Настройки независимы для каждой стороны:

| Настройка стороны | Режим |
|---|---|
| Нет `[relay.inbound_tls]` / `[relay.outbound_tls]` | Обычный TCP на этой стороне |
| Таблица с `mode = "tls"` | Обычный TLS, согласование 1.2 или 1.3 |
| Таблица с `mode = "gost"` | ГОСТ TLS, только 1.2 |

Параметра выбора версии обычного TLS в v0.1.13 **нет**: нельзя конфигом
принудительно разрешить только 1.2 или только 1.3. Для отключения TLS удалите
соответствующую таблицу целиком; `mode = "tcp"` и `enabled = false` не поддерживаются.
Изменения читаются при запуске: перезапустите профиль после изменения конфига
или сертификатов. Перезапуск разрывает его текущие соединения.

TCP-режим также может прозрачно передавать TLS исходного приложения:
в таком случае relay не завершает TLS и не проверяет сертификаты.

## Установка готового статического бинарника

В новом рабочем каталоге скачайте архив и контрольные суммы:

```bash
release_url=https://github.com/igor04091968/socat-rust/releases/download/v0.1.13
curl -fL "$release_url/SHA256SUMS" -o SHA256SUMS
curl -fL "$release_url/socat-rust-0.1.13-linux-amd64-tls-gost.tar.gz" \
  -o socat-rust-0.1.13-linux-amd64-tls-gost.tar.gz
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf socat-rust-0.1.13-linux-amd64-tls-gost.tar.gz
cd socat-rust-0.1.13-linux-amd64-tls-gost
sha256sum -c SHA256SUMS
sudo install -m 0755 socat-rust-linux-amd64-tls-gost-static /usr/local/sbin/socat-rust
sudo install -d -m 0755 /etc/socat-rust /var/log/socat-rust
/usr/local/sbin/socat-rust --version
```

Проверка `--ignore-missing` относится к внешнему списку файлов релиза:
на этом шаге скачан только архив. Внутри архива проверяется полный список.
Бинарник содержит криптобиблиотеки; конфиг, CA, сертификаты и ключи хранятся отдельно.

## Базовый TCP-профиль

Сохраните как `/etc/socat-rust/relays.toml`, например через `sudoedit`:

```toml
[[relay]]
name = "demo"
listen = "127.0.0.1:18000"
upstream = "127.0.0.1:18080"
allow = ["127.0.0.1/32"]
uid = 2450100
pid_file = "/run/socat-rust/demo.lock"
log_file = "/var/log/socat-rust/demo.log"
backlog = 16
max_connections = 4
eof_grace_seconds = 1
connect_timeout_seconds = 10
verbose_payload_logging = false
```

`2450100` — пример выделенного ненулевого UID. При старте от root процесс
подготавливает лог и lock-файл, затем устанавливает числовые UID и GID,
оба равные `uid`, и очищает дополнительные группы. Указанное имя пользователя
в системе не требуется. Если `uid` отсутствует, процесс остаётся под UID запуска.
Запуск из-под другого непривилегированного UID будет отклонён.

`listen` и `upstream` задаются числовыми IPv4-адресами с портом; DNS-имя
в `upstream` не поддерживается. `allow` ограничивает адреса клиентов.
`max_connections` задаёт число одновременно обслуживаемых соединений.
Таймаут подключения действует на одну попытку; повторные TCP-подключения
продолжаются с ограниченной задержкой между попытками.

Проверка всех профилей без открытия сетевых сокетов и запуск в терминале:

```bash
sudo /usr/local/sbin/socat-rust --config /etc/socat-rust/relays.toml config-check
sudo /usr/local/sbin/socat-rust --config /etc/socat-rust/relays.toml --relay demo
```

Остановка — Ctrl-C или SIGTERM. При заданном `log_file` рабочий лог пишется
в файл; без него foreground-процесс пишет в stdout.

Для локальной проверки запустите тестовый HTTP-сервер в другом терминале:

```bash
demo_web_root=$(mktemp -d)
printf 'relay works\n' > "$demo_web_root/index.html"
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$demo_web_root"
```

Затем выполните `curl --noproxy '*' http://127.0.0.1:18000/`.
Ожидаемый ответ — `relay works`. После проверки остановите оба процесса.

## TLS к внешнему серверу

В базовом профиле измените `upstream` на адрес TLS-сервера, например
`192.0.2.10:443`, затем добавьте таблицу:

```toml
[relay.outbound_tls]
mode = "tls"
ca_file = "/etc/socat-rust/pki/demo/upstream-ca.pem"
server_name = "upstream.example.org"
handshake_timeout_seconds = 10
```

Со стороны клиента остаётся TCP, к upstream устанавливается TLS.
`server_name` задаёт проверяемое имя сертификата; оно не разрешает DNS
и не меняет IP из `upstream`. CA-файл обязателен и заменяет стандартное
хранилище доверия. Проверка цепочки, срока и имени включена всегда.

Для взаимной аутентификации добавьте в эту же таблицу оба поля:

```toml
certificate = "/etc/socat-rust/pki/demo/client-chain.pem"
private_key = "/etc/socat-rust/pki/demo/client.key"
```

## Приём TLS от клиента

К базовому TCP-профилю добавьте:

```toml
[relay.inbound_tls]
mode = "tls"
certificate = "/etc/socat-rust/pki/demo/server-chain.pem"
private_key = "/etc/socat-rust/pki/demo/server.key"
handshake_timeout_seconds = 10
```

Клиент подключается по TLS, upstream получает обычный TCP. Чтобы требовать
клиентский сертификат, добавьте в эту таблицу
`client_ca = "/etc/socat-rust/pki/demo/client-ca.pem"`.
Без `client_ca` клиентский сертификат не требуется.

Если нужны TLS на обеих сторонах, добавьте обе таблицы к одному `[[relay]]`.
Каждая сторона получает отдельную TLS-сессию; relay обрабатывает расшифрованные
данные. Обычные поля профиля размещайте перед TLS-таблицами, иначе TOML
отнесёт их к последней открытой таблице.

## ГОСТ TLS

Для нужной стороны замените `mode = "tls"` на `mode = "gost"` и добавьте
`gost_cipher`. Например, исходящая сторона:

```toml
[relay.outbound_tls]
mode = "gost"
gost_cipher = "kuznyechik"
ca_file = "/etc/socat-rust/pki/demo/gost-ca.pem"
server_name = "gost.example.org"
handshake_timeout_seconds = 10
```

Допустимые значения: `kuznyechik` (по умолчанию), `magma`, `gost28147`,
`legacy28147`. Предлагается только выбранный набор шифров. Для входящего ГОСТ
нужны подходящие ГОСТ-сертификат и ключ в `certificate`/`private_key`.
Взаимная аутентификация задаётся теми же полями, что для обычного TLS.

ГОСТ работает только с TLS 1.2. Автоматического перехода на обычный TLS или
TCP при ошибке нет. Совместимость с конкретным внешним сервисом проверяется
отдельно. Реализация не является сертифицированным СКЗИ и не содержит
CryptoPro CSP. Контейнеры CSP, токены, зашифрованные ключевые контейнеры
и настройки CRL/OCSP не поддерживаются. Подробности — [TLS_GOST.md](TLS_GOST.md).

## Права на ключи

Процесс повторно загружает TLS-материалы после смены UID. Все каталоги пути
должны быть доступны этому UID, ключи и CA — читаться им. Для профиля из примера:

```bash
sudo install -d -m 0755 /etc/socat-rust/pki
sudo install -d -o 2450100 -g 2450100 -m 0700 /etc/socat-rust/pki/demo
sudo install -o 2450100 -g 2450100 -m 0600 server.key /etc/socat-rust/pki/demo/server.key
sudo install -o 2450100 -g 2450100 -m 0600 server-chain.pem /etc/socat-rust/pki/demo/server-chain.pem
```

Аналогично установите необходимые CA и клиентские материалы. Используйте
свои сертификаты, абсолютные пути и закрытый доступ к ключам.
Дополнительная группа пользователя не поможет после её очистки при смене UID.
Для TLS `verbose_payload_logging` должен оставаться `false`.

## Ручной фоновый запуск

```bash
sudo /usr/local/sbin/socat-rust --daemon \
  --config /etc/socat-rust/relays.toml --relay demo
sudo tail -n 50 /var/log/socat-rust/demo.log
sudo ss -ltnp 'sport = :18000'
```

`--background` — синоним `--daemon`. Используйте абсолютные пути: фоновый
процесс меняет рабочий каталог на `/`. Нулевой код выхода родителя означает
успешный fork, но ещё не готовность дочернего процесса. Проверяйте лог,
слушающий сокет и передачу данных.

Для остановки сначала сверьте PID из `pid_file` с командой, UID и путём
исполняемого файла процесса, затем отправьте SIGTERM. Не удаляйте lock-файл
работающего процесса: это может позволить второму экземпляру обойти блокировку.
Старый файл после падения не блокирует запуск — kernel lock уже освобождён.

## Запуск через systemd

Используйте шаблон `systemd/socat-rust@.service` из исходников. В архиве релиза
исходники находятся во вложенном `source.tar.gz`:

```bash
tar -xzf source.tar.gz
cd socat-rust-0.1.13
sudo install -m 0644 systemd/socat-rust@.service /etc/systemd/system/
sudo install -d -m 0755 /usr/local/share/doc/socat-connectors
sudo install -m 0644 docs/ASTRA_CONNECTORS.md /usr/local/share/doc/socat-connectors/README.md
sudo systemctl daemon-reload
sudo systemctl start socat-rust@demo.service
sudo systemctl status socat-rust@demo.service
sudo journalctl -u socat-rust@demo.service -n 50 --no-pager
```

При работе из Git-клона команды установки выполняются из корня репозитория,
распаковка `source.tar.gz` не нужна. Шаблон использует `/usr/local/sbin/socat-rust`
и `/etc/socat-rust/relays.toml`, запускается от root и передаёт смену UID самому relay.
Ключ `--daemon` в unit не добавляйте. При `log_file` смотрите рабочие сообщения
в файле; ранние ошибки запуска доступны в journal.

```bash
sudo systemctl restart socat-rust@demo.service
sudo systemctl stop socat-rust@demo.service
sudo systemctl enable socat-rust@demo.service
sudo systemctl disable socat-rust@demo.service
```

`enable`/`disable` управляют автозагрузкой; сами по себе они не запускают
и не останавливают процесс. До включения нового listener остановите старый
relay на том же адресе и порту.

Старый `scripts/generate-systemd-units.py` создаёт отдельную схему с именами
`socat-rust-<name>.service`, другим путём бинарника и запуском от UID через
systemd. Она не взаимозаменяема с приведённым шаблоном `@`.

## Группа банковских коннекторов

Для диапазона `bnk2450001`–`bnk2450037` есть отдельный Python-менеджер
(нужен Python 3.11+). Устанавливается из корня исходников:

```bash
sudo install -m 0755 scripts/socat-connectors /usr/local/sbin/socat-connectors
sudo socat-connectors list
sudo socat-connectors check
sudo socat-connectors status
sudo socat-connectors start --relay bnk2450034
sudo socat-connectors restart --relay bnk2450034
sudo socat-connectors stop --relay bnk2450034
```

Без `--relay` действие относится ко всем имеющимся профилям диапазона.
Менеджер использует шаблон `socat-rust@...`, пропускает отсутствующие локальные
адреса и умеет безопасно остановить распознанный ручной `--daemon` при `restart`.
`enable` и `disable` отдельно управляют автозагрузкой. Профиль `demo` этим
менеджером не обслуживается. Детали — [ASTRA_CONNECTORS.md](ASTRA_CONNECTORS.md).

## CentOS 5 и старое ядро

Для ядра 2.6.18 используйте отдельный `legacy-kernel`-вариант.
Обычная статическая сборка для современного Linux не гарантирует совместимость
со старым ядром. Готовый legacy-бинарник опубликован в
[релизе v0.1.11](https://github.com/igor04091968/socat-rust/releases/tag/v0.1.11).
Legacy поддерживает только TCP; TLS-конфигурация отклоняется.
На CentOS 5 нет systemd: запускайте в терминале, через supervisor в foreground
или вручную с `--daemon`. Для SysV init используйте режим, соответствующий
модели контроля процесса вашего init-скрипта.

## Если запуск не удался

`config-check` проверяет весь файл, включая сертификаты всех профилей,
но не доступность upstream и не успешность TLS-рукопожатия. Даже выбранный
TCP-профиль не запустится plain-бинарником, если в другом профиле файла есть TLS.
Используйте бинарник с нужными возможностями или разделите конфиги.

При ошибке bind проверьте наличие локального IP и занятость порта.
При ошибке чтения ключа проверьте доступ от числового UID профиля ко всему пути.
Работающий процесс и открытый listener ещё не подтверждают передачу до upstream:
проверьте соединение реальным клиентом и посмотрите журнал relay.
