# Запуск socat-rust: TCP, TLS и ГОСТ

Инструкция для Linux x86_64, выпуск v0.1.20. Один процесс обслуживает один
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
release_url=https://github.com/igor04091968/socat-rust/releases/download/v0.1.20
curl -fL "$release_url/SHA256SUMS" -o SHA256SUMS
curl -fL "$release_url/socat-rust-0.1.20-linux-amd64-tls-gost.tar.gz" \
  -o socat-rust-0.1.20-linux-amd64-tls-gost.tar.gz
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf socat-rust-0.1.20-linux-amd64-tls-gost.tar.gz
cd socat-rust-0.1.20-linux-amd64-tls-gost
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
runtime_workers = 0 # авто: от 1 до 2, с учётом доступных CPU
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
`max_connections` — верхний предел одновременно обслуживаемых соединений.
В Tokio-сборке эффективный предел автоматически снижается с учётом RLIMIT_NOFILE,
текущего числа открытых файлов, доступной памяти Linux и лимита cgroup v1/v2;
проверка выполняется раз в секунду. По умолчанию резервируется 32 FD, 64 МиБ
памяти и оценивается 1 МиБ на сессию. Эти оценки настраиваются в `[relay.resources]`:

```toml
[relay.resources]
reserve_fds = 32
reserve_memory_bytes = 67108864
memory_per_connection_bytes = 1048576
cpu_pressure_high_percent = 20
```

Нулевой вычисленный бюджет приостанавливает приём, а не запускает новые сессии;
текущие соединения завершаются штатно. Когда ресурсы освобождаются, приём
возобновляется автоматически. На системах без доступного счётчика памяти действует
ограничение по FD и `max_connections`. При наличии Linux PSI CPU-давление cgroup
(или системы, если cgroup PSI недоступен) снижает лимит новых соединений после
трёх высоких измерений; возврат идёт ступенями после пяти спокойных измерений.
При исчезновении метрики контроллер постепенно возвращает исходный лимит. Уже
принятые сессии не завершаются из-за CPU-давления. Порог настраивается через
`cpu_pressure_high_percent`; значение `0` выключает CPU-адаптацию. PSI недоступен
на legacy-сборке и части старых ядер.

`runtime_workers = 0` выбирает от 1 до 2
Tokio worker-потоков по доступной параллельности; явное значение 1..64 фиксирует
их число. Для множества профилей оставляйте авто или 1; TLS-нагрузку проверяйте
измерением перед увеличением. Legacy-сборка для CentOS 5 эти лимиты не применяет.

`connect_timeout_seconds` ограничивает одну попытку. После ошибки relay повторяет
подключение с экспоненциальной задержкой до 30 секунд, но по умолчанию не дольше
`upstream_retry_window_seconds = 300`; затем закрывает клиентскую сессию и
освобождает слот. Значение `0` сохраняет бесконечные повторы. Окно учитывает
таймаут текущей попытки и не удерживает слот дольше установленной границы.
Все шаблонные профили и сгенерированные отдельные unit-файлы входят в общую
systemd slice `socat-rust.slice`; она включает учёт, но не задаёт произвольных лимитов.
Системный администратор может задать подходящие для узла `MemoryHigh`, `MemoryMax`
и `CPUQuota` через drop-in `/etc/systemd/system/socat-rust.slice.d/resources.conf`.
Нужно установить slice unit и затем выполнить `systemctl daemon-reload`.

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

## Процесс и терминал (exec/pty)

Профиль с `endpoint = "exec"` запускает программу без shell и соединяет её
stdin/stdout с расшифрованным клиентским потоком. `endpoint = "pty"` делает то
же через псевдотерминал: работает job control, Ctrl-C, `stty`, полноэкранные
программы. Оба режима требуют mTLS (`inbound_tls.client_ca`) и недоступны в
`legacy-kernel`.

```toml
[[relay]]
name = "console-demo"
listen = "10.34.0.1:8090"
allow = ["10.19.63.0/24"]
endpoint = "pty"
uid = 2450090
max_connections = 1
log_file = "/var/log/console-demo.log"

[relay.inbound_tls]
mode = "tls"
certificate = "/etc/socat-rust/pki/demo/server-chain.pem"
private_key = "/etc/socat-rust/pki/demo/server.key"
client_ca = "/etc/socat-rust/pki/demo/client-ca.pem"

[relay.process]
command = "/bin/bash"
args = ["-i", "-l"]
working_directory = "/var/lib/socat-rust/console-demo"
environment = { TERM = "xterm-256color", HOME = "/var/lib/socat-rust/console-demo" }
stderr = "client"
start_timeout_seconds = 5
idle_timeout_seconds = 900
terminate_grace_seconds = 5
max_duration_seconds = 28800
max_processes = 64
terminal = { rows = 24, columns = 80, term = "xterm-256color" }
```

Поля `process`:

- `command` — абсолютный путь, `args` — массив без разбора shell-строки;
- `environment` — полная замена окружения (PATH по умолчанию системный),
  переменные не наследуются;
- `stderr` — `log` (по умолчанию), `client` или `discard`; у PTY stderr процесса
  объединён с терминальным потоком и всегда идёт клиенту;
- `working_directory` — рабочий каталог (абсолютный путь);
- `start_timeout_seconds` — максимальное измеренное время `Command::spawn()`;
  вызов синхронный и не прерывается таймером; превышение закрывает сессию после возврата;
- `idle_timeout_seconds` — простой до завершения, `0` — без ограничения;
- `max_duration_seconds` — предел жизни сессии, `0` — без ограничения;
- `max_processes` — `RLIMIT_NPROC` для UID (учитывается суммарно по UID,
  поэтому профилю нужен отдельный UID; под root ядро может не применять лимит);
- `terminal` — только для `pty`; `term` задаёт `TERM`, явный `environment.TERM`
  должен совпадать. Если HOME не задан, PTY берёт его из `/etc/passwd`.

Процесс запускается в отдельной группе (pty — в отдельной сессии с
управляющим терминалом). При обрыве клиента, `SIGTERM` сервису, простое или
истечении `max_duration_seconds` процессу даётся `terminate_grace_seconds` на
штатный выход, затем всей группе посылается `SIGTERM`, ещё через
`terminate_grace_seconds` — `SIGKILL`. Фоновые задания не переживают лидера.
Зомби и fd на `/dev/ptmx` не остаются.

### Консольный клиент

`console` — интерактивный клиент к pty-профилю: передаёт нажатия, размер окна
и печатает вывод. Сертификаты берутся из флагов или из профиля `--relay`.

```bash
socat-rust console 10.34.0.1:8090 --relay console-demo \
  --ca /etc/socat-rust/pki/demo/client-ca.pem \
  --cert /etc/socat-rust/pki/demo/client.pem \
  --key /etc/socat-rust/pki/demo/client.key
```

Выход из шелла закрывает сессию; код выхода процесса возвращается как код
`socat-rust console`. Протокол версионирован префиксом `\0SRC1`; клиент,
который его не присылает, получает прозрачный поток.

### Требования и ограничения

- сервису нужны `/dev/ptmx` и `/dev/pts` (при `PrivateDevices=true` добавьте
  `DeviceAllow=/dev/ptmx rw` и `DeviceAllow=/dev/pts/* rw`);
- `NoNewPrivileges=true` в юните не даёт `su`/`sudo` повысить права —
  шелл работает от UID сервиса; для root-консоли запускайте профиль под root
  или без `NoNewPrivileges`;
- `ProtectHome=true` скрывает `/home`; задайте `working_directory` и `HOME`
  вне домашних каталогов (юнит разрешает запись в `/var/lib/socat-rust`,
  `/run` и `/var/log`);
- число одновременных сессий ограничивает `max_connections`, дерево процессов —
  `max_processes`, время — `max_duration_seconds` и `idle_timeout_seconds`;
- в журнал пишутся метаданные (pid, причина завершения, код/сигнал), но не
  содержимое сессии, если не включён `verbose_payload_logging`.

### Откат

Старый бинарник и конфиг сохраняйте рядом (`socat-rust.old`, `relays.toml.bak`).
Откат: вернуть файлы, `systemctl restart socat-rust@<профиль>`, проверить
журнал и реальное подключение. Профили без `endpoint` продолжают работать как
TCP и после обновления.

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
sudo install -m 0644 systemd/socat-rust.slice /etc/systemd/system/
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
systemd. Она не взаимозаменяема с приведённым шаблоном `@`. Для неё также установите
`systemd/socat-rust.slice`, чтобы сгенерированные процессы попали в общий cgroup.

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
