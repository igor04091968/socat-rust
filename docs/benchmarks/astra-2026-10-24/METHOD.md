# Как выполнено сравнение и как его повторить

[Результаты](README.md) относятся к одному узлу и одному ресурсному бюджету.
Это сравнение установленных комплектов: Rust + статический OpenSSL 3.5.9
и репозиторный socat + OpenSSL 3.4.0. Вывод о влиянии только языка Rust из этих
данных сделать нельзя. Конфигурация и версии зафиксированы в [environment.json](environment.json).

## Состав стенда

В TCP-режиме клиент, relay и echo-сервер обмениваются синтетическими байтами
через 127.0.0.1. В TLS-режимах клиент подключается к relay по TCP, а relay —
к Python SSL echo-серверу с проверкой CA и имени. Сервер фиксирует TLS 1.2
или TLS 1.3. Оба relay используют одинаковые адреса, сертификат RSA-3072,
набор шифров, буфер 16 КиБ и лимит 32 обслуживаемых соединения.

Тесты измеряют:

- 1500 RTT запроса/ответа по 128 байт после 30 прогревочных обменов;
- 150 новых соединений с первым ответом;
- непрерывную передачу 64 МиБ через одну сессию;
- 16 параллельных потоков по 8 МиБ;
- CPU-время семейства relay, PSS и частные страницы при 32 сессиях;
- бинарную целостность, half-close/EOF, ACL и отказ при неверном имени сервера.

Отправка и чтение больших потоков выполняются одновременно. Ожидание эха
после каждого блока использовалось только в ранней диагностике и исключено
из основных измерений: такой цикл оценивает взаимодействие RTT/буферизации,
а не непрерывную передачу.

Выполнены три повтора. Порядок Rust/socat чередовался; в TCP добавлен прямой
клиент → echo как контроль. Результат — медиана трёх значений, а не лучший
из повторов. p95/p99 вычислены внутри повтора, в отчёте — медиана трёх квантилей.
Скорость считается по полезному объёму одного направления; echo возвращает
столько же обратно. Клиентские потоки и установление сессий входят во время
сценария. CPU Python-клиента и сервера не входит в CPU relay, но расходует
общую CPU-квоту стенда.

## Ограничения

Общий cgroup ограничивался одним CPU и 512 МиБ RAM. Квота действовала
на весь стенд, включая backend и клиент; её throttling сохранён в JSON.
Она также влияла на число автоматически выбираемых Tokio worker-потоков.
Поэтому результаты нельзя переносить на полностью загруженные шесть CPU,
сетевую карту, WAN, долговременную стабильность или банковские транзакции.

PSS зависит от других процессов, разделяющих страницы. Для сравнения памяти
дополнительно сняты Private_Clean + Private_Dirty, приближение USS. Суммарный
RSS процессов socat не считается физическим расходом памяти. Снимки памяти
однократные; потребление под длительной нагрузкой и пики здесь не измерялись.

Превышение max-children описано для конкретного сценария и установленной
сборки socat. Причина не установлена. Проверка прикладного банковского протокола,
внешнего CryptoPro endpoint и отказоустойчивой пары не выполнялась.

## Подготовка к повтору

Нужны Linux с cgroup v2, systemd и /proc, Python 3.11+, штатный socat с OpenSSL
и установленный all-feature бинарник socat-rust v0.1.13. Сценарии ожидают пути
`/usr/bin/socat` и `/usr/local/sbin/socat-rust`. Проверяйте версии и SHA256:

```bash
/usr/local/sbin/socat-rust --version
/usr/bin/socat -V
openssl version
sha256sum /usr/local/sbin/socat-rust
```

Из корня Git-клона, под обычным пользователем с sudo:

```bash
umask 077
bench_user=$(id -un)
bench_group=$(id -gn)
bench_root=$(mktemp -d /var/tmp/socat-comparison.XXXXXX)
bench_unit="socat-comparison-$(date +%s)"
bench_docs=docs/benchmarks/astra-2026-10-24
install -d -m 0700 "$bench_root/clean" "$bench_root/capacity" "$bench_root/memory"
install -m 0600 "$bench_docs/harness/benchmark.py" "$bench_root/clean/benchmark.py"
install -m 0600 "$bench_docs/harness/capacity_probe.py" "$bench_root/capacity/capacity_probe.py"
install -m 0600 "$bench_docs/harness/memory_probe.py" "$bench_root/memory/memory_probe.py"
```

Каждый запуск использует новый каталог. Генератор откажется перезаписывать
ключ, а `memory_probe.py` ожидает ещё не созданный каталог pki. Рабочие
relays.toml, процессы и ключи сценариям не передаются. Код хранит только
временные конфиги, lock-файлы и синтетический сертификат внутри bench_root.
Убедитесь, что есть резерв CPU/RAM: встроенные guard-проверки прерывают тест
при MemAvailable < 768 МиБ или load average > 4; это не замена ресурсным лимитам.

## Запуск под теми же ресурсными ограничениями

Функция создаёт отдельный временный systemd unit. Проверяйте содержимое команд
перед запуском на рабочем узле. На фактическом стенде дополнительно контролировались
PID, состояния и хеши существующих служб до/после; их приватные снимки сюда не входят.

```bash
bench_start_case() {
  bench_case=$1
  bench_script=$2
  sudo systemd-run --unit="$bench_unit-$bench_case" \
    --property="User=$bench_user" --property="Group=$bench_group" \
    --property=CPUQuota=100% --property=CPUWeight=10 --property=Nice=10 \
    --property=MemoryHigh=384M --property=MemoryMax=512M --property=MemorySwapMax=0 \
    --property=TasksMax=192 --property=LimitNOFILE=2048 \
    --property=RuntimeMaxSec=600 --property=TimeoutStopSec=5 \
    --property=KillMode=control-group --property=NoNewPrivileges=yes \
    --property="WorkingDirectory=$bench_root/$bench_case" \
    --property="StandardOutput=append:$bench_root/$bench_case/run.log" \
    --property="StandardError=append:$bench_root/$bench_case/run.log" \
    --setenv=PYTHONDONTWRITEBYTECODE=1 \
    /bin/bash -c 'python3 "$1"; rc=$?; printf "%s\n" "$rc" > exit.status; exit "$rc"' \
    benchmark "$bench_script"
}
bench_start_case clean benchmark.py
```

`systemd-run` возвращает управление до завершения сценария. Контроль:

```bash
sudo systemctl status "$bench_unit-clean.service" --no-pager
cat "$bench_root/clean/run.log"
cat "$bench_root/clean/exit.status"
```

Нулевой exit.status и финальное `COMPLETED 6 84` подтверждают завершение.
Если файла exit.status нет, а unit уже failed/inactive, смотрите journal и лог;
не повторяйте прерванный запуск в тот же каталог без разбора состояния.
Финальный JSON — `$bench_root/clean/results.json`, промежуточный —
results.partial.json. Исходник [benchmark.py](harness/benchmark.py) фиксирует
полные команды обоих relay и все параметры нагрузок.

После завершения основного прогона запускайте следующие случаи **по одному**:

```bash
bench_start_case capacity capacity_probe.py
# Дождаться capacity/exit.status = 0, сохранить capacity/capacity.json и лог.
# Затем:
bench_start_case memory memory_probe.py
# Дождаться memory/exit.status = 0, сохранить memory/memory.json и лог.
```

Не запускайте два случая одновременно: это изменит общий CPU-бюджет.
[capacity_probe.py](harness/capacity_probe.py) использует другой echo-сервер
со счётчиком активных сессий и перепроверяет лимиты 1/2/32 до и после half-close.
Он также делает диагностическую пробу ГОСТ-шифра у socat на временном loopback-порту.
`verify=0` есть только у этой диагностической пробы, не у измеряемых TLS-сессий.
[memory_probe.py](harness/memory_probe.py) использует исходник и тестовый сертификат
из соседнего clean, поэтому основной прогон должен завершиться раньше.

## Функциональные проверки TLS/ГОСТ/PKI

Дополнительно на Astra запускались существующие сценарии репозитория:

- [test_pki_integration.py](../../../scripts/test_pki_integration.py): 25 проверок;
- [test_tls_integration.py](../../../scripts/test_tls_integration.py): 34 проверки
  с GOST fixture и 14 без него для TLS-only бинарника.

Для них в отдельный закрытый каталог были скопированы plain/TLS-only бинарники
того же v0.1.13 и статический тестовый генератор gost-fixture, без установки
в системные пути. Его исходник — [tests/gost_fixture.c](../../../tests/gost_fixture.c);
сборку выполняет [build-static-tls.sh](../../../scripts/build-static-tls.sh).
Это тестовый инструмент; production-ключи ему не передаются. Нагрузка запускалась
отдельным unit с теми же лимитами и TOKIO_WORKER_THREADS=1, без пересечения
с измерениями скорости. Команды сценариев описаны в [TLS_GOST.md](../../TLS_GOST.md)
и [PKI_RU.md](../../PKI_RU.md).

Ouroboros использовался на ноутбуке для изолированной проверки двух функций
стенда, но не для численных измерений. Его runtime требует Python 3.12,
системный Python Astra на стенде — 3.11. Трассировка не добавлялась в relay.

## Сохранение результатов и уборка

Сохраните JSON и логи, проверьте отсутствие тестовых процессов и слушающих
портов. До завершения тестов не удаляйте каталоги и lock-файлы. Для принудительной
остановки используется только точное имя созданного тестового unit; рабочие
`socat-rust@*.service` эта процедура не затрагивает. После остановки и экспорта
результатов удаляются только созданные временные каталоги и синтетические ключи.
На исходном стенде отсутствие оставшихся процессов/портов и неизменность
рабочих профилей проверены после уборки.

Опубликованные сценарии — точные копии использованных файлов. Данные обезличены
в объёме, указанном в [отчёте](README.md#материалы), численные значения не менялись.
Проверка целостности из каталога отчёта: `sha256sum -c SHA256SUMS`.
