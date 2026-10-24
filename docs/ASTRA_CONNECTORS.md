# Управление socat-rust на Astra 1.8

Установлены /usr/local/sbin/socat-connectors и шаблон socat-rust@.service.
Требуется Python 3.11+ (stdlib, без pip). Бинарник и relays.toml сохраняются.

sudo socat-connectors check
socat-connectors list
sudo socat-connectors start
socat-connectors status
sudo socat-connectors stop
sudo socat-connectors restart --relay bnk2450001
sudo socat-connectors enable
sudo socat-connectors disable
journalctl -u socat-rust@bnk2450001.service -n 50 --no-pager

enable/disable управляют только автозагрузкой; start/stop — текущим запуском.
Без аргументов показывается status. В группу входят существующие профили
bnk2450001..bnk2450037 из relays.toml. Отсутствующие номера не выдумываются.
Добавленные в этот диапазон профили попадут
в следующий вызов скрипта автоматически; для них отдельно повторите enable.
Перед удалением профиля выполните stop и disable с --relay, пока он есть
в конфигурации. Прямые команды systemctl работают независимо от скрипта.

Программа работает в foreground под systemd, без --daemon. Сам бинарник
сначала готовит журналы/lock, затем сбрасывает root до UID/GID профиля.
Его flock защищает от второго экземпляра, включая ручной --daemon.
status распознаёт ручные процессы как manual/running (для проверки /proc нужен root).
start при наличии ручного процесса останавливается с подсказкой restart.
stop завершает и systemd, и проверенные ручные экземпляры через SIGTERM.
restart переводит ручные экземпляры под systemd и прерывает их текущие соединения.
Перед сигналом проверяются бинарник, argv, UID, inode удерживаемого flock;
сигнал передаётся через pidfd, чтобы не затронуть повторно использованный PID.
При незавершении за10секунд возвращается ошибка; SIGKILL не отправляется. Не удаляйте lock-файл запущенного процесса.
PrivateTmp намеренно не включён: профиль14 использует /tmp/bnk2450014.lock.

После сбоя — повтор через15секунд, не более5запусков за300секунд.
После устранения причины:
sudo systemctl reset-failed socat-rust@bnk2450011.service
sudo socat-connectors start --relay bnk2450011

На момент установки профиль11 требует10.34.0.1:8011, которого нет на сервере.
Для его работы нужен штатно назначенный адрес или отдельное согласованное
изменение listen в конфигурации. При start/restart профиль без локального IPv4 пропускается с сообщением,
остальные запускаются; exitcode1 сообщает о неполном запуске.
Скрипт не меняет адреса и маршруты.
Состояние active/running подтверждает процесс, а не доступность upstream.
Payload-логи и их настройки унаследованы от relays.toml.

Откат: sudo socat-connectors disable; sudo socat-connectors stop;
удалить только установленные socat-connectors и socat-rust@.service,
затем sudo systemctl daemon-reload. relays.toml и бинарник не удалять.
