# Установка

[← к содержанию](../README.md#документация)

1. [Сборка](#сборка)
2. [Установка узла на Linux](#установка-узла-на-linux)
3. [Служба узла (systemd)](#служба-узла-systemd)
4. [Сервер обнаружения как служба](#сервер-обнаружения-как-служба)
5. [Файрвол](#файрвол)
6. [Каталог данных](#каталог-данных)
7. [Обновление и удаление](#обновление-и-удаление)
8. [Windows](#windows)

Один бинарник `dvpn` — это и узел, и сервер обнаружения, и все команды управления. Готовых сборок версии 4 пока
нет (автоматическая сборка релизов в планах), поэтому DVPN собирается из исходников.

## Сборка

### Зависимости

Нужны Rust **1.88+** и компоновщик C (сам код на чистом Rust, внешних библиотек нет).

| Система | Команда |
|---|---|
| Debian, Ubuntu | `sudo apt install build-essential git curl` |
| Fedora | `sudo dnf install gcc git curl` |
| Arch | `sudo pacman -S base-devel git` |
| Alpine | `sudo apk add build-base git curl` |

Rust — через [rustup](https://rustup.rs/) (пакеты дистрибутивов часто слишком старые):

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustc --version          # 1.88 или новее
```

### Сборка

```shell
git clone https://git.mihprog.com/DVPN/DVPN.git
cd DVPN
git switch DVPN-rs
cargo build --release
./target/release/dvpn -v
```

Бинарник — `target/release/dvpn`. Собирать можно на любой машине и копировать на узлы той же архитектуры:
бинарник зависит только от glibc (или musl, если собирать под `x86_64-unknown-linux-musl`).

**Статическая сборка** (для старых систем и роутеров):

```shell
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# target/x86_64-unknown-linux-musl/release/dvpn
```

**Под Windows** с Linux:

```shell
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu   # нужен mingw-w64
```

## Установка узла на Linux

### Что нужно в системе

| Функция | Что требуется |
|---|---|
| TUN, адреса на нём | root или `CAP_NET_ADMIN`; модуль `tun` (есть почти везде, `/dev/net/tun`) |
| системные маршруты и `ip rule` ([routing.md](routing.md#системные-маршруты)), флаг multicast для mDNS | `ip` (iproute2) |
| шлюз и ACL ([exit.md](exit.md#узел-шлюз-gateway), [acl.md](acl.md)) | `nft` (nftables) |
| пересылка на шлюзе | запись в `/proc/sys` (root) |
| split DNS для `.dvpn` | systemd-resolved и `resolvectl` (необязательно) |

Узлу с маршрутами, шлюзом, ACL и DNS проще всего работать от **root** — так и устроена служба ниже. Сервер
обнаружения root не нужен.

### Размещение файлов

Рекомендуемая схема — каталог `/opt/dvpn` с бинарником и данными плюс ссылка в `PATH`:

```shell
sudo install -d -m 700 /opt/dvpn
sudo install -m 755 target/release/dvpn /opt/dvpn/dvpn
sudo ln -sf /opt/dvpn/dvpn /usr/local/bin/dvpn
```

По умолчанию `dvpn` хранит данные **рядом с настоящим бинарником** (ссылка раскрывается), поэтому любая команда
`sudo dvpn …` сама работает с `/opt/dvpn/config.toml` — `--dir` указывать не нужно.

> Другой каталог (например, `/etc/dvpn`) тоже можно: тогда указывайте его каждой команде (`--dir /etc/dvpn`) или в
> `DVPN_DIR`. Учтите, что `sudo` по умолчанию сбрасывает переменные окружения.

### Первичная настройка

```shell
sudo dvpn show-key           # создаст /opt/dvpn/config.toml (права 0600) и покажет ключ узла
```

Дальше — по ситуации:

* **новая сеть:** добавьте сервер обнаружения в `config.toml` и создайте группу —
  [quickstart.md](quickstart.md#2-алиса-группа);
* **вход в существующую:** `sudo dvpn group join` и вставьте invite — серверы обнаружения придут из него.

Проверьте запуском в консоли:

```shell
sudo dvpn                    # Ctrl+C — остановить; маршруты и правила снимутся
```

В логе должны быть `Connection status connected` и строки о найденных участниках. Если всё в порядке —
оформите узел службой.

## Служба узла (systemd)

```ini
# /etc/systemd/system/dvpn.service
[Unit]
Description=DVPN node
Documentation=https://git.mihprog.com/DVPN/DVPN
# сеть должна быть поднята: узел сразу открывает сокет и ищет серверы обнаружения
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/dvpn/dvpn --dir /opt/dvpn
# /run/dvpn: unix-сокет API для dvpn status, dvpn exit и т.п.
RuntimeDirectory=dvpn
# узел сам убирает маршруты, ip rule, таблицы nft и DNS по SIGTERM
KillSignal=SIGTERM
TimeoutStopSec=10
Restart=on-failure
RestartSec=5
# немного изоляции, совместимой с работой узла
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```shell
sudo systemctl daemon-reload
sudo systemctl enable --now dvpn
systemctl status dvpn
journalctl -u dvpn -f          # лог; уровень — [app] log_level в config.toml
```

Не добавляйте `ProtectSystem=strict` и `ProtectKernelTunables=yes`: узлу нужно писать свой `config.toml` (новые
сертификаты, psk), а шлюзу — `/proc/sys`.

### Управление работающей службой

Команды обращаются к службе через `/run/dvpn/dnet.sock` (`dnet` — `[net] tun_name`) и читают тот же
`config.toml`, поэтому запускаются через `sudo`:

```shell
sudo dvpn status
sudo dvpn neighbors
sudo dvpn exit --v4 vps1       # служба подхватит изменение за секунду
sudo dvpn node set phone --relay
```

Изменения `[exit]`, записей группы (`node set`, `revoke`, `acl set`) применяются на лету. Остальные правки
`config.toml` (порты, серверы, `[net]`, `[gateway]`, `[dns]`) — после `sudo systemctl restart dvpn`.

### Без TUN

Узел-ретранслятор или узел только для записей группы может работать без TUN-интерфейса:
`ExecStart=/opt/dvpn/dvpn --dir /opt/dvpn -d` (или без секции `[net]`). Тогда API слушает UDP `127.0.0.1:9902`.

### OpenRC и другие системы

Узлу нужно одно: запустить `/opt/dvpn/dvpn --dir /opt/dvpn` от root после поднятия сети и останавливать его
сигналом SIGTERM (тогда он уберёт за собой маршруты). Пример для OpenRC:

```sh
#!/sbin/openrc-run
# /etc/init.d/dvpn
command=/opt/dvpn/dvpn
command_args="--dir /opt/dvpn"
command_background=yes
pidfile=/run/dvpn.pid
output_log=/var/log/dvpn.log
error_log=/var/log/dvpn.log
depend() { need net; }
start_pre() { checkpath -d -m 0755 /run/dvpn; }
```

## Сервер обнаружения как служба

Серверу не нужны root и TUN. Удобно запустить его от отдельного непривилегированного пользователя с собственным
каталогом данных — systemd создаст и то, и другое сам:

```ini
# /etc/systemd/system/dvpn-server.service
[Unit]
Description=DVPN discovery server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/dvpn/dvpn --dir /var/lib/dvpn-server server
# временный пользователь и каталог /var/lib/dvpn-server, который переживает перезапуски
DynamicUser=yes
StateDirectory=dvpn-server
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```shell
sudo systemctl daemon-reload
sudo systemctl enable --now dvpn-server
journalctl -u dvpn-server | grep 'Public key'     # ключ для [servers.*] key у узлов
```

Ключ сервера хранится в `/var/lib/dvpn-server/config.toml` (`[local_server]`); сделайте его копию — с новым
ключом пришлось бы менять конфиг у всех узлов.

* Другой порт или адрес: `server -p 7000` или `server -a 203.0.113.10` в `ExecStart`. Если у сервера **несколько
  IP**, обязательно укажите `-a <публичный IP>` ([discovery.md](discovery.md#сервер-обнаружения)).
* Порт ниже 1024 — добавьте `AmbientCapabilities=CAP_NET_BIND_SERVICE`.
* Сервер и узел на одной машине — две службы, два каталога данных (у них разные ключи).

## Файрвол

| Кто | Что открыть |
|---|---|
| сервер обнаружения | входящий UDP на его порт (6485) |
| узел со статическим адресом (`--static`) | входящий UDP на его `bind_port` |
| узел-шлюз | пересылку `dnet` ↔ WAN, если в `FORWARD` запрет по умолчанию |
| обычный узел за NAT | ничего: hole punching работает исходящими пакетами |

Примеры для сервера:

```shell
sudo ufw allow 6485/udp                                    # ufw
sudo firewall-cmd --permanent --add-port=6485/udp && sudo firewall-cmd --reload   # firewalld
sudo nft add rule inet filter input udp dport 6485 accept  # nftables (своя таблица filter)
```

Трафик внутри сети идёт через интерфейс `dnet`: если на узле файрвол с запретом входящих, разрешите нужное на
`dnet` или доверьте его целиком (`firewall-cmd --zone=trusted --add-interface=dnet`). Права участников внутри сети
удобнее задавать [ACL](acl.md).

## Каталог данных

| Файл | Назначение |
|---|---|
| `config.toml` | ключ узла, группа (psk, сертификат, у админа — секрет группы), серверы обнаружения, порты, TUN, маршруты, шлюзы, логи |
| `state.bin` | записи группы, подписанные её ключом: сертификаты участников, отзывы, смены psk, правила ACL |

* По умолчанию файлы лежат рядом с бинарником; другой каталог — `--dir` или `DVPN_DIR`.
* При первом запуске любой команды создаётся `config.toml` с новым ключом узла. Права — `0600`: в нём секреты.
  Команды, меняющие конфиг, сохраняют ваши комментарии и порядок секций.
* Приватный ключ можно не хранить в файле, а передавать переменной `DVPN_PRIVATE_KEY` (в службе —
  `Environment=` или `EnvironmentFile=` с правами `0600`).
* Список участников на диске не хранится: узел узнаёт их от сервера обнаружения и соседей.

**Резервная копия.** У обычного участника достаточно сохранить `config.toml` (ключ узла и сертификат). У админа —
обязательно `dvpn group backup` ([groups.md](groups.md#резервная-копия-админа)): без секрета группы ею нельзя
управлять.

## Обновление и удаление

**Обновление:**

```shell
cd DVPN && git pull && cargo build --release
sudo systemctl stop dvpn
sudo install -m 755 target/release/dvpn /opt/dvpn/dvpn
sudo systemctl start dvpn
```

Ключи, группа и записи хранятся в `config.toml` и `state.bin` и при обновлении не меняются. Переход с 3.x —
[migration.md](migration.md).

**Удаление:**

```shell
sudo systemctl disable --now dvpn dvpn-server
sudo rm /etc/systemd/system/dvpn.service /etc/systemd/system/dvpn-server.service /usr/local/bin/dvpn
sudo systemctl daemon-reload
sudo rm -r /opt/dvpn            # вместе с ключами! у админа — сначала group backup
```

После остановки в системе не должно остаться ничего от DVPN: `ip rule` без правил 7346/7347, нет таблиц
`nft list tables | grep dvpn`. Если узел был убит `kill -9`, правила, таблица маршрутов и ACL снимутся при следующем запуске, а таблица
шлюза — если `[gateway]` ещё в конфиге. Вручную: `ip rule del priority 7346; ip rule del priority 7347` (то же с
`ip -6`), `ip route flush table 7347` (и `-6`), `nft delete table inet dvpn_gw`, `nft delete table inet dvpn_acl`,
записи NDP proxy — `ip -6 neigh show proxy`.

## Windows

> Сборка под Windows проверена только компиляцией: запуск ещё не тестировался. Системные маршруты, kill switch,
> шлюз и ACL на Windows пока не работают — их поддержка запланирована вместе со сборкой релизов и тестами на
> Windows.

1. Скачайте [Wintun](https://www.wintun.net/) и положите `wintun.dll` (из папки под вашу архитектуру, обычно
   `bin/amd64`) **рядом с `dvpn.exe`**.
2. Запускайте из консоли **от имени администратора**.
3. Разрешите `dvpn.exe` в брандмауэре Windows (входящий UDP).

API на Windows всегда UDP `127.0.0.1:9902`. Запуск службой Windows пока не поддерживается.
