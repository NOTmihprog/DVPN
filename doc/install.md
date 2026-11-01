# Установка

[← к содержанию](../README.md#документация)

## Сборка

Нужен Rust 1.85+ ([rustup.rs](https://rustup.rs/)). Готовых бинарников версии 4 пока нет: автоматическая сборка
релизов в планах.

```shell
git clone https://git.mihprog.com/DVPN/DVPN.git
cd DVPN
git switch DVPN-rs
cargo build --release
# бинарник: target/release/dvpn (dvpn.exe на Windows)
```

Один бинарник — и узел, и сервер обнаружения, и все команды управления.

### Кросс-сборка под Windows

```shell
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu   # нужен mingw-w64
```

## Linux

Узлу нужен TUN-интерфейс, а для этого — root или capability `CAP_NET_ADMIN`:

```shell
sudo setcap cap_net_admin+ep target/release/dvpn   # чтобы запускать без sudo
```

Что ещё узел делает в системе и что для этого нужно:

| Функция | Что требуется |
|---|---|
| TUN, адреса на нём | `CAP_NET_ADMIN` |
| Системные маршруты и `ip rule` ([маршруты](routing.md#системные-маршруты)), флаг multicast для mDNS | `CAP_NET_ADMIN`, `ip` (iproute2) в `PATH` |
| Шлюз, ACL ([exit](exit.md#узел-шлюз-gateway), [acl](acl.md)) | `nft` (nftables) в `PATH` |
| sysctl пересылки на шлюзе | запись в `/proc/sys` (root) |
| Split DNS для `.dvpn` | systemd-resolved и `resolvectl` (необязательно) |
| API на unix-сокете `/run/dvpn/<tun>.sock` | право писать в `/run/dvpn` (под systemd — `RuntimeDirectory=dvpn`) |

Без прав на `/run/dvpn` API автоматически слушает `127.0.0.1:9902` (или укажите адрес `-a`).

## Windows

> Сборка под Windows проверена только компиляцией: запуск ещё не тестировался. Системные маршруты, kill switch,
> шлюз и ACL на Windows пока не работают — их поддержка запланирована вместе со сборкой релизов.

1. Скачайте [Wintun](https://www.wintun.net/) и положите `wintun.dll` (из папки под вашу архитектуру,
   обычно `bin/amd64`) **рядом с `dvpn.exe`**.
2. Запускайте из консоли **от имени администратора**.
3. Разрешите `dvpn.exe` в брандмауэре Windows (входящий UDP), иначе пиры не смогут достучаться.

API на Windows всегда UDP `127.0.0.1:9902`.

## Каталог данных

| Файл | Назначение |
|---|---|
| `config.toml` | ключ узла, группа (psk, сертификат, у админа — секрет группы), серверы обнаружения, порты, TUN, маршруты, шлюзы, логи |
| `state.bin` | записи группы, подписанные её ключом: сертификаты участников, отзывы, смены psk, правила ACL |

Список участников на диске не хранится: узел узнаёт их от сервера обнаружения и соседей, имя и адрес каждого —
из его сертификата.

* По умолчанию файлы лежат **рядом с бинарником**.
* Другой каталог: опция `--dir <путь>` или переменная окружения `DVPN_DIR` — действует для всех команд, в том
  числе для управления работающим узлом.
* При первом запуске любой команды создаётся `config.toml` по умолчанию с новым ключом узла (`[identity]`).
* `config.toml` записывается с правами `0600`: в нём секреты. Команды, меняющие конфиг, сохраняют ваши
  комментарии и порядок секций.
* Приватный ключ можно не хранить в файле, а передавать переменной окружения `DVPN_PRIVATE_KEY`.

Работающий узел следит за `config.toml` и `state.bin`: изменения через `dvpn exit`, `dvpn node set`,
`dvpn group revoke` и т.п. подхватываются за секунду, перезапуск не нужен.

## Запуск как службы (systemd)

Пример для узла, установленного в `/opt/dvpn`:

```ini
# /etc/systemd/system/dvpn.service
[Unit]
Description=DVPN node
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/dvpn/dvpn --dir /opt/dvpn
RuntimeDirectory=dvpn
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```shell
sudo systemctl daemon-reload
sudo systemctl enable --now dvpn
journalctl -u dvpn -f
```

Команды управления (`dvpn status`, `dvpn exit …`) запускайте с тем же каталогом: `dvpn --dir /opt/dvpn status`
или `export DVPN_DIR=/opt/dvpn`.

При остановке (SIGTERM, Ctrl+C) узел убирает за собой маршруты, правила `ip rule`, таблицы nftables, NDP proxy
и настройки DNS. Если узел упал, всё это снимается при следующем старте.

### Сервер обнаружения как служба

То же самое с `ExecStart=/opt/dvpn/dvpn --dir /opt/dvpn server`. Root серверу не нужен: можно добавить
`User=dvpn`, если порт ≥ 1024 (по умолчанию 6485). Подробнее — [обнаружение узлов](discovery.md#сервер-обнаружения).

## Обновление

Остановите службу, замените бинарник, запустите снова. Ключи и группа хранятся в `config.toml` и `state.bin` и
не меняются. Узлы разных сборок одной версии протокола совместимы; переход с 3.x — [migration.md](migration.md).
