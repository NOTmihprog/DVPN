# API

[← к содержанию](../README.md#документация)

Узел предоставляет локальный API для внешних программ: GUI и TUI, скриптов мониторинга, своих сервисов поверх
сети. Через него же работают команды `dvpn status`, `neighbors`, `routes`, `path`, `ping`, `metrics`.

## Транспорт

Датаграммы [msgpack](https://msgpack.org/):

* Linux и macOS, узел от root или службой: unix-сокет `/run/dvpn/<tun_name>.sock`;
* узел от пользователя: unix-сокет `$XDG_RUNTIME_DIR/dvpn/<tun_name>.sock` (обычно `/run/user/<uid>/dvpn/`);
* без TUN (`-d`, нет `[net]`) — так же, имя сокета `dnet.sock` или по `[net] tun_name`;
* Windows (и где нет ни того, ни другого каталога): UDP `127.0.0.1:9902`;
* свой адрес: `dvpn -a 127.0.0.1:9000` или `dvpn -a /path/to/api.sock` — и для узла, и для команд.

Команды `dvpn` и `dvpn-client` ищут узел в том же порядке: `DVPN_API`, `/run/dvpn/…`, `$XDG_RUNTIME_DIR/dvpn/…`,
UDP `127.0.0.1:9902`.

## Доступ

Не выставляйте API наружу: кто может слать в него запросы, управляет узлом.

**Unix-сокет** защищён правами файла, токены не нужны:

* `/run/dvpn/<tun>.sock` — `0660`, группа `dvpn`, если она есть. Пользоваться узлом без `sudo`:
  `sudo groupadd dvpn && sudo usermod -aG dvpn $USER` (и перезайти), затем перезапустить узел;
* `$XDG_RUNTIME_DIR/dvpn/<tun>.sock` — `0600` в каталоге `0700`: только сам пользователь;
* сокет по `-a <путь>` — `0600`.

**UDP** на `127.0.0.1` доступен любому локальному пользователю, поэтому:

* чтение (`get`) — без токена; с `[api] token = "all"` в `config.toml` — тоже по токену;
* изменения (`set`, `del`, `route`) — только с полем `"token"` в каждом запросе;
* токен узел создаёт при каждом запуске и пишет в `api-<port>.token`: Linux — `/run/dvpn/` (`0640`, группа
  `dvpn`) или `$XDG_RUNTIME_DIR/dvpn/` (`0600`); Windows — `%ProgramData%\dvpn\` (только SYSTEM и
  администраторы) или `%LOCALAPPDATA%\dvpn\` (узел не от администратора);
* `dvpn-client` и `dvpn` берут токен из `DVPN_API_TOKEN` или из этого файла сами;
* без токена — `not_permitted`. Если файл токена записать некуда, API по UDP только для чтения.

На Windows позже — именованный канал (named pipe) с правами доступа вместо UDP, вместе со службой Windows.

## Подключение

Каждое сообщение — msgpack-словарь с полем `type`. Версия протокола API — **4**.

1. Клиент отправляет `{"type": "init", "name": "my-app", "version": 4}`. Узел отвечает:

   ```
   {"type": "init", "version": 4, "min_version": 4,     # версии API, которые узел обслуживает
    "key": "DZVS…", "name": "alice",                    # этот узел
    "group": "<id группы>", "group_name": "home",
    "admin": true,                                      # есть ли у узла секрет группы
    "node_version": "4.2.2"}
   ```

   Без `version` или с версией, которую узел не обслуживает, приходит
   `{"type": "error", "err": "version_unsupported", "msg": "…", "min": 4, "max": 4}`, и клиент не подключён.
   Повторный `init` допустим (например, после `close`).
2. Пока клиент не подключён, на запросы приходит `{"type": "close"}` — нужно снова отправить `init`.
3. Узел шлёт клиенту `{"type": "ping"}` раз в 15 с; клиент отвечает `{"type": "pong"}`, иначе примерно через 45 с
   соединение закрывается.
4. Отключиться — `{"type": "close"}`.

Запросы `get` / `set` / `del` / `route` содержат произвольный `id`; ответ приходит как
`{"type": "res", "id": <тот же id>, "res": <результат>}`.

### Ошибки

Неудачный запрос отвечает без `res`, с кодом и текстом:

```
{"type": "res", "id": 1, "err": "key_validate_error", "msg": "bob: no such node key or name"}
```

`err` — стабильный код для программ, `msg` — текст для людей (может меняться).

Ответ должен помещаться в одну датаграмму (до 65 000 байт). Больший приходит ошибкой `too_large`; списки
`members`, `neighbors`, `routes` (`mesh` и `ckr`) и `peers` в `metrics` можно просить частями: `"offset": 0,
"limit": 100`. Ответы `routes` и `metrics` содержат `mesh_total`, `ckr_total`, `peers_total`. `dvpn-client`
собирает части сам. Событие больше датаграммы узел не отправляет (пишет в журнал). `nil` в `res` — это результат
(«нет данных», «нет пути»), а не ошибка. Сообщение неизвестного типа — `{"type": "error", "err":
"unknown_type", "msg"}`.

| код | когда |
|---|---|
| `version_unsupported` | `init` без `version` или с неподдерживаемой |
| `too_large` | ответ не помещается в датаграмму: просить частями (`offset`, `limit`) |
| `not_permitted` | UDP: нет или неверный токен (см. [Доступ](#доступ)) |
| `unknown_type` | неизвестный `type` сообщения |
| `unknown_request` | неизвестный `req` |
| `bad_param` | не хватает параметра или он не того типа (`req`, `arg`, `addr`) |
| `key_validate_error` | `key` не передан, или нет узла с таким ключом, началом ключа или именем |
| `key_ambiguous` | начало ключа подходит нескольким узлам |
| `server_not_found` | `addr` — не сервер обнаружения этого узла |
| `name_not_str`, `addr_validate_error`, `endpoint_validate_error`, `sub_args_not_dict`, `force_not_bool` | `set peer`: неверное поле |
| `peer_not_exist`, `error_delete_self_peer` | `del` |
| `not_int`, `out_of_range`, `route_exist`, `route_not_exist`, `not_permission` | `route` |
| `gateway_unknown`, `gateway_self`, `dns_invalid`, `sources_invalid`, `table_invalid`, `config_write` | `set exit` |
| `not_admin`, `clock_untrusted` | операции админа: у узла нет секрета группы; часы раньше сборки (нужен NTP) |
| `member_unknown`, `member_ambiguous`, `member_not_seen` | участник не найден, имя подходит нескольким, сертификата ещё нет |
| `addr_taken`, `addr_invalid`, `route_invalid`, `endpoint_invalid`, `no_address`, `config_read` | `set invite`, `set node` |
| `revoke_self`, `acl_parse` | `set revoke`, `set acl` |

Узлы везде обозначаются полем `key` — публичным ключом узла (base64url). В запросах можно передать однозначное
начало ключа или имя участника.

Пример на Python:

```python
import socket, msgpack
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
node = ("127.0.0.1", 9902)
s.sendto(msgpack.dumps({"type": "init", "name": "example", "version": 4}), node)
print(msgpack.loads(s.recv(65535)))   # {'type': 'init', 'version': 4, 'key': 'DZVS...', 'name': 'alice', ...}
s.sendto(msgpack.dumps({"type": "get", "id": 1, "req": "status"}), node)
print(msgpack.loads(s.recv(65535)))   # {'type': 'res', 'id': 1, 'res': {'key': 'DZVS...', 'name': 'alice', ...}}
```

С unix-сокетом — `socket.AF_UNIX`, `SOCK_DGRAM`, и клиенту нужен свой адрес (`s.bind("/tmp/my-app.sock")`).

## get

`{"type": "get", "id": 1, "req": "<запрос>", ...параметры}`

### Состояние узла

| `req` | параметры | результат |
|---|---|---|
| `status` | | словарь: `key`, `name`, `group`, `group_name`, `admin`, `prefixes` (адреса и подсети из сертификата), `ula` (IPv6-адрес узла в группе), `relay`, `cert_days`, `epoch` (эпоха psk), `servers` (`[{addr, connected}]`), `exit_v4`, `exit_v6` (имя текущего шлюза или nil), `kill_switch`, `local_addr`, `uptime_secs` |
| `version` | | `{api, api_min, node, wire}`: версии API, программы узла и протокола на проводе (`"dvpn/4"`) |
| `neighbors` | | список прямых соседей: `key`, `name`, `endpoint`, `rtt_ms`, `alive`, `session_secs`, `tx_packets`, `tx_bytes`, `rx_packets`, `rx_bytes` |
| `routes` | | `{"mesh": [{key, name, via, via_name, cost}], "ckr": [{net, to, system}]}` |
| `path` | `key` | список хопов `[{key, name}]` до участника (последний — он сам) или nil |
| `ping` | `key` | `{"rtt_ms": 12.3, "via": "direct" \| "relays"}` или nil, если ответа нет за 2 с |
| `metrics` | | счётчики, см. [ниже](#metrics) |

`ping` отвечает не сразу (ждёт ответа участника), остальные запросы при этом обслуживаются.

### Группа и участники

| `req` | параметры | результат |
|---|---|---|
| `group` | | группа глазами этого узла, без секретов, см. [ниже](#group) |
| `members` | | все участники, в том числе офлайн и исключённые, см. [ниже](#members) |

#### group

```
{
  "id": "<id группы>", "name": "home", "admin": true,
  "epoch": 3,                                   # эпоха psk, с которой узел шлёт
  "prev_epoch_until": 1793650000 | nil,         # до этого времени ещё принимается прошлый psk
  "next_epoch": {"epoch": 4, "at": 1793650120,  # объявленная смена psk (unix-время перехода)
                 "started": false,              # время перехода уже наступило
                 "has_key": true} | nil,        # у узла есть новый psk (нет — после перехода связи не будет)
  "cert": {"not_after": 1796000000, "days": 24, "invite": false},   # свой сертификат; invite — ещё от invite
  "obfs": {"junk_count": [0, 0], "junk_size": [40, 40], "signatures": 0,
           "init_pad": [0, 0], "resp_pad": [0, 0], "data_pad": [0, 0]},   # профиль маскировки: размеры и счётчики
  "servers": [{"addr": "203.0.113.1:6485", "key": "...", "connected": true}],
  "statics": [{"key": "...", "name": "vps" | nil, "endpoints": ["vps.example.org:8647"], "direct": true}]
}
```

Время везде — unix-секунды.

#### members

Список, по имени. Участники берутся из записей группы, из рукопожатий и от серверов обнаружения; для каждого —
самый свежий сертификат.

```
{
  "key": "...", "name": "bob",
  "addrs": ["10.10.33.2"],                      # адреса узла (/32, /128)
  "routes": ["192.168.1.0/24"],                 # подсети за ним
  "roles": ["relay"],                           # admin, relay, exit_v4, exit_v6
  "not_after": 1796000000, "days": 24, "expired": false,
  "invite": false,                              # сертификат ещё от invite (админ не видел узел в сети)
  "revoked": false,
  "self": false,                                # это сам узел
  "online": true,                               # есть путь: напрямую или через ретрансляторы
  "direct": false                               # есть живая прямая связь
}
```

Исключённый узел, сертификат которого этот узел не видел, приходит с `name`, `not_after`, `days` = nil и пустыми
списками.

### Выход в интернет и доступ

| `req` | параметры | результат |
|---|---|---|
| `exit` | | `[exit]` и выбранные шлюзы, см. [ниже](#exit) |
| `acl` | | правила доступа группы, см. [ниже](#acl) |

#### exit

```
{
  "v4": [{"gateway": "vps",                     # как записано в [exit]: имя или ключ
          "key": "..." | nil, "name": "vps" | nil,   # кого это значит (nil — неизвестный участник)
          "alive": true}],                      # есть путь до него
  "v6": [...],
  "kill_switch": true,                          # действует ли kill switch (по умолчанию да)
  "dns": ["1.1.1.1"],                           # DNS через шлюз
  "sources": ["10.10.33.2/32"],                 # через шлюз только эти источники (v4 и v6 вместе)
  "table": 100 | nil,                           # своя таблица маршрутизации
  "active": {"v4": {"key", "name"} | nil, "v6": ...},   # шлюз, через который идёт интернет сейчас
  "blocked": {"v4": false, "v6": false}         # kill switch блокирует интернет: шлюзы есть, живых нет
}
```

#### acl

```
{
  "set": true,                                  # админ задал правила (false — все ко всем)
  "default": "deny",
  "toml": "default = \"deny\"\n...",            # как dvpn acl show: имена вместо ключей
  "tags": {"servers": ["vps"]},
  "rules": [{"from": ["alice"], "to": ["servers"], "proto": "tcp",     # any, tcp, udp, icmp
             "ports": [[22, 22], [8000, 8080]], "allow": true}]
}
```

### Участники и серверы

> Устаревшие (как в v3): вместо `peer_*` — `members` и `neighbors`, вместо `server_*` — `group` (`servers`). Они
> остаются, но новых полей не получат.

| `req` | параметры | результат |
|---|---|---|
| `key` | | свой ключ |
| `peers` | | ключи известных участников |
| `peer_exist` | `key` | bool |
| `peer_name`, `peer_addr` | `key` | строка или nil |
| `peer_sub_args` | `key` | словарь доп. параметров или nil |
| `peer_sub_arg` | `key`, `arg` | значение параметра |
| `peer_endpoint` | `key` | `[ip, port]` или nil |
| `peer_status` | `key` | есть ли прямое соединение |
| `peer_ping` | `key` | RTT в мс (0, если неизвестен) |
| `peer_crypto_status` | `key` | `"noise_ikpsk2"`, если есть сессия, иначе `"no"` |
| `servers` | | список `[ip, port]` серверов обнаружения |
| `server_status` | `addr: [ip, port]` | подключён ли сервер |
| `server_key` | `addr` | публичный ключ сервера (bytes) |
| `server_last_announce`, `server_last_search`, `server_last_response` | `addr` | unix-время, 0 — никогда |
| `local_addr` | | `[ip, port]` UDP-сокета узла |

### metrics

```
{
  "uptime_secs": 3600,
  "handshakes": 42,                                   # завершённые рукопожатия (обе роли, смены ключей)
  "relayed": {"packets": 1200, "bytes": 1500000},     # передано дальше для других (ретранслятор)
  "drops": {"no_route": 0, "no_session": 3, ...},     # отброшенные пакеты по причинам
  "peers": [
    {"key": "...", "name": "bob",
     "ip_tx": {"packets": .., "bytes": ..}, "ip_rx": {...},       # IP-трафик с участником, любым путём
     "wire_tx": {...}, "wire_rx": {...}}                          # пакеты прямой сессии с ним
  ]
}
```

Причины отбрасывания — [troubleshooting.md](troubleshooting.md#счётчики-dvpn-metrics). Счётчики считаются с
запуска узла.

## set / del

### set exit

То же, что `dvpn exit`: узел пишет `[exit]` в свой `config.toml` (остальной файл не трогает) и сразу выбирает
шлюзы заново. Ответ — как у `get exit`.

```
{"type": "set", "id": 7, "req": "exit",
 "v4": ["vps", "home"], "v6": [],               # шлюзы по приоритету: имена или ключи; [] или nil — нет
 "kill_switch": false,                          # nil — по умолчанию (включён)
 "dns": ["1.1.1.1"], "sources": ["10.10.33.2"], # списки целиком заменяют старые
 "table": 100,                                  # nil — убрать
 "clear": true}                                 # сначала убрать весь [exit]
```

Поля, которых нет, не меняются. Ошибки: `gateway_unknown` (не ключ и не имя ровно одного участника, или
исключённый), `gateway_self`, `dns_invalid`, `sources_invalid`, `table_invalid` (0, 253–255 и таблица DVPN
заняты), `bad_param`, `config_write` (не удалось записать `config.toml`). При ошибке ничего не меняется.

### Операции админа

Только на узле с секретом группы (иначе `not_admin`) — то же, что `dvpn group invite/revoke/rotate`, `dvpn node
set`, `dvpn acl set/clear`. Узел сразу применяет новые записи группы и рассылает их серверам обнаружения и
соседям. Участник в `key` — ключ, начало ключа или имя.

```
{"type": "set", "req": "invite", "name": "carol",          # имя нового узла (обязательно)
 "addr": "10.10.33.40",                                     # необязательно: иначе свободный в сети группы
 "ttl_hours": 24, "statics": ["vps.example.org:8647"],      # статические адреса этого узла для новичка
 "routes": ["192.168.5.0/24"], "relay": false}
→ {"invite": "...", "name": "carol", "addr": "10.10.33.40", "until": 1793736000,
   "warnings": ["no [servers] and no statics: ..."]}

{"type": "set", "req": "node", "key": "bob", "name": "bob2", "addr": "10.10.33.9",
 "add_routes": ["192.168.2.0/24"], "del_routes": [...], "relay": true}
→ {"key", "name", "prefixes", "relay", "not_after"}           # новый сертификат участника

{"type": "set", "req": "revoke", "key": "bob", "rotate": true, "lead_secs": 120}
→ {"key", "name", "epoch", "at"}                             # epoch/at — смена psk (nil с "rotate": false)

{"type": "set", "req": "rotate", "lead_secs": 120}   → {"epoch", "at", "sealed_to"}
{"type": "set", "req": "acl", "toml": "default = \"deny\"\n..."}   → как get acl
{"type": "del", "req": "acl"}                        → как get acl
```

Invite — секрет: кто его знает, может войти в группу (один раз, до `until`). Не пишите его в журналы.

### set peer / del

`{"type": "set", "id": 2, "req": "peer", "key": "...", "name": "...", "addr": "10.10.33.5",
"endpoint": ["1.2.3.4", 5000], "sub_args": {...}, "force": false}` — поля, которых нет, не меняются; с
`"force": true` — очищаются. Ошибки (в `err`, см. [выше](#ошибки)): `key_validate_error`, `key_ambiguous`,
`name_not_str`, `addr_validate_error`, `endpoint_validate_error`, `sub_args_not_dict`, `force_not_bool`.

Имя и адрес участника задаёт его сертификат; `set` меняет только локальные данные узла (например, `sub_args` или
адрес для попытки соединения).

`{"type": "del", "id": 3, "req": "peer" | "peer_endpoint", "key": "..."}` — удалить участника из локального
списка или сбросить его текущее соединение. Ошибки: `key_validate_error`, `key_ambiguous`, `peer_not_exist`,
`error_delete_self_peer`.

## События

Узел присылает клиентам `{"type": "event", "event": {"kind": "...", ...}}`. По умолчанию — все виды, кроме
`metrics` и `log`.

| `kind` | когда | поля |
|---|---|---|
| `neighbor` | прямая связь появилась, пропала, сменила адрес (роуминг) | `key`, `name`, `state`: `up` / `down` / `moved`, `endpoint` |
| `route` | сменился первый хоп до участника | `key`, `name`, `via`, `via_name` (nil — пути нет) |
| `exit` | сменился шлюз или kill switch | `active: {v4, v6}` (`{key, name}` или nil), `blocked: {v4, v6}` |
| `member` | участник вошёл, изменился (имя, адреса, роли) или исключён | `action`: `add` / `update` / `revoke`, `key`, `name`, `prefixes`, `revoked` |
| `epoch` | объявлена смена psk или узел на неё перешёл | `epoch` (текущая), `next: {epoch, at}` или nil |
| `metrics` | раз в `metrics_secs` (только по подписке) | как ответ `get metrics` |
| `log` | строка журнала узла (только по подписке) | `level` (`error` … `trace`), `time` (unix-секунды с долями), `text` |
| `peer` | изменилась локальная запись узла (устаревшее, как в v3) | `action`: `add` / `update` / `del`, `key`, `name`, `addr`, `endpoint`, `sub_args` |
| `server` | сервер обнаружения подключился или отключился | `server: [ip, port]`, `status` |
| `ping` | новый замер RTT | `key`, `ping` (мс) |

`neighbor`, `route`, `exit`, `member`, `epoch` узел находит, сравнивая своё состояние раз в секунду: событие
приходит не позже чем через секунду после изменения, кто бы его ни сделал (API, CLI, другой админ).

Выбрать виды событий и частоту `metrics`:

```
{"type": "sub", "id": 8, "events": ["neighbor", "exit", "metrics"], "metrics_secs": 2}   → nil
{"type": "sub", "id": 9, "log_level": "warn"}   → вдобавок к обычным — строки журнала от warn и серьёзнее
{"type": "sub", "id": 10, "events": nil}       → снова все, кроме metrics и log
```

`events` заменяет прошлый выбор; с `metrics_secs` добавляется `metrics`, с `log_level` (`error`, `warn`, `info`,
`debug`, `trace`; по умолчанию `info`) — `log`. Журнал не подробнее, чем `[app] log_level` узла; строки самого
API в события не попадают. Неизвестный вид — `bad_param`. После
повторного `init` узел подписку забывает (`dvpn-client` отправляет её снова сам).

## Свои данные поверх сети

Клиент может занять номер маршрута от 32 до 255 и обмениваться через него произвольными данными с участниками —
по тем же зашифрованным сессиям, что и IP-трафик, напрямую или через ретрансляторы:

```
{"type": "route", "id": 4, "req": "reg", "route": 40}      → nil или ошибка route_exist / out_of_range / not_int
{"type": "route", "id": 5, "req": "del", "route": 40}      → nil или ошибка route_not_exist / not_permission
{"type": "route", "id": 6, "req": "routes"}                → [40]
{"type": "net", "rou": 40, "key": "<кому>", "pack": b"данные"}
```

Пакет, пришедший от участника на маршрут 40, доставляется занявшему его клиенту как
`{"type": "net", "rou": 40, "key": "<от кого>", "pack": b"..."}`. Пакет должен помещаться в одну датаграмму: не
больше ~1400 байт напрямую и ~1350 через ретрансляторы. Доставка не гарантируется (как UDP).
