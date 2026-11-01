# API

[← к содержанию](../README.md#документация)

Узел предоставляет локальный API для внешних программ: GUI и TUI, скриптов мониторинга, своих сервисов поверх
сети. Через него же работают команды `dvpn status`, `neighbors`, `routes`, `path`, `ping`, `metrics`.

## Транспорт

Датаграммы [msgpack](https://msgpack.org/):

* Linux, если включён TUN и есть права на `/run/dvpn`: unix-сокет `/run/dvpn/<tun_name>.sock`;
* иначе (и на Windows): UDP `127.0.0.1:9902`;
* свой адрес: `dvpn -a 127.0.0.1:9000` или `dvpn -a /path/to/api.sock` — и для узла, и для команд.

> Любой локальный пользователь с доступом к сокету управляет узлом. Не выставляйте API наружу.

## Подключение

Каждое сообщение — msgpack-словарь с полем `type`.

1. Клиент отправляет `{"type": "init", "name": "my-app"}`. Без этого на остальные запросы приходит
   `{"type": "close"}`.
2. Узел шлёт клиенту `{"type": "ping"}` раз в 15 с; клиент отвечает `{"type": "pong"}`, иначе примерно через 45 с
   соединение закрывается.
3. Отключиться — `{"type": "close"}`.

Запросы `get` / `set` / `del` / `route` содержат произвольный `id`; ответ приходит как
`{"type": "res", "id": <тот же id>, "res": <результат>}`.

Узлы везде обозначаются полем `key` — публичным ключом узла (base64url). В запросах можно передать однозначное
начало ключа или имя участника.

Пример на Python:

```python
import socket, msgpack
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
node = ("127.0.0.1", 9902)
s.sendto(msgpack.dumps({"type": "init", "name": "example"}), node)
s.sendto(msgpack.dumps({"type": "get", "id": 1, "req": "status"}), node)
print(msgpack.loads(s.recv(65535)))   # {'type': 'res', 'id': 1, 'res': {'key': 'DZVS...', 'name': 'alice', ...}}
```

С unix-сокетом — `socket.AF_UNIX`, `SOCK_DGRAM`, и клиенту нужен свой адрес (`s.bind("/tmp/my-app.sock")`).

## get

`{"type": "get", "id": 1, "req": "<запрос>", ...параметры}`

### Состояние узла

| `req` | параметры | результат |
|---|---|---|
| `status` | | словарь: `key`, `name`, `group`, `prefixes` (адреса и подсети из сертификата), `relay`, `cert_days`, `servers` (`[{addr, connected}]`), `exit_v4`, `exit_v6` (имя текущего шлюза или nil), `kill_switch`, `local_addr` |
| `neighbors` | | список прямых соседей: `key`, `name`, `endpoint`, `rtt_ms`, `alive`, `session_secs`, `tx_packets`, `tx_bytes`, `rx_packets`, `rx_bytes` |
| `routes` | | `{"mesh": [{key, name, via, via_name, cost}], "ckr": [{net, to, system}]}` |
| `path` | `key` | список хопов `[{key, name}]` до участника (последний — он сам) или nil |
| `ping` | `key` | `{"rtt_ms": 12.3, "via": "direct" \| "relays"}` или nil, если ответа нет за 2 с |
| `metrics` | | счётчики, см. [ниже](#metrics) |

`ping` отвечает не сразу (ждёт ответа участника), остальные запросы при этом обслуживаются.

### Участники и серверы

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

`{"type": "set", "id": 2, "req": "peer", "key": "...", "name": "...", "addr": "10.10.33.5",
"endpoint": ["1.2.3.4", 5000], "sub_args": {...}, "force": false}` — поля, которых нет, не меняются; с
`"force": true` — очищаются. Ошибки возвращаются строкой: `key_validate_error`, `key_ambiguous`, `name_not_str`,
`addr_validate_error`, `endpoint_validate_error`, `sub_args_not_dict`, `force_not_bool`.

Имя и адрес участника задаёт его сертификат; `set` меняет только локальные данные узла (например, `sub_args` или
адрес для попытки соединения).

`{"type": "del", "id": 3, "req": "peer" | "peer_endpoint", "key": "..."}` — удалить участника из локального
списка или сбросить его текущее соединение. Ошибки: `peer_not_exist`, `error_delete_self_peer`.

## События

Узел рассылает всем клиентам `{"type": "event", "event": {...}}`:

* изменения участников: `{"action": "add" | "update" | "del", "key", "name", "addr", "endpoint", "sub_args"}`;
* статус сервера обнаружения: `{"server": [ip, port], "status": bool}`;
* новый замер RTT: `{"key": "...", "ping": 12.3}`.

## Свои данные поверх сети

Клиент может занять номер маршрута от 32 до 255 и обмениваться через него произвольными данными с участниками —
по тем же зашифрованным сессиям, что и IP-трафик, напрямую или через ретрансляторы:

```
{"type": "route", "id": 4, "req": "reg", "route": 40}      → nil или "route_exist" / "out_of_range"
{"type": "route", "id": 5, "req": "del", "route": 40}      → nil или "route_not_exist" / "not_permission"
{"type": "route", "id": 6, "req": "routes"}                → [40]
{"type": "net", "rou": 40, "key": "<кому>", "pack": b"данные"}
```

Пакет, пришедший от участника на маршрут 40, доставляется занявшему его клиенту как
`{"type": "net", "rou": 40, "key": "<от кого>", "pack": b"..."}`. Пакет должен помещаться в одну датаграмму: не
больше ~1400 байт напрямую и ~1350 через ретрансляторы. Доставка не гарантируется (как UDP).
