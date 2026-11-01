# Диагностика и решение проблем

[← к содержанию](../README.md#документация)

## Команды диагностики

Команды спрашивают работающий узел через его [API](api.md): unix-сокет `/run/dvpn/<tun>.sock` или
`127.0.0.1:9902`. Если узел запущен с `--dir` или `-a`, укажите то же самое и команде.

### dvpn status — этот узел

```
$ dvpn status
node      alice (DZVSMn8lShIWwhSda4umRbtk027yZh_KeJONsPodlFc)
group     a9XkT0bq…
addresses 10.10.33.1/32, 192.168.10.0/24
relay     yes   certificate valid 27 more days
socket    [::]:8812
tracker   203.0.113.10:6485 connected
exit      IPv4 vps1, IPv6 -
```

`addresses` — адрес и подсети из сертификата. Если ни один шлюз не доступен, в строке `exit` появится
`(kill switch on: no gateway alive)`.

Что смотреть: подключены ли серверы обнаружения (`tracker`), сколько дней осталось у сертификата, какой шлюз
используется.

### dvpn neighbors — прямые соседи

```
| Name  | Key        | Endpoint           | RTT ms | Alive | Session | Sent     | Received |
|-------|------------|--------------------|--------|-------|---------|----------|----------|
| bob   | k3Jd9aQ0xZ | 198.51.100.7:31544 | 23.4   | yes   | 85 s    | 1.2 MiB  | 845.0 KiB|
| vps1  | 7sLq0bX2pM | 203.0.113.10:7000  | 11.0   | yes   | 40 s    | 312.4 KiB| 290.1 KiB|
```

* **Endpoint** — внешний адрес соседа, по которому идёт сессия. Адрес из LAN — значит, вы в одной сети.
* **Alive** `no` — сосед давно молчит (больше 25 с): связь вот-вот будет признана потерянной.
* **Session** — сколько связь идёт по этому адресу; сбрасывается при смене адреса соседа (роуминг, переподключение).
* **Sent / Received** — объём прямой сессии с соседом, включая служебные пакеты и транзит через него.

Если нужного участника здесь нет — прямой связи нет; смотрите `dvpn path`.

### dvpn routes — маршруты

```
Mesh (node: first hop, cost in ms)
| Node   | Key        | Via  | Cost |
| laptop | 9fKs1LmQ2w | vps1 | 34   |

CKR (destination: node)
| Prefix          | To                       | System route |
| 10.10.33.2/32   | bob                      | yes    |
| 192.168.30.0/24 | office                   | yes    |
| 0.0.0.0/0       | vps1                     | yes    |
| 10.0.0.0/8      | (not through the tunnel) | yes    |
```

**Mesh** — до каких узлов трафик идёт через ретрансляторы и через какой первый хоп. **CKR** — таблица
адресов ([routing.md](routing.md#таблица-маршрутов-ckr)): куда уходит каждая подсеть; `(kill switch: dropped)` —
шлюз недоступен.

### dvpn path и dvpn ping

```
$ dvpn path laptop
DZVSMn8lSh (this node) -> vps1 -> laptop

$ dvpn ping laptop -c 3
laptop: 34.12 ms (relays)
laptop: 33.87 ms (relays)
laptop: 35.01 ms (relays)
3 of 3 answered, average 34.33 ms
```

`dvpn ping` меряет время по сессии DVPN с участником (через `KIND_CONTROL`, как keepalive), а не ICMP: он
работает, даже если ICMP запрещён [ACL](acl.md) или файрволом участника. `(direct)` — прямая сессия, `(relays)` —
через ретрансляторы.

Обычные `ping`, `traceroute`, `tracepath`, `mtr` тоже работают; ретрансляторы видны как хопы
([mesh.md](mesh.md#диагностика)).

### Счётчики: dvpn metrics

```
$ dvpn metrics

Uptime 3600 s, handshakes 64, relayed for others 1200 / 1.4 MiB

Traffic (packets / bytes; IP: with the member on any path, wire: the direct session)
| Name   | Key        | IP sent          | IP received      | Wire sent        | Wire received    |
| bob    | k3Jd9aQ0xZ | 9120 / 8.1 MiB   | 7311 / 1.2 MiB   | 9530 / 8.5 MiB   | 7702 / 1.3 MiB   |
| laptop | 9fKs1LmQ2w | 102 / 9.6 KiB    | 98 / 9.2 KiB     | 0 / 0 B          | 0 / 0 B          |

Dropped packets
| Reason         | Packets |
| no_route       | 0       |
| no_session     | 3       |
...
```

* **IP sent / received** — IP-пакеты с участником (как их видит TUN), любым путём: напрямую или через
  ретрансляторы. У `laptop` выше трафик только через ретранслятор, поэтому прямая сессия пуста.
* **Wire sent / received** — пакеты прямой сессии с этим соседом на проводе: IP, записи группы, маршруты,
  keepalive и транзит. Рукопожатия не считаются.
* **relayed for others** — пакеты, которые этот узел передал дальше как ретранслятор.
* **handshakes** — завершённые рукопожатия (обе роли, прямые и сквозные, со сменами ключей): частый рост без
  новых соседей — признак нестабильной связи.

Причины отбрасывания:

| Причина | Что значит |
|---|---|
| `no_route` | из TUN: адрес назначения не принадлежит ни одному участнику (нет маршрута CKR) |
| `no_session` | из TUN: сессии с участником ещё нет — идёт рукопожатие; растёт при старте и при обрывах |
| `unreachable` | из TUN: до участника нет ни пути, ни адреса для попытки (приложению отправлен ICMP host unreachable) |
| `too_big` | из TUN: пакет с DF больше пути (отправлен ICMP packet too big) |
| `kill_switch` | из TUN: интернет при недоступных шлюзах (отправлен ICMP prohibited) |
| `foreign_source` | от участника: адрес источника не его ([проверка источника](routing.md#проверка-источника)) |
| `unreadable` | из сети: пакет не из какой-либо сессии — мусор перед рукопожатиями, зонды, повторы, чужая группа или psk |
| `not_relay` | транзит пришёл узлу без роли `relay` |
| `hop_limit` | транзит: кончился лимит хопов (traceroute, петля при перестроении маршрутов) |
| `no_way_on` | транзит: ретранслятору некуда передать пакет дальше |

Счётчики считаются с запуска узла; счётчики исключённого участника удаляются. В программах — `get metrics`
через [API](api.md#metrics). Экспорт в Prometheus — в планах (этап 8).

## Логи

Уровень — `[app] log_level` в `config.toml`: `TRACE`, `DEBUG`, `INFO` (по умолчанию), `WARNING`, `ERROR`. Под
systemd: `journalctl -u dvpn -f`.

| Строка | Что значит |
|---|---|
| `Connection status connected via …` | подключились к серверу обнаружения |
| `Peer bob(…) new endpoint 1.2.3.4:5678` | сервер сообщил адрес участника |
| `Link \| session with bob(…) established` (DEBUG) | прямая сессия установлена |
| `Link \| peer bob(…) at new endpoint …` | роуминг: участник сменил адрес |
| `Mesh \| end-to-end session with laptop(…) via vps1(…)` | сессия через ретранслятор |
| `Group \| … revoked, dropped` | участник исключён |
| `Mesh \| … sends too many bad … messages: ignored for a while` | сосед заблокирован за флуд ([mesh.md](mesh.md#защита-рассылки)) |
| `DNS \| systemd-resolved: …` | split DNS настроен |

## Типичные проблемы

| Симптом | Причина и решение |
|---|---|
| `not in any group` | узел не в группе: `dvpn group create` или `dvpn group join <invite>` |
| `own certificate in group …: certificate expired` | срок истёк, а админ всё это время не был в сети: `dvpn group leave`, затем новый invite |
| `this node is revoked from the group` | узел исключён админом |
| `psk epoch N is active but there is no key for this node` | psk группы сменился, а ключ для этого узла не выдан (узел исключён, или админ не видел его в сети с момента входа): попросите новый invite |
| `invite already used` в логе сервера | по этому invite уже вошёл другой узел: нужен новый |
| `invite expired` | invite просрочен (`--ttl`): попросите новый |
| `The clock is earlier than this build` | часы не выставлены (роутер без RTC до NTP): узел работает, но сервер обнаружения не ответит, пока время не установится; после NTP узел подключится сам. Админские команды до этого отказывают |
| `Connection status connecting` повторяется, `connected` нет | сервер недоступен или не тот ключ: проверьте `addr`/`port`/`key` в `[servers.*]` и открыт ли UDP-порт; сервер с чужим ключом молчит; часы расходятся с сервером больше чем на 10 минут; у сервера несколько IP — запустите его с `-a <публичный IP>` |
| сервер подключён, но участника не находит | участник не запущен или подключён к другому серверу; разные группы (`dvpn group list`, сравните id) |
| `new endpoint` есть, сессии нет; растёт `unreadable` | разный профиль `[groups.obfs]` (поменялся у админа после invite) — или NAT не пробивается (симметричный NAT у обоих). Назначьте ретранслятор (`dvpn node set vps --relay`) или пробросьте порт и задайте фиксированный `bind_port` |
| участник есть в `routes` через ретранслятор, но не в `neighbors` | прямой путь не пробился, трафик идёт через ретранслятор — это нормально; узлы продолжают пробовать |
| растёт `foreign_source` | участник шлёт пакеты не с адреса из сертификата: адрес на его TUN изменён вручную, или на нём LAN без `--route` |
| растёт `no_route` | приложения шлют в туннель адреса, которых нет в CKR: проверьте `dvpn routes` и системные маршруты |
| `Tun init error` | нет прав (root / `CAP_NET_ADMIN` / администратор), на Windows нет `wintun.dll` рядом с exe, либо интерфейс с таким именем уже есть |
| ping идёт, большие пакеты (сайты, файлы) зависают | уменьшите `[net] mtu`, например до 1280 |
| нет интернета, в `dvpn status` — `kill switch on: no gateway alive` | ни один шлюз не доступен: проверьте их в `dvpn neighbors` / `dvpn path`; временно — `dvpn exit --kill-switch off` |
| `*.dvpn` не разрешаются | нет systemd-resolved: настройте DNS вручную ([dns.md](dns.md#без-systemd-resolved)); проверьте `resolvectl status dnet` |
| оба участника за одним роутером не соединяются | роутер без NAT hairpinning и LAN-адреса недоступны друг другу (разные VLAN): назначьте ретранслятор |
