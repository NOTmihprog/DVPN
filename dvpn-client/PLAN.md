# dvpn-client — план

Клиентская библиотека на Rust для локального API узла DVPN v4 (`doc/api.md`). Этап 9.2 плана DVPN (в плане он
называется DVPNrs). На ней строятся CLI `dvpn`, DVPN-tui (9.4), DVPN-gui (9.5) и клиент API в DVPN-android.

Крейт `dvpn-client` в workspace репозитория DVPN (папка `dvpn-client/`), лицензия MIT OR Apache-2.0.

## Цели

* Один клиент вместо своих реализаций: `api::query` и разбор ответов в CLI, `DVPN-gui/src/api.rs`,
  `DVPN-android/native/src/api.rs`.
* Протокол меняется в одном коммите: запрос в узле (`src/api.rs`), метод и типы здесь, тест, `doc/api.md`.
  Тесты узла (`api::tests`) разбирают его ответы типами отсюда — расхождение ломает `cargo test`.
* Типизированно: запросы — методы, ответы — структуры, ошибки — `enum` с кодом узла и его текстом.
* Не терять связь: ответ на `ping` узла, повторный `init` после `close` и после перезапуска узла.
* Асинхронный клиент (tokio) и синхронная обёртка для простых программ и скриптов.
* Зависимость только в одну сторону: `dvpn` → `dvpn-client`. Клиент не зависит от узла (тот тянет TUN,
  криптографию, nftables) и не содержит его кода (GPL-3.0): типы протокола написаны здесь заново.

## Зависимость от DVPN (9.1)

Первая версия работает с тем, что уже есть в API v4:

* `init` с версией;
* ошибки в `err`/`msg`;
* `status`, `neighbors`, `routes`, `path`, `ping`, `metrics`, `peer_*`, `server_*`;
* `set/del peer`, маршруты 32–255, события `peer`/`server`/`ping`.

Каждое расширение 9.1 сразу получает метод здесь:

* `group`, `members`, `exit`, `acl`;
* админские `set`;
* события `neighbor`/`route`/`exit`/`member`, подписки.

Порядок работ: запрос в узле → тест в `api::tests` → метод и тест здесь.

## Устройство

```
src/
  lib.rs         реэкспорт, API_VERSION
  addr.rs        ApiAddr: Unix(path) | Udp(SocketAddr); автоопределение как у CLI
  transport.rs   датаграммный сокет: unix (свой адрес во временном каталоге) или UDP
  wire.rs        msgpack <-> rmpv::Value, поля сообщений, field()/map() помощники
  error.rs       Error, ErrorCode
  types.rs       InitInfo, Status, Neighbor, Routes{mesh, ckr}, Hop, Ping, Metrics, Server, Event, …
                 (после 9.1: Group, Member, Exit, ExitUpdate, Acl, Invite, NodeChange, …)
  client.rs      Client (async): соединение, запросы, события, переподключение
  pipe.rs        Pipe: маршрут API 32–255 — свой протокол поверх сети
  blocking.rs    blocking::Client — синхронная обёртка (feature `blocking`)
  testing.rs     MockNode — поддельный узел для тестов (feature `testing`)
examples/
  status.rs  watch.rs  ping.rs  pipe_chat.rs  invite.rs
```

Зависимости: `rmpv` (как узел), `serde` (+ `rmpv::ext` для разбора в структуры), `tokio` (`net`, `sync`, `time`,
`rt`, `macros`), `thiserror`, `log`.

### Адрес узла

`ApiAddr::detect(tun_name: Option<&str>)`:

1. `DVPN_API` из окружения;
2. `/run/dvpn/<tun>.sock`, если есть (по умолчанию `dvpn0`);
3. `127.0.0.1:9902`.

Для unix-сокета клиент биндит свой адрес (`$XDG_RUNTIME_DIR` или временный каталог,
`dvpnrs-<pid>-<n>.sock`) и удаляет его при `Drop`.

### Ошибки

```rust
pub enum Error {
    Io(std::io::Error),
    Timeout,                                   // узел не ответил за время запроса
    NotConnected,                              // нет init: узел не запущен или перезапускается
    VersionUnsupported { min: u64, max: u64 }, // узел не обслуживает API v4
    Api { code: ErrorCode, msg: String },      // ответ с err
    Protocol(String),                          // ответ не того вида (ошибка разбора)
}

#[non_exhaustive]
pub enum ErrorCode {
    UnknownType, UnknownRequest, BadParam, KeyValidate, KeyAmbiguous, ServerNotFound,
    PeerNotExist, DeleteSelf, RouteExist, RouteNotExist, OutOfRange, NotPermission, NotInt,
    NotAdmin, ClockUntrusted, /* 9.1 */ …
    Other(String),                             // код, которого библиотека ещё не знает
}
```

`nil` в `res` — это не ошибка: методы возвращают `Option<T>` (`path`, `ping`).

### Клиент

```rust
let c = Client::connect(ApiAddr::detect(None)).name("my-app").await?;
let info: &InitInfo = c.info();                 // key, name, group, admin, node_version
let st: Status = c.status().await?;
let hops: Option<Vec<Hop>> = c.path("bob").await?;
let rtt: Option<Ping> = c.ping("bob").await?;   // до 2 с ожидания, другие запросы не ждут
let mut ev = c.events();                        // tokio::sync::broadcast::Receiver<Event>
let mut st = c.state();                         // watch: Connecting | Connected(InitInfo) | Lost
```

* Внутри одна задача приёма. Ответы раздаются по `id` через `oneshot`, события — в `broadcast`, пакеты
  маршрутов — в `mpsc` своего `Pipe`. На `ping` узла задача сразу отвечает `pong`.
* Таймаут запроса — 5 с (у `ping` — 5 с, узел ждёт ответа 2 с), настраивается.
* Переподключение. На `close` — снова `init`. Если на запросы долго нет ответов (узел перезапущен, UDP-адрес
  не изменился) — `init` с backoff 0.5 → 8 с. Состояние меняется в `state()`, ожидающие запросы получают
  `NotConnected`. После переподключения библиотека заново занимает маршруты живых `Pipe`.
* Узел — `impl Into<NodeRef>`: ключ, его начало или имя участника, как в API.
* Чистый запрос для того, чего ещё нет в типах: `c.raw("get", "something", fields) -> Result<Value>`.

### Трубы (маршруты 32–255)

```rust
let pipe = c.pipe(40).await?;                   // route reg; Drop → route del
pipe.send("bob", b"hello").await?;              // net-пакет, ≤ ~1350 байт через ретрансляторы
let (from, data) = pipe.recv().await?;
```

`Pipe::MAX_PAYLOAD` — безопасный размер. Больший пакет — ошибка до отправки. Доставка не гарантируется.

### Синхронный клиент (feature `blocking`)

`blocking::Client` держит свой current-thread runtime в фоновом потоке. Методы те же, без `async`. События —
через `std::sync::mpsc::Receiver`.

## Этапы

Сделано (2026-11-02): этап 1 и большая часть 2 — `addr`, `transport` (UDP и unix), `wire`, `error` (`ErrorCode`
со всеми кодами узла), `Client::connect` с `init` и `VersionUnsupported`, ответ на `ping`, повторный `init` на
`close`, `raw`, типы и методы `status`, `version`, `neighbors`, `routes`, `metrics`, `path`, `ping`, `group`,
`members`, `exit`/`set_exit`, `acl`, `reset_endpoint`. Вместо `MockNode` пока тесты против настоящего узла:
`api::tests::client_over_udp` / `client_over_a_unix_socket` в `dvpn`. Не сделано: `peer_*`/`server_*` (устаревшие
— только через `raw`), типизированные события, `MockNode`.

| # | Что | Готово, когда |
|---|---|---|
| 1 | `addr`, `transport`, `wire`, `error`; `Client::connect` + `init` + ответ на `ping`; `raw` | `examples/status.rs` печатает ответ живого узла; `VersionUnsupported` на старом узле |
| 2 | Типы и методы на текущем API: `status`, `neighbors`, `routes`, `path`, `ping`, `metrics`, `servers`/`server_*`, `peer_*`, `set_peer`, `del_peer`, `del_endpoint` | каждый метод покрыт тестом против `MockNode` (ответ и ошибки) |
| 3 | События и переподключение: `events()`, `state()`, повторный `init`, backoff | тест: MockNode перезапускается → клиент сам подключается, запросы снова идут |
| 4 | Трубы: `pipe()`, `send`, `recv`, перерегистрация после переподключения | `examples/pipe_chat.rs` между двумя узлами через ретранслятор (netns) |
| 5 | `blocking` | те же примеры в синхронном виде |
| 6 | Методы 9.1 по мере появления в узле: `group`, `members`, `exit`/`set_exit`, `acl`/`set_acl`/`clear_acl`, `invite`, `set_node`, `revoke`, `rotate`, подписки на события и `metrics` | `examples/invite.rs`: админ выдаёт invite, новый узел входит (netns) |
| 7 | Переход клиентов: CLI `dvpn` (диагностика сразу после этапа 2, админские команды — с этапом 6), DVPN-tui, DVPN-gui, DVPN-android/native | ни у кого нет своей реализации протокола; `api::query` удалён |
| 8 | Документация (rustdoc с примерами), CI: fmt, clippy, тесты; публикация (git-зависимость или crates.io) | `cargo doc` без предупреждений |

## Тесты

* **Юнит:** разбор каждого ответа и каждого кода ошибки, включая неизвестные (`ErrorCode::Other`).
* **Против узла в `cargo test`:** `api::tests` в `dvpn` поднимают настоящий узел без сети и разбирают каждый
  его ответ типами `dvpn-client`.
* **`MockNode`** (feature `testing`, им могут пользоваться и TUI/GUI). UDP- или unix-сокет со сценарием:
  «на `get status` ответить X», «прислать событие», «послать `close`», «замолчать на N секунд».
* **Против живого узла:** тесты `#[ignore]`, адрес из `DVPN_API`. `cargo test -- --ignored` на машине с
  запущенным `dvpn -d`.
* **netns-стенд DVPN** (`tests/netns-e2e.sh`): примеры как клиенты — статус, соседи, маршруты, событие, труба
  через ретранслятор (критерий приёмки этапа 9).

## Решения

* **Лицензия — MIT OR Apache-2.0** (2026-11-02). Библиотека говорит с узлом только по протоколу и кода узла
  (GPL-3.0) не содержит, её можно брать в программы под любой лицензией.
* **Имя крейта — `dvpn-client`** (2026-11-02).
* **Место — workspace репозитория DVPN, CLI на нём** (2026-11-02, вместо отдельного репозитория DVPNrs и CLI
  без библиотеки). Узел и клиент выпускаются вместе, протокол меняется в одном коммите, CLI теряет свою
  реализацию. Внешние программы берут крейт git-зависимостью на репозиторий DVPN (cargo находит его в workspace),
  позже — с crates.io.
* **Узел пока не переходит на общие структуры:** `src/api.rs` по-прежнему собирает ответы словарями msgpack,
  согласованность держат тесты из `api::tests`. Перевод обработчиков на serde-структуры клиента — потом, если
  окупится.
