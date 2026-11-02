# dvpn-client

Клиентская библиотека на Rust для локального API узла [DVPN](https://git.mihprog.com/DVPN/DVPN) v4
([описание протокола](https://git.mihprog.com/DVPN/DVPN/src/branch/DVPN-rs/doc/api.md)).

На ней строятся CLI `dvpn`, [DVPN-tui](https://git.mihprog.com/DVPN/DVPN-tui) и DVPN-gui; подойдёт и для своих программ:
мониторинг, автоматизация, свои протоколы поверх сети DVPN.

> [!WARNING]
> В разработке. План — [PLAN.md](PLAN.md).

Крейт — `dvpn-client`:

```toml
[dependencies]
dvpn-client = { git = "https://git.mihprog.com/DVPN/DVPN", branch = "DVPN-rs" }
```

## Лицензия

На выбор: [MIT](LICENSE-MIT) или [Apache-2.0](LICENSE-APACHE). Узел DVPN — GPL-3.0, но библиотека говорит с ним
только по протоколу и кода узла не содержит, поэтому её можно брать в программы под любой лицензией.
