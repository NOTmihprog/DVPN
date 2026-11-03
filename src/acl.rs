//! Access control inside the group (PLAN §7.4): who may reach whom, on which protocols and
//! ports. An admin writes the rules once (`dvpn acl set acl.toml`); they travel as a record of
//! the group (signed by the group key), so every node enforces the same rules.
//!
//! ```toml
//! default = "allow"                     # or "deny": what no rule matches
//! [tags]
//! servers = ["msk-firstvds", "posad"]   # member names or node keys
//! [[rule]]
//! from = ["*"]                          # tags, members, or "*" (anybody in the group)
//! to = ["servers"]
//! proto = "tcp"                         # tcp, udp, icmp, or any (default)
//! ports = ["22", "80-443"]              # destination ports (tcp/udp), none = all
//! action = "allow"
//! ```
//!
//! Each node enforces the rules whose `to` includes it, on traffic arriving from the tunnel for
//! itself or the subnets behind it, first match wins. Replies to its own connections always pass
//! (conntrack), and so does what is not from a member's address (the internet through an exit
//! is not a member). Rendered into nftables (`table inet dvpn_acl`) on Linux; elsewhere the node
//! filters the packets itself (`aclfilter.rs`).

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::process::{Command, Stdio};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::identity::NodeId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Any,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Who {
    Anybody,
    Tag(String),
    Node(NodeId),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub from: Vec<Who>,
    pub to: Vec<Who>,
    pub proto: Proto,
    pub ports: Vec<(u16, u16)>,
    pub allow: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acl {
    pub default_deny: bool,
    pub tags: BTreeMap<String, Vec<NodeId>>,
    pub rules: Vec<Rule>,
}

fn who_text(w: &Who, name: &dyn Fn(&NodeId) -> String) -> String {
    match w {
        Who::Anybody => "*".into(),
        Who::Tag(t) => t.clone(),
        Who::Node(n) => name(n),
    }
}

impl Acl {
    /// Parses the TOML form; `member` resolves a member name or key.
    pub fn parse(text: &str, member: &dyn Fn(&str) -> Option<NodeId>) -> anyhow::Result<Acl> {
        use anyhow::{anyhow, bail};
        let doc: toml_edit::DocumentMut = text.parse()?;
        let default_deny = match doc.get("default").and_then(|v| v.as_str()) {
            None | Some("allow") => false,
            Some("deny") => true,
            Some(x) => bail!("default: {x}: allow or deny"),
        };
        let strings = |item: Option<&toml_edit::Item>, what: &str| -> anyhow::Result<Vec<String>> {
            let Some(item) = item else { return Ok(Vec::new()) };
            let arr = item.as_array().ok_or_else(|| anyhow!("{what}: expected a list"))?;
            arr.iter()
                .map(|v| v.as_str().map(str::to_owned).ok_or_else(|| anyhow!("{what}: expected strings")))
                .collect()
        };
        let mut tags = BTreeMap::new();
        if let Some(t) = doc.get("tags") {
            let t = t.as_table_like().ok_or_else(|| anyhow!("[tags] is not a table"))?;
            for (k, v) in t.iter() {
                if k == "*" {
                    bail!("tag name * is reserved");
                }
                let mut ids = Vec::new();
                for m in strings(Some(v), &format!("tags.{k}"))? {
                    ids.push(member(&m).ok_or_else(|| anyhow!("tags.{k}: no member {m}"))?);
                }
                tags.insert(k.to_owned(), ids);
            }
        }
        let who = |s: &str, ctx: &str| -> anyhow::Result<Who> {
            if s == "*" {
                return Ok(Who::Anybody);
            }
            if tags.contains_key(s) {
                return Ok(Who::Tag(s.to_owned()));
            }
            member(s).map(Who::Node).ok_or_else(|| anyhow!("{ctx}: {s} is neither a tag nor a member"))
        };
        let mut rules = Vec::new();
        if let Some(arr) = doc.get("rule") {
            let arr = arr.as_array_of_tables().ok_or_else(|| anyhow!("rules must be [[rule]] sections"))?;
            for (i, t) in arr.iter().enumerate() {
                let ctx = format!("rule #{}", i + 1);
                for (k, _) in t.iter() {
                    if !["from", "to", "proto", "ports", "action"].contains(&k) {
                        bail!("{ctx}: unknown key {k}");
                    }
                }
                let from =
                    strings(t.get("from"), &ctx)?.iter().map(|s| who(s, &ctx)).collect::<anyhow::Result<Vec<_>>>()?;
                let to =
                    strings(t.get("to"), &ctx)?.iter().map(|s| who(s, &ctx)).collect::<anyhow::Result<Vec<_>>>()?;
                if from.is_empty() || to.is_empty() {
                    bail!("{ctx}: from and to are required");
                }
                let proto = match t.get("proto").and_then(|v| v.as_str()) {
                    None | Some("any") => Proto::Any,
                    Some("tcp") => Proto::Tcp,
                    Some("udp") => Proto::Udp,
                    Some("icmp") => Proto::Icmp,
                    Some(x) => bail!("{ctx}: proto {x}: tcp, udp, icmp or any"),
                };
                let mut ports = Vec::new();
                for p in strings(t.get("ports"), &ctx)? {
                    let (a, b) = p.split_once('-').unwrap_or((&p, &p));
                    let (a, b): (u16, u16) = (a.trim().parse()?, b.trim().parse()?);
                    if a > b || a == 0 {
                        bail!("{ctx}: bad port range {p}");
                    }
                    ports.push((a, b));
                }
                if !ports.is_empty() && !matches!(proto, Proto::Tcp | Proto::Udp) {
                    bail!("{ctx}: ports need proto tcp or udp");
                }
                let allow = match t.get("action").and_then(|v| v.as_str()) {
                    Some("allow") => true,
                    Some("deny") => false,
                    _ => bail!("{ctx}: action: allow or deny"),
                };
                rules.push(Rule { from, to, proto, ports, allow });
            }
        }
        Ok(Acl { default_deny, tags, rules })
    }

    /// The TOML form, with members by `name`.
    pub fn to_toml(&self, name: &dyn Fn(&NodeId) -> String) -> String {
        let mut s = format!("default = \"{}\"\n", if self.default_deny { "deny" } else { "allow" });
        let q = |v: Vec<String>| v.iter().map(|x| format!("\"{x}\"")).collect::<Vec<_>>().join(", ");
        if !self.tags.is_empty() {
            s.push_str("\n[tags]\n");
            for (t, ids) in &self.tags {
                let _ = writeln!(s, "{t} = [{}]", q(ids.iter().map(name).collect()));
            }
        }
        for r in &self.rules {
            let _ = writeln!(s, "\n[[rule]]");
            let _ = writeln!(s, "from = [{}]", q(r.from.iter().map(|w| who_text(w, name)).collect()));
            let _ = writeln!(s, "to = [{}]", q(r.to.iter().map(|w| who_text(w, name)).collect()));
            let proto = match r.proto {
                Proto::Any => "any",
                Proto::Tcp => "tcp",
                Proto::Udp => "udp",
                Proto::Icmp => "icmp",
            };
            let _ = writeln!(s, "proto = \"{proto}\"");
            if !r.ports.is_empty() {
                let ports =
                    r.ports.iter().map(|(a, b)| if a == b { a.to_string() } else { format!("{a}-{b}") }).collect();
                let _ = writeln!(s, "ports = [{}]", q(ports));
            }
            let _ = writeln!(s, "action = \"{}\"", if r.allow { "allow" } else { "deny" });
        }
        s
    }

    pub(crate) fn covers(&self, w: &Who, n: &NodeId) -> bool {
        match w {
            Who::Anybody => true,
            Who::Tag(t) => self.tags.get(t).is_some_and(|ids| ids.contains(n)),
            Who::Node(x) => x == n,
        }
    }

    /// The nftables chain body for node `me`: `prefixes` are the members' addresses and subnets.
    /// `None` when nothing restricts traffic to `me` (no table needed).
    pub fn render(&self, me: &NodeId, prefixes: &HashMap<NodeId, Vec<IpNet>>) -> Option<String> {
        let mine: Vec<&Rule> = self.rules.iter().filter(|r| r.to.iter().any(|w| self.covers(w, me))).collect();
        if mine.iter().all(|r| r.allow) && !self.default_deny {
            return None;
        }
        let mut out = String::from("ct state established,related accept\n");
        // traffic from outside the group (e.g. the internet through an exit) is not ours to judge
        let all: Vec<IpNet> = prefixes.values().flatten().copied().collect();
        let set = |nets: &[IpNet], v6: bool| -> Option<String> {
            let v: Vec<String> =
                nets.iter().filter(|n| matches!(n, IpNet::V6(_)) == v6).map(|n| n.to_string()).collect();
            (!v.is_empty()).then(|| format!("{{ {} }}", v.join(", ")))
        };
        for r in mine {
            let from: Vec<IpNet> = if r.from.contains(&Who::Anybody) {
                all.clone()
            } else {
                prefixes
                    .iter()
                    .filter(|(n, _)| r.from.iter().any(|w| self.covers(w, n)))
                    .flat_map(|(_, p)| p.clone())
                    .collect()
            };
            let verdict = if r.allow { "accept" } else { "drop" };
            for v6 in [false, true] {
                let Some(src) = set(&from, v6) else { continue };
                let fam = if v6 { "ip6" } else { "ip" };
                let l4 = match r.proto {
                    Proto::Any => String::new(),
                    Proto::Icmp => (if v6 { "meta l4proto ipv6-icmp " } else { "meta l4proto icmp " }).to_owned(),
                    Proto::Tcp | Proto::Udp => {
                        let p = if r.proto == Proto::Tcp { "tcp" } else { "udp" };
                        if r.ports.is_empty() {
                            format!("meta l4proto {p} ")
                        } else {
                            let ports: Vec<String> = r
                                .ports
                                .iter()
                                .map(|(a, b)| if a == b { a.to_string() } else { format!("{a}-{b}") })
                                .collect();
                            format!("{p} dport {{ {} }} ", ports.join(", "))
                        }
                    }
                };
                let _ = writeln!(out, "{fam} saddr {src} {l4}{verdict}");
            }
        }
        if self.default_deny {
            for v6 in [false, true] {
                if let Some(src) = set(&all, v6) {
                    let fam = if v6 { "ip6" } else { "ip" };
                    let _ = writeln!(out, "{fam} saddr {src} drop");
                }
            }
        }
        Some(out)
    }
}

const TABLE: &str = "dvpn_acl";

/// Installs (or with `None` removes) the ACL chain for traffic from `tun`.
pub fn apply_nft(tun: &str, chain: Option<&str>) {
    if !cfg!(target_os = "linux") {
        // elsewhere the node enforces the rules itself (aclfilter.rs)
        return;
    }
    let _ = Command::new("nft").args(["delete", "table", "inet", TABLE]).stderr(Stdio::null()).status();
    let Some(body) = chain else { return };
    let script = format!(
        "table inet {TABLE} {{
    chain acl {{
{body}    }}
    chain input {{ type filter hook input priority 0; iifname \"{tun}\" jump acl; }}
    chain forward {{ type filter hook forward priority 0; iifname \"{tun}\" jump acl; }}
}}"
    );
    let child = Command::new("nft").args(["-f", "-"]).stdin(Stdio::piped()).stderr(Stdio::piped()).spawn();
    let Ok(mut child) = child else {
        log::warn!("ACL | cannot run nft");
        return;
    };
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(script.as_bytes());
    }
    match child.wait_with_output() {
        Ok(o) if o.status.success() => log::info!("ACL | rules applied"),
        Ok(o) => log::warn!("ACL | nft: {}", String::from_utf8_lossy(&o.stderr).trim()),
        Err(e) => log::warn!("ACL | nft: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> [NodeId; 3] {
        [1u8, 2, 3].map(|i| crate::identity::Identity::from_seed(&[i; 32]).id())
    }

    #[test]
    fn parse_render_round_trip() {
        let [a, b, c] = ids();
        let names = [("a", a), ("b", b), ("c", c)];
        let member = |s: &str| names.iter().find(|(n, _)| *n == s).map(|(_, k)| *k);
        let text = r#"
default = "deny"
[tags]
servers = ["c"]
[[rule]]
from = ["a"]
to = ["servers"]
proto = "tcp"
ports = ["22", "80-443"]
action = "allow"
[[rule]]
from = ["*"]
to = ["servers"]
proto = "icmp"
action = "allow"
"#;
        let acl = Acl::parse(text, &member).unwrap();
        assert!(acl.default_deny);
        assert_eq!(acl.tags["servers"], vec![c]);
        let name = |n: &NodeId| names.iter().find(|(_, k)| k == n).unwrap().0.to_owned();
        assert_eq!(Acl::parse(&acl.to_toml(&name), &member).unwrap(), acl, "TOML round trip");

        let prefixes: HashMap<NodeId, Vec<IpNet>> = [
            (a, vec!["10.0.0.1/32".parse().unwrap()]),
            (b, vec!["10.0.0.2/32".parse().unwrap(), "fd00::2/128".parse().unwrap()]),
            (c, vec!["10.0.0.3/32".parse().unwrap()]),
        ]
        .into();
        let r = acl.render(&c, &prefixes).unwrap();
        assert!(r.starts_with("ct state established,related accept"));
        assert!(r.contains("ip saddr { 10.0.0.1/32 } tcp dport { 22, 80-443 } accept"), "{r}");
        assert!(r.contains("meta l4proto icmp accept"), "{r}");
        assert!(r.contains("ip6 saddr { fd00::2/128 } meta l4proto ipv6-icmp accept"), "{r}");
        assert!(r.trim_end().ends_with("drop"), "default deny last: {r}");
        // a is not a server: default deny still applies to it
        assert!(acl.render(&a, &prefixes).is_some());
        // allow-all ACL: nothing to install
        let open = Acl::parse("default = \"allow\"\n", &member).unwrap();
        assert!(open.render(&a, &prefixes).is_none());
    }

    #[test]
    fn bad_acls() {
        let member = |s: &str| (s == "a").then(|| ids()[0]);
        for (bad, why) in [
            ("default = \"maybe\"", "allow or deny"),
            ("[[rule]]\nfrom = [\"x\"]\nto = [\"*\"]\naction = \"allow\"", "neither a tag nor a member"),
            (
                "[[rule]]\nfrom = [\"a\"]\nto = [\"*\"]\nproto = \"icmp\"\nports = [\"1\"]\naction = \"deny\"",
                "ports need",
            ),
            ("[[rule]]\nfrom = [\"a\"]\nto = [\"*\"]\naction = \"drop\"", "action"),
            ("[[rule]]\nfrom = [\"a\"]\nto = [\"*\"]\nport = [\"1\"]\naction = \"deny\"", "unknown key"),
            ("[tags]\nt = [\"zz\"]", "no member zz"),
        ] {
            let err = format!("{:#}", Acl::parse(bad, &member).unwrap_err());
            assert!(err.contains(why), "{bad}: {err}");
        }
    }
}
