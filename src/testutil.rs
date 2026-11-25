//! For tests only.

/// Runs test `name` (its full path) again as root of a network namespace of its own, so it may use
/// port 53, nftables and a TUN without touching the machine. True inside the namespace; false
/// outside, after the run there succeeded (or where a namespace, nftables or a TUN cannot be had,
/// as in a container: then the test is skipped, with a message). `path`: a directory before the others in `PATH`.
#[cfg(target_os = "linux")]
pub(crate) fn in_netns(name: &str, path: Option<&std::path::Path>) -> bool {
    const INSIDE: &str = "DVPN_TEST_IN_NETNS";
    if std::env::var_os(INSIDE).is_some() {
        return true;
    }
    let probe = "ip link set lo up && ip tuntap add dvpnprobe mode tun && nft list ruleset";
    let ok = std::process::Command::new("unshare").args(["-rn", "sh", "-c", probe]).output();
    if !ok.is_ok_and(|o| o.status.success()) {
        eprintln!("{name} skipped: needs unshare -rn, ip, nft and /dev/net/tun");
        return false;
    }
    let mut c = std::process::Command::new("unshare");
    c.args(["-rn", "sh", "-c", "ip link set lo up && exec \"$@\"", "sh"]);
    c.arg(std::env::current_exe().unwrap());
    c.args([name, "--exact", "--include-ignored", "--nocapture", "--test-threads=1"]).env(INSIDE, "1");
    if let Some(p) = path {
        let old = std::env::var("PATH").unwrap_or_default();
        c.env("PATH", format!("{}:{old}", p.display()));
    }
    let o = c.output().expect("unshare (util-linux)");
    let (out, err) = (String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success(), "in the namespace:\n{out}\n{err}");
    assert!(out.contains("1 passed"), "{name} is not the name of a test:\n{out}");
    false
}
