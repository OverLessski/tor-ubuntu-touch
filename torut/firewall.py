import shutil
import subprocess


NAT_CHAIN = "TUT_TOR_NAT"
OUT_CHAIN = "TUT_TOR_OUT"
OUT6_CHAIN = "TUT_TOR6_OUT"
TOR_VIRTUAL_NETWORK = "10.192.0.0/10"


class FirewallError(RuntimeError):
    pass


def _binary(name):
    path = shutil.which(name)
    if not path:
        raise FirewallError(f"required command not found: {name}")
    return path


def _run(binary, args, check=True):
    result = subprocess.run(
        [_binary(binary), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise FirewallError(f"{binary} {' '.join(args)} failed: {detail}")
    return result.returncode == 0


def _remove_jump(binary, table, chain):
    args = ["-t", table, "-D", "OUTPUT", "-j", chain] if table else ["-D", "OUTPUT", "-j", chain]
    while _run(binary, args, check=False):
        pass


def _remove_chain(binary, table, chain):
    _remove_jump(binary, table, chain)
    prefix = ["-t", table] if table else []
    _run(binary, [*prefix, "-F", chain], check=False)
    _run(binary, [*prefix, "-X", chain], check=False)


def cleanup():
    _remove_chain("iptables", "nat", NAT_CHAIN)
    _remove_chain("iptables", "filter", OUT_CHAIN)
    _remove_chain("ip6tables", "filter", OUT6_CHAIN)


def _append(binary, table, chain, rules):
    prefix = ["-t", table] if table else []
    for rule in rules:
        _run(binary, [*prefix, "-A", chain, *rule])


def apply(tor_uid, ports, allow_lan):
    cleanup()
    try:
        _run("iptables", ["-t", "nat", "-N", NAT_CHAIN])
        _run("iptables", ["-N", OUT_CHAIN])
        _run("ip6tables", ["-N", OUT6_CHAIN])

        nat_rules = [
            ["-m", "owner", "--uid-owner", str(tor_uid), "-j", "RETURN"],
            ["-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(ports["dns"])],
            ["-p", "tcp", "--dport", "53", "-j", "RETURN"],
            ["-d", TOR_VIRTUAL_NETWORK, "-p", "tcp", "-j", "REDIRECT", "--to-ports", str(ports["trans"])],
            ["-d", "127.0.0.0/8", "-j", "RETURN"],
            ["-d", "169.254.0.0/16", "-j", "RETURN"],
        ]
        if allow_lan:
            nat_rules.extend([
                ["-d", "10.0.0.0/8", "-j", "RETURN"],
                ["-d", "172.16.0.0/12", "-j", "RETURN"],
                ["-d", "192.168.0.0/16", "-j", "RETURN"],
            ])
        nat_rules.extend([
            ["-p", "tcp", "-j", "REDIRECT", "--to-ports", str(ports["trans"])],
            ["-j", "RETURN"],
        ])
        _append("iptables", "nat", NAT_CHAIN, nat_rules)

        out_rules = [
            ["-m", "owner", "--uid-owner", str(tor_uid), "-j", "ACCEPT"],
            ["-o", "lo", "-j", "ACCEPT"],
            ["-p", "tcp", "--dport", "53", "-j", "REJECT"],
            ["-d", TOR_VIRTUAL_NETWORK, "-j", "DROP"],
            ["-d", "127.0.0.0/8", "-j", "ACCEPT"],
            ["-d", "169.254.0.0/16", "-j", "ACCEPT"],
        ]
        if allow_lan:
            out_rules.extend([
                ["-d", "10.0.0.0/8", "-j", "ACCEPT"],
                ["-d", "172.16.0.0/12", "-j", "ACCEPT"],
                ["-d", "192.168.0.0/16", "-j", "ACCEPT"],
            ])
        out_rules.extend([
            ["-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"],
            ["-j", "DROP"],
        ])
        _append("iptables", None, OUT_CHAIN, out_rules)

        out6_rules = [
            ["-m", "owner", "--uid-owner", str(tor_uid), "-j", "ACCEPT"],
            ["-o", "lo", "-j", "ACCEPT"],
            ["-p", "udp", "--dport", "53", "-j", "DROP"],
            ["-p", "tcp", "--dport", "53", "-j", "DROP"],
            ["-p", "ipv6-icmp", "--icmpv6-type", "133", "-j", "ACCEPT"],
            ["-p", "ipv6-icmp", "--icmpv6-type", "135", "-j", "ACCEPT"],
            ["-p", "ipv6-icmp", "--icmpv6-type", "136", "-j", "ACCEPT"],
        ]
        if allow_lan:
            out6_rules.extend([
                ["-d", "fe80::/10", "-j", "ACCEPT"],
                ["-d", "fc00::/7", "-j", "ACCEPT"],
            ])
        out6_rules.append(["-j", "DROP"])
        _append("ip6tables", None, OUT6_CHAIN, out6_rules)

        _run("iptables", ["-t", "nat", "-I", "OUTPUT", "1", "-j", NAT_CHAIN])
        _run("iptables", ["-I", "OUTPUT", "1", "-j", OUT_CHAIN])
        _run("ip6tables", ["-I", "OUTPUT", "1", "-j", OUT6_CHAIN])
    except BaseException:
        cleanup()
        raise


def status():
    nat = _run("iptables", ["-t", "nat", "-C", "OUTPUT", "-j", NAT_CHAIN], check=False)
    out = _run("iptables", ["-C", "OUTPUT", "-j", OUT_CHAIN], check=False)
    out6 = _run("ip6tables", ["-C", "OUTPUT", "-j", OUT6_CHAIN], check=False)
    return nat and out and out6
