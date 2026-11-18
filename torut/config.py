import ipaddress
import json
import os
import pwd
import re
from pathlib import Path

from .output import info


ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.json"
EXAMPLE_PATH = ROOT / "config.example.json"
BRIDGE_TYPES = ("plain", "obfs4", "webtunnel", "snowflake")
TRANSPORT_TYPES = ("obfs4", "webtunnel", "snowflake")


class ConfigError(ValueError):
    pass


def ensure_config():
    if CONFIG_PATH.is_symlink():
        raise ConfigError(f"refusing to use a symlink as {CONFIG_PATH.name}")
    if CONFIG_PATH.exists():
        return False
    descriptor = os.open(CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(EXAMPLE_PATH.read_bytes())
    if os.geteuid() == 0 and os.environ.get("SUDO_UID"):
        account = pwd.getpwuid(int(os.environ["SUDO_UID"]))
        os.chown(CONFIG_PATH, account.pw_uid, account.pw_gid)
    CONFIG_PATH.chmod(0o600)
    info(f"Created {CONFIG_PATH.name}; add bridge lines there if needed")
    return True


def load_config():
    ensure_config()
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read {CONFIG_PATH}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("top-level JSON value must be an object")

    tor = data.setdefault("tor", {})
    firewall = data.setdefault("firewall", {})
    if not isinstance(tor, dict) or not isinstance(firewall, dict):
        raise ConfigError("tor and firewall must be JSON objects")

    if "bridge" in data:
        raise ConfigError("bridge is no longer supported; use the 'bridges' object with arrays")
    bridges = data.setdefault("bridges", {})
    if not isinstance(bridges, dict):
        raise ConfigError("bridges must be a JSON object")
    unknown_bridge_types = sorted(set(bridges) - set(BRIDGE_TYPES))
    if unknown_bridge_types:
        raise ConfigError("unknown bridge type(s): " + ", ".join(unknown_bridge_types))
    tor.setdefault("trans_port", 9040)
    tor.setdefault("dns_port", 5353)
    tor.setdefault("socks_port", 9050)
    tor.setdefault("bootstrap_timeout", 240)
    tor.setdefault("tor_user", "auto")
    firewall.setdefault("allow_lan", True)
    for bridge_type in BRIDGE_TYPES:
        bridges.setdefault(bridge_type, [])

    for key in ("trans_port", "dns_port", "socks_port"):
        value = tor[key]
        if not isinstance(value, int) or isinstance(value, bool) or not 1024 <= value <= 65535:
            raise ConfigError(f"tor.{key} must be an integer from 1024 to 65535")
    if len({tor["trans_port"], tor["dns_port"], tor["socks_port"]}) != 3:
        raise ConfigError("Tor ports must be different")
    timeout = tor["bootstrap_timeout"]
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 30 <= timeout <= 1800:
        raise ConfigError("tor.bootstrap_timeout must be from 30 to 1800 seconds")
    if not isinstance(tor["tor_user"], str) or not tor["tor_user"].strip():
        raise ConfigError("tor.tor_user must be a non-empty account name")
    if not isinstance(firewall["allow_lan"], bool):
        raise ConfigError("firewall.allow_lan must be true or false")

    for bridge_type in BRIDGE_TYPES:
        entries = bridges[bridge_type]
        if not isinstance(entries, list):
            raise ConfigError(f"bridges.{bridge_type} must be an array of bridge lines")
        normalized = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, str):
                raise ConfigError(f"bridges.{bridge_type}[{index}] must be a string")
            normalized.append(parse_bridge(bridge_type, entry))
        bridges[bridge_type] = normalized
    return data


def _strip_bridge_prefix(value):
    text = value.strip()
    if text.lower().startswith("bridge "):
        text = text[7:].strip()
    if not text or any(char in text for char in ("\n", "\r", "\0")):
        raise ConfigError("bridge lines must be non-empty single-line strings")
    return text


def _validate_endpoint(value, allow_hostname=True):
    match = re.fullmatch(r"(\[[0-9A-Fa-f:]+\]|[^\s:]+):(\d{1,5})", value)
    if not match:
        raise ConfigError("bridge address must use HOST:PORT or [IPv6]:PORT format")
    host = match.group(1)
    if host.startswith("["):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError as exc:
            raise ConfigError("invalid IPv6 bridge address") from exc
    else:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not allow_hostname or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
                raise ConfigError("invalid bridge host")
            if re.fullmatch(r"[0-9.]+", host):
                raise ConfigError("invalid IPv4 bridge address")
            if host.startswith(".") or host.endswith(".") or ".." in host:
                raise ConfigError("invalid bridge hostname")
    port = int(match.group(2))
    if not 1 <= port <= 65535:
        raise ConfigError("bridge port must be from 1 to 65535")


def parse_bridge(bridge_type, value):
    text = _strip_bridge_prefix(value)
    parts = text.split()
    if bridge_type == "plain":
        if len(parts) > 2:
            raise ConfigError("plain bridge format is: HOST:PORT [FINGERPRINT]")
        _validate_endpoint(parts[0])
        if len(parts) == 2 and not re.fullmatch(r"[A-Fa-f0-9]{40}", parts[1]):
            raise ConfigError("plain bridge fingerprint must contain 40 hexadecimal characters")
        return text

    expected = bridge_type
    if parts[0].lower() != expected:
        raise ConfigError(f"bridges.{bridge_type} entries must start with '{expected}'")
    if len(parts) < 3:
        raise ConfigError(f"{bridge_type} bridge line is incomplete")
    _validate_endpoint(parts[1], allow_hostname=False)
    if not re.fullmatch(r"[A-Fa-f0-9]{40}", parts[2]):
        raise ConfigError(f"{bridge_type} bridge fingerprint must contain 40 hexadecimal characters")

    if bridge_type == "obfs4":
        if len(parts) < 5 or not any(part.startswith("cert=") and len(part) > 5 for part in parts):
            raise ConfigError("obfs4 bridge must include cert= and iat-mode= parameters")
        if not any(re.fullmatch(r"iat-mode=[01]", part) for part in parts):
            raise ConfigError("obfs4 bridge must include iat-mode=0 or iat-mode=1")
    elif bridge_type == "webtunnel":
        if not any(part.startswith("url=https://") for part in parts[3:]):
            raise ConfigError("webtunnel bridge must include an url=https:// parameter")
    elif bridge_type == "snowflake":
        if len(parts) < 3:
            raise ConfigError("snowflake bridge line is incomplete")
    return text
