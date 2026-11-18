import json
import os
import pwd
import re
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

from . import __version__, firewall
from .binaries import resolve_binaries
from .config import BRIDGE_TYPES, TRANSPORT_TYPES
from .output import info, success, warning


class RuntimeErrorBase(RuntimeError):
    pass


def _user_context():
    if os.geteuid() != 0:
        raise RuntimeErrorBase("root is required; run this command with sudo")
    value = os.environ.get("SUDO_UID")
    if not value:
        raise RuntimeErrorBase("run with sudo from your normal user, not from a root shell")
    try:
        account = pwd.getpwuid(int(value))
    except (ValueError, KeyError) as exc:
        raise RuntimeErrorBase("cannot identify the user who called sudo") from exc
    return account


def _paths(account):
    home = Path(account.pw_dir)
    state_dir = home / ".local/state/tor-ubuntu-touch"
    data_dir = home / ".local/share/tor-ubuntu-touch/data"
    return {
        "home": home,
        "state_dir": state_dir,
        "state_file": state_dir / "state.json",
        "log_file": state_dir / "tor.log",
        "data_dir": data_dir,
        "run_dir": Path(f"/run/tor-ubuntu-touch-{account.pw_uid}"),
        "exec_dir": Path(f"/home/.tor-ubuntu-touch-{account.pw_uid}"),
    }


def _process_uids():
    used = set()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            values = (entry / "status").read_text(encoding="ascii")
            uid_line = next(line for line in values.splitlines() if line.startswith("Uid:"))
            used.update(int(value) for value in uid_line.split()[1:5])
        except (OSError, ValueError, StopIteration):
            continue
    return used


def _tor_account(name, caller_uid):
    if name != "auto":
        try:
            account = pwd.getpwnam(name)
        except KeyError as exc:
            raise RuntimeErrorBase(f"Tor runtime user does not exist: {name}") from exc
        if account.pw_uid in (0, caller_uid) or account.pw_gid == 0:
            raise RuntimeErrorBase("tor.tor_user must be a separate unprivileged account")
        processes = _uid_processes(account.pw_uid)
        if processes:
            raise RuntimeErrorBase(
                f"Tor runtime user {name} is already used by: {'; '.join(processes[:3])}. "
                "Use tor.tor_user: auto or choose an unused account."
            )
        return account

    used_uids = _process_uids()
    accounts = sorted(pwd.getpwall(), key=lambda item: item.pw_uid)
    for account in accounts:
        if not 100 <= account.pw_uid < 1000 or account.pw_uid == caller_uid or account.pw_gid == 0:
            continue
        if account.pw_uid not in used_uids:
            return account

    assigned_uids = {item.pw_uid for item in accounts}
    for uid in range(60000, 65000):
        if uid not in assigned_uids and uid not in used_uids and uid != caller_uid:
            return SimpleNamespace(
                pw_name=f"tor-runtime-{uid}",
                pw_uid=uid,
                pw_gid=65534,
                pw_dir="/",
            )
    raise RuntimeErrorBase("cannot find an unused UID for the Tor process")


def _ensure_user_dir(path, account, mode=0o700):
    home = Path(account.pw_dir).resolve()
    path = Path(path)
    try:
        relative = path.relative_to(home)
    except ValueError as exc:
        raise RuntimeErrorBase(f"runtime path is outside the user's home: {path}") from exc
    current = home
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise RuntimeErrorBase(f"refusing to use a symlink in the runtime path: {current}")
    path.mkdir(parents=True, exist_ok=True)
    current = path
    while current != home and home in current.parents:
        os.chown(current, account.pw_uid, account.pw_gid)
        current = current.parent
    path.chmod(mode)


def _chown_tree(path, uid, gid):
    path = Path(path)
    if not path.exists():
        return
    for current, directories, files in os.walk(path):
        os.chown(current, uid, gid)
        for name in directories + files:
            item = Path(current) / name
            try:
                os.chown(item, uid, gid, follow_symlinks=False)
            except (NotImplementedError, OSError):
                pass


def _copy_data_to_runtime(source, destination, tor_account):
    if destination.exists():
        shutil.rmtree(destination)
    if source.exists():
        shutil.copytree(source, destination, symlinks=True)
    else:
        destination.mkdir(parents=True)
    destination.chmod(0o700)
    _chown_tree(destination, tor_account.pw_uid, tor_account.pw_gid)


def _save_runtime_data(source, destination, account):
    if not source.exists():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination, symlinks=True)
    destination.chmod(0o700)
    _chown_tree(destination, account.pw_uid, account.pw_gid)


def _check_port(port, protocol):
    kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError as exc:
            raise RuntimeErrorBase(f"127.0.0.1:{port}/{protocol} is already in use") from exc


def _prepare_binaries(exec_dir, user_home, use_nix, bridge_types):
    binaries = resolve_binaries(use_nix=use_nix, user_home=user_home)
    tor = binaries["tor"]
    transport_sources = binaries["transports"]
    bridge_types = list(bridge_types)
    for bridge_type in bridge_types:
        if bridge_type == "plain":
            continue
        if not transport_sources.get(bridge_type):
            raise RuntimeErrorBase(
                f"{bridge_type} transport binary was not found; run --download-binaries "
                "or install the required transport in your Nix profile"
            )

    exec_dir = Path(exec_dir)
    if exec_dir.is_symlink():
        raise RuntimeErrorBase(f"refusing to use a symlink as runtime binary directory: {exec_dir}")
    exec_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    exec_dir.chmod(0o755)
    bin_dir = exec_dir / "bin"
    if bin_dir.is_symlink():
        raise RuntimeErrorBase(f"refusing to use a symlink as runtime binary directory: {bin_dir}")
    bin_dir.mkdir(mode=0o755, exist_ok=True)
    bin_dir.chmod(0o755)

    tor_target = bin_dir / "tor"
    shutil.copy2(tor, tor_target)
    tor_target.chmod(0o755)

    copied = {}
    transport_targets = {}
    for bridge_type in bridge_types:
        if bridge_type == "plain":
            continue
        source = Path(transport_sources[bridge_type]).resolve()
        if source not in copied:
            name = source.name
            target = bin_dir / name
            if target.exists() and target.is_symlink():
                raise RuntimeErrorBase(f"refusing to overwrite a symlink: {target}")
            shutil.copy2(source, target)
            target.chmod(0o755)
            copied[source] = target
        transport_targets[bridge_type] = copied[source]
    return tor_target, transport_targets


def _write_torrc(path, cfg, data_dir, transports, bridge_lines):
    tor = cfg["tor"]
    lines = [
        "ClientOnly 1",
        "RunAsDaemon 0",
        f"DataDirectory {data_dir}",
        "SafeLogging 1",
        "AvoidDiskWrites 1",
        "ClientDNSRejectInternalAddresses 1",
        "ClientRejectInternalAddresses 1",
        "AutomapHostsOnResolve 1",
        "VirtualAddrNetworkIPv4 10.192.0.0/10",
        "Log notice stdout",
        f"SocksPort 127.0.0.1:{tor['socks_port']}",
        f"TransPort 127.0.0.1:{tor['trans_port']}",
        f"DNSPort 127.0.0.1:{tor['dns_port']}",
    ]
    if bridge_lines:
        lines.append("UseBridges 1")
        grouped = {}
        for bridge_type, executable in transports.items():
            if bridge_type not in TRANSPORT_TYPES:
                continue
            grouped.setdefault(str(executable), set()).add(bridge_type)
        for executable, bridge_types in sorted(grouped.items()):
            names = ",".join(sorted(bridge_types))
            lines.append(f"ClientTransportPlugin {names} exec {executable}")
        lines.extend(f"Bridge {bridge}" for bridge in bridge_lines)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o644)


def _select_bridges(cfg, requested):
    if not requested:
        return [], []
    if requested == ["all"]:
        selected = [name for name in BRIDGE_TYPES if cfg["bridges"].get(name)]
        if not selected:
            raise RuntimeErrorBase("no bridges are configured in config.json")
    else:
        selected = list(dict.fromkeys(requested))
    missing = [name for name in selected if not cfg["bridges"].get(name)]
    if missing:
        raise RuntimeErrorBase(
            "no bridge lines configured for: " + ", ".join(missing) + "; add them to config.json"
        )
    lines = []
    for bridge_type in selected:
        lines.extend(cfg["bridges"][bridge_type])
    return selected, lines

def _verify_tor(tor, torrc, tor_account, home_dir):
    try:
        result = subprocess.run(
            [str(tor), "--verify-config", "-f", str(torrc)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            preexec_fn=lambda: _drop_privileges(tor_account.pw_uid, tor_account.pw_gid),
            env={
                **os.environ,
                "HOME": str(home_dir),
                "USER": tor_account.pw_name,
                "LOGNAME": tor_account.pw_name,
            },
        )
    except PermissionError as exc:
        raise RuntimeErrorBase(
            f"Tor cannot be executed by the runtime user from {tor}; keep binaries on an executable, accessible filesystem"
        ) from exc
    if result.returncode != 0:
        raise RuntimeErrorBase(f"Tor rejected its configuration:\n{result.stdout.strip()}")


def _wait_ready(process, log_file, timeout, offset=0):
    deadline = time.monotonic() + timeout
    reported_bootstrap = set()
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeErrorBase(f"Tor exited with status {process.returncode}; see {log_file}")
        try:
            with log_file.open("rb") as stream:
                stream.seek(offset)
                content = stream.read().decode("utf-8", errors="replace")
        except OSError:
            content = ""
        for match in re.finditer(r"^.*?Bootstrapped\s+(\d+)%", content, re.MULTILINE):
            percentage = int(match.group(1))
            if percentage not in reported_bootstrap:
                info(f"Tor bootstrap: Bootstrapped {percentage}%")
                reported_bootstrap.add(percentage)
        dns_ready = "Opened DNS listener connection (ready)" in content
        trans_ready = bool(re.search(r"Opened Transparent .*listener connection \(ready\)", content))
        bootstrapped = "Bootstrapped 100%" in content
        if dns_ready and trans_ready and bootstrapped:
            return
        time.sleep(1)
    raise RuntimeErrorBase(f"Tor did not finish bootstrap and open both listeners in {timeout}s; see {log_file}")


def _drop_privileges(uid, gid):
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    os.chdir("/")


def _group_alive(pgid):
    try:
        os.killpg(int(pgid), 0)
    except (ProcessLookupError, ValueError):
        return False
    except PermissionError:
        return True
    return True


def _write_state(path, data, account):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(data, indent=2) + "\n")
    os.chown(temporary, account.pw_uid, account.pw_gid)
    os.replace(temporary, path)


def _read_state(paths):
    try:
        return json.loads(paths["state_file"].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _process_start_ticks(pid):
    try:
        raw = Path(f"/proc/{int(pid)}/stat").read_text(encoding="ascii")
        fields = raw[raw.rfind(")") + 2:].split()
        return int(fields[19])
    except (OSError, ValueError, IndexError):
        return None


def _owned_tor_alive(state):
    try:
        pid = int(state.get("pid", 0))
        run_dir = Path(state.get("run_dir", ""))
        command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        command = [item.decode("utf-8", errors="replace") for item in command if item]
        if len(command) < 3 or command[1] != "-f":
            return False
        if Path(command[2]) != run_dir / "torrc":
            return False
        if os.getpgid(pid) != pid:
            return False
        expected = state.get("process_start_ticks")
        current = _process_start_ticks(pid)
        if expected is not None and current != expected:
            return False
        return True
    except (OSError, ValueError, TypeError):
        return False


def _uid_processes(uid):
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            values = (entry / "status").read_text(encoding="ascii")
            uid_line = next(line for line in values.splitlines() if line.startswith("Uid:"))
            if uid not in {int(value) for value in uid_line.split()[1:5]}:
                continue
            command = (entry / "cmdline").read_bytes().split(b"\0")
            executable = next((part for part in command if part), b"")
            name = Path(executable.decode("utf-8", errors="replace")).name
            found.append(name or f"PID {entry.name}")
        except (OSError, ValueError, StopIteration):
            continue
    return found


def start(cfg, use_bridges=None, use_nix=False):
    requested = list(use_bridges or [])
    account = _user_context()
    paths = _paths(account)
    existing = _read_state(paths)
    if existing and _owned_tor_alive(existing):
        raise RuntimeErrorBase("Tor is already running; use --status or --stop")
    if existing:
        stop_state(existing, paths, account)
    elif firewall.status():
        firewall.cleanup()

    selected_bridges, bridge_lines = _select_bridges(cfg, requested)
    tor_account = _tor_account(cfg["tor"]["tor_user"], account.pw_uid)
    info(f"Using isolated Tor runtime identity {tor_account.pw_name} (UID {tor_account.pw_uid})")
    if selected_bridges:
        info("Configured bridge types: " + ", ".join(selected_bridges))

    ports = {
        "trans": cfg["tor"]["trans_port"],
        "dns": cfg["tor"]["dns_port"],
        "socks": cfg["tor"]["socks_port"],
    }
    _check_port(ports["trans"], "tcp")
    _check_port(ports["socks"], "tcp")
    _check_port(ports["dns"], "udp")

    _ensure_user_dir(paths["state_dir"], account)
    _ensure_user_dir(paths["data_dir"], account)
    run_dir = paths["run_dir"]
    exec_dir = paths["exec_dir"]
    if run_dir.exists():
        shutil.rmtree(run_dir)
    if exec_dir.exists():
        shutil.rmtree(exec_dir)
    run_dir.mkdir(mode=0o755)
    runtime_data = run_dir / "data"
    _copy_data_to_runtime(paths["data_dir"], runtime_data, tor_account)

    try:
        tor, transports = _prepare_binaries(exec_dir, account.pw_dir, use_nix, selected_bridges)
        torrc = run_dir / "torrc"
        _write_torrc(torrc, cfg, runtime_data, transports, bridge_lines)
        _verify_tor(tor, torrc, tor_account, runtime_data)
    except BaseException:
        _save_runtime_data(runtime_data, paths["data_dir"], account)
        shutil.rmtree(run_dir, ignore_errors=True)
        shutil.rmtree(exec_dir, ignore_errors=True)
        raise

    info("Installing transparent-proxy firewall")
    try:
        firewall.apply(tor_account.pw_uid, ports, cfg["firewall"]["allow_lan"])
    except BaseException:
        _save_runtime_data(runtime_data, paths["data_dir"], account)
        shutil.rmtree(run_dir, ignore_errors=True)
        shutil.rmtree(exec_dir, ignore_errors=True)
        raise

    process = None
    try:
        info("Starting Tor; waiting for bootstrap progress from Tor logs")
        log_offset = paths["log_file"].stat().st_size if paths["log_file"].exists() else 0
        if paths["log_file"].is_symlink():
            raise RuntimeErrorBase("refusing to write the Tor log through a symlink")
        descriptor = os.open(
            paths["log_file"],
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "a", encoding="utf-8") as log_handle:
            os.fchown(log_handle.fileno(), account.pw_uid, account.pw_gid)
            os.fchmod(log_handle.fileno(), 0o600)
            log_handle.write(f"\n--- tor-ubuntu-touch {__version__} start ---\n")
            log_handle.flush()
            process = subprocess.Popen(
                [str(tor), "-f", str(torrc)],
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                close_fds=True,
                start_new_session=True,
                preexec_fn=lambda: _drop_privileges(tor_account.pw_uid, tor_account.pw_gid),
                env={**os.environ, "HOME": str(runtime_data), "USER": tor_account.pw_name, "LOGNAME": tor_account.pw_name},
            )
        _wait_ready(process, paths["log_file"], cfg["tor"]["bootstrap_timeout"], log_offset)
        state = {
            "pid": process.pid,
            "process_start_ticks": _process_start_ticks(process.pid),
            "tor_uid": tor_account.pw_uid,
            "tor_user": tor_account.pw_name,
            "caller_uid": account.pw_uid,
            "run_dir": str(run_dir),
            "exec_dir": str(exec_dir),
            "runtime_data": str(runtime_data),
            "persistent_data": str(paths["data_dir"]),
            "log_file": str(paths["log_file"]),
            "bridges": selected_bridges,
            "started": int(time.time()),
        }
        _write_state(paths["state_file"], state, account)
    except BaseException:
        if process:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and _group_alive(process.pid):
                time.sleep(0.2)
            if _group_alive(process.pid):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        firewall.cleanup()
        _save_runtime_data(runtime_data, paths["data_dir"], account)
        shutil.rmtree(run_dir, ignore_errors=True)
        shutil.rmtree(exec_dir, ignore_errors=True)
        raise

    mode = "bridges: " + ", ".join(selected_bridges) if selected_bridges else "direct Tor"
    success(f"Transparent Tor proxy is running ({mode})")
    info(f"Logs: {paths['log_file']}")
    info("Stop with: sudo ./tor-ubuntu-touch --stop")

def stop_state(state, paths, account):
    pid = int(state.get("pid", 0) or 0)
    if pid and _owned_tor_alive(state) and _group_alive(pid):
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline and _group_alive(pid):
            time.sleep(0.25)
        if _group_alive(pid):
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    firewall.cleanup()
    runtime_data = Path(state.get("runtime_data", ""))
    persistent_data = Path(state.get("persistent_data", str(paths["data_dir"])))
    if runtime_data.is_dir() and runtime_data.parent == paths["run_dir"]:
        _save_runtime_data(runtime_data, persistent_data, account)
    run_dir = Path(state.get("run_dir", str(paths["run_dir"])))
    if run_dir == paths["run_dir"]:
        shutil.rmtree(run_dir, ignore_errors=True)
    exec_dir = Path(state.get("exec_dir", str(paths["exec_dir"])))
    if exec_dir == paths["exec_dir"]:
        shutil.rmtree(exec_dir, ignore_errors=True)
    paths["state_file"].unlink(missing_ok=True)


def stop():
    account = _user_context()
    paths = _paths(account)
    state = _read_state(paths)
    if state:
        stop_state(state, paths, account)
        success("Tor stopped and firewall rules removed")
    else:
        firewall.cleanup()
        shutil.rmtree(paths["run_dir"], ignore_errors=True)
        shutil.rmtree(paths["exec_dir"], ignore_errors=True)
        info("No active Tor state found; project firewall chains were cleaned")


def status():
    account = _user_context()
    paths = _paths(account)
    state = _read_state(paths)
    if not state:
        if firewall.status():
            warning("Tor state is missing but the project firewall chains are active")
            info("Run --stop to remove the remaining rules")
        else:
            info("Tor is not running")
        return
    alive = _owned_tor_alive(state)
    fw = firewall.status()
    if alive and fw:
        success(f"Tor is running (PID {state['pid']})")
        active_bridges = state["bridges"]
        info("Mode: " + ("bridges: " + ", ".join(active_bridges) if active_bridges else "direct Tor"))
        info(f"Logs: {paths['log_file']}")
    else:
        warning("Tor or its firewall is not fully active")
        info("Run --stop to clean up, then start again")


def show_logs(lines=80, follow=False):
    account = _user_context()
    paths = _paths(account)
    log_file = paths["log_file"]
    if not log_file.exists():
        raise RuntimeErrorBase(f"log file not found: {log_file}")
    if follow:
        with log_file.open("r", encoding="utf-8", errors="replace") as stream:
            stream.seek(0, os.SEEK_END)
            try:
                while True:
                    line = stream.readline()
                    if line:
                        print(line, end="")
                    else:
                        time.sleep(0.25)
            except KeyboardInterrupt:
                return
    content = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
    print("\n".join(content[-lines:]))
