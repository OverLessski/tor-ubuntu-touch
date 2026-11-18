import gzip
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from .config import ROOT
from .output import info, success, warning


BIN_DIR = ROOT / ".bin"
TOR_REPO = "https://deb.torproject.org/torproject.org"


class BinaryError(RuntimeError):
    pass


def _download(url, target):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    wget = shutil.which("wget")
    if wget:
        result = subprocess.run(
            [wget, "-q", "-T", "45", "-t", "2", "-O", str(target), url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode == 0 and target.exists() and target.stat().st_size:
            return
        target.unlink(missing_ok=True)
        detail = result.stderr.strip() or result.stdout.strip()
        raise BinaryError(f"wget failed for {url}: {detail}")
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "tor-ubuntu-touch/0.1"})
        with urllib.request.urlopen(request, timeout=45) as response, target.open("wb") as output:
            shutil.copyfileobj(response, output)
    except (OSError, urllib.error.URLError) as exc:
        target.unlink(missing_ok=True)
        raise BinaryError(f"download failed for {url}: {exc}") from exc
    if not target.exists() or not target.stat().st_size:
        raise BinaryError(f"empty download: {url}")


def _os_release():
    values = {}
    try:
        lines = Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    for line in lines:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"').strip("'")
    return values


def _architecture():
    machine = platform.machine().lower()
    mapping = {
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "armhf",
        "armv6l": "armhf",
        "x86_64": "amd64",
        "amd64": "amd64",
        "riscv64": "riscv64",
    }
    if machine not in mapping:
        raise BinaryError(f"unsupported CPU architecture: {machine}")
    return mapping[machine]


def _parse_packages(raw):
    if raw.startswith(b"\x1f\x8b"):
        raw = gzip.decompress(raw)
    entries = []
    for block in raw.decode("utf-8", errors="replace").split("\n\n"):
        item = {}
        current = None
        for line in block.splitlines():
            if line.startswith((" ", "\t")) and current:
                item[current] += "\n" + line[1:]
            elif ": " in line:
                current, value = line.split(": ", 1)
                item[current] = value
        if item.get("Package"):
            entries.append(item)
    return entries


def _find_entry(entries, name, arch):
    for item in entries:
        if item.get("Package") == name and item.get("Architecture") in (arch, "all"):
            if item.get("Filename") and item.get("SHA256"):
                return item
    return None


def _tor_project_entries(suite, arch, workdir):
    url = f"{TOR_REPO}/dists/{suite}/main/binary-{arch}/Packages.gz"
    target = workdir / f"torproject-{suite}-{arch}.Packages.gz"
    try:
        _download(url, target)
    except BinaryError:
        return []
    return _parse_packages(target.read_bytes())


def _ubuntu_entries(suite, arch, workdir):
    if arch in ("arm64", "armhf", "riscv64"):
        mirrors = ["https://ports.ubuntu.com/ubuntu-ports"]
    else:
        mirrors = ["https://archive.ubuntu.com/ubuntu", "https://old-releases.ubuntu.com/ubuntu"]
    for mirror in mirrors:
        collected = []
        for component in ("universe", "main"):
            url = f"{mirror}/dists/{suite}/{component}/binary-{arch}/Packages.gz"
            target = workdir / f"ubuntu-{suite}-{component}-{arch}.Packages.gz"
            try:
                _download(url, target)
                collected.extend(_parse_packages(target.read_bytes()))
            except BinaryError:
                continue
        if any(_find_entry(collected, name, arch) for name in ("tor", "lyrebird", "obfs4proxy", "snowflake-client", "webtunnel")):
            return collected, mirror
    return [], ""


def _download_package(entry, base_url, workdir):
    filename = entry["Filename"]
    url = f"{base_url.rstrip('/')}/{filename}"
    package_file = workdir / Path(filename).name
    _download(url, package_file)
    digest = hashlib.sha256(package_file.read_bytes()).hexdigest()
    if digest.lower() != entry["SHA256"].lower():
        package_file.unlink(missing_ok=True)
        raise BinaryError(f"SHA256 mismatch for {package_file.name}")
    return package_file, url, digest


def _extract_binary(package_file, candidates, destination, workdir):
    extractor = shutil.which("dpkg-deb")
    if not extractor:
        raise BinaryError("dpkg-deb is required to extract downloaded packages")
    unpack_dir = workdir / (package_file.stem + "-root")
    unpack_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [extractor, "-x", str(package_file), str(unpack_dir)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise BinaryError(f"dpkg-deb could not extract {package_file.name}: {result.stderr.strip()}")
    source = next((unpack_dir / candidate for candidate in candidates if (unpack_dir / candidate).is_file()), None)
    if source is None:
        raise BinaryError(f"binary not found in {package_file.name}: {', '.join(candidates)}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    destination.chmod(0o755)


def _commit_staged(staging):
    with tempfile.TemporaryDirectory(prefix=".download-", dir=BIN_DIR) as temp:
        commit_dir = Path(temp)
        for item in staging.iterdir():
            shutil.copy2(item, commit_dir / item.name)
        for name in ("tor", "lyrebird", "obfs4proxy", "snowflake-client", "webtunnel-client"):
            source = commit_dir / name
            if source.exists():
                os.replace(source, BIN_DIR / name)
        manifest = commit_dir / "manifest.json"
        if manifest.exists():
            os.replace(manifest, BIN_DIR / "manifest.json")


def download_binaries():
    suite_data = _os_release()
    suite = suite_data.get("UBUNTU_CODENAME") or suite_data.get("VERSION_CODENAME")
    distro = suite_data.get("ID", "unknown")
    arch = _architecture()
    if not suite:
        raise BinaryError("cannot detect OS codename from /etc/os-release")
    if BIN_DIR.is_symlink():
        raise BinaryError("refusing to write binaries through a .bin symlink")
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    info(f"Looking for official {arch} packages for {distro} {suite}")
    with tempfile.TemporaryDirectory(prefix="tor-ut-download-") as temp:
        workdir = Path(temp)
        staging = workdir / "bin"
        staging.mkdir()
        tor_entry = None
        package_entries = {}
        package_sources = {}
        entries = _tor_project_entries(suite, arch, workdir)
        if entries:
            tor_entry = _find_entry(entries, "tor", arch)
            for package_name in ("lyrebird", "snowflake-client", "webtunnel", "obfs4proxy"):
                found = _find_entry(entries, package_name, arch)
                if found:
                    package_entries[package_name] = found
                    package_sources[package_name] = (TOR_REPO, "Tor Project package repository")
        if distro == "ubuntu" and (not tor_entry or "lyrebird" not in package_entries):
            ubuntu_items, ubuntu_base = _ubuntu_entries(suite, arch, workdir)
            if not tor_entry:
                tor_entry = _find_entry(ubuntu_items, "tor", arch)
            for package_name in ("lyrebird", "snowflake-client", "webtunnel", "obfs4proxy"):
                if package_name not in package_entries:
                    found = _find_entry(ubuntu_items, package_name, arch)
                    if found:
                        package_entries[package_name] = found
                        package_sources[package_name] = (ubuntu_base, "Ubuntu official archive")
        if not tor_entry:
            raise BinaryError(f"no Tor package found for {distro} {suite} {arch}; use system packages or Nix")

        if _find_entry(entries, "tor", arch):
            tor_base = TOR_REPO
            tor_source = "Tor Project package repository"
        else:
            tor_base = ubuntu_base
            tor_source = "Ubuntu official archive"

        tor_package, tor_url, tor_hash = _download_package(tor_entry, tor_base, workdir)
        _extract_binary(tor_package, ["usr/bin/tor", "usr/sbin/tor"], staging / "tor", workdir)
        manifest = {
            "tor": {
                "version": tor_entry.get("Version", "unknown"),
                "source": tor_source,
                "url": tor_url,
                "sha256": tor_hash,
            },
            "transports": {},
        }

        extraction = {
            "lyrebird": (["usr/bin/lyrebird", "usr/sbin/lyrebird"], "lyrebird"),
            "obfs4proxy": (["usr/bin/obfs4proxy", "usr/sbin/obfs4proxy"], "obfs4proxy"),
            "snowflake-client": (["usr/bin/snowflake-client", "usr/sbin/snowflake-client"], "snowflake-client"),
            "webtunnel": (["usr/bin/webtunnel-client", "usr/sbin/webtunnel-client", "usr/bin/webtunnel"], "webtunnel-client"),
        }
        installed = []
        transport_packages = ("lyrebird",) if "lyrebird" in package_entries else ("obfs4proxy", "snowflake-client", "webtunnel")
        for package_name in transport_packages:
            entry = package_entries.get(package_name)
            if not entry:
                continue
            base_url, source_name = package_sources[package_name]
            package_file, package_url, package_hash = _download_package(entry, base_url, workdir)
            candidates, output_name = extraction[package_name]
            output_path = staging / output_name
            _extract_binary(package_file, candidates, output_path, workdir)
            manifest["transports"][output_name] = {
                "package": package_name,
                "version": entry.get("Version", "unknown"),
                "source": source_name,
                "url": package_url,
                "sha256": package_hash,
            }
            installed.append(output_name)

        if "lyrebird" not in installed and not installed:
            warning("No pluggable-transport package was found; direct Tor mode will still work")
        elif "lyrebird" not in installed:
            warning("Lyrebird is unavailable; only the separately installed transport binaries can be used")
        try:
            result = subprocess.run(
                [str(staging / "tor"), "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BinaryError(f"downloaded Tor cannot run on this Ubuntu Touch base: {exc}") from exc
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise BinaryError(f"downloaded Tor cannot run on this system: {detail}")
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        _commit_staged(staging)
        for name in ("lyrebird", "obfs4proxy", "snowflake-client", "webtunnel-client"):
            if name not in installed:
                (BIN_DIR / name).unlink(missing_ok=True)
    success(f"Tor {tor_entry.get('Version', 'unknown')} installed in .bin/tor")
    for name in installed:
        package = manifest["transports"][name]
        success(f"{package['package']} {package['version']} installed in .bin/{name}")
    if "lyrebird" in installed:
        info("Lyrebird provides obfs4, Snowflake and WebTunnel transports")
    success("Binary download and SHA256 verification completed")


def _resolve_in_paths(names, paths):
    for directory in paths:
        for name in names:
            candidate = directory / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate.resolve()
    return None


def resolve_binaries(use_nix=False, user_home=None):
    if use_nix:
        paths = []
        if user_home:
            profile_name = Path(user_home).name
            paths.extend([
                Path(user_home) / ".nix-profile/bin",
                Path(user_home) / ".local/state/nix/profile/bin",
                Path("/etc/profiles/per-user") / profile_name / "bin",
            ])
        paths.extend([
            Path("/nix/var/nix/profiles/default/bin"),
            Path("/run/current-system/sw/bin"),
        ])
        env_paths = [
            Path(value)
            for value in os.environ.get("PATH", "").split(os.pathsep)
            if value and "/nix/" in value
        ]
        paths.extend(env_paths)
        tor = _resolve_in_paths(["tor"], paths)
        if not tor:
            raise BinaryError("Tor was not found in Nix profiles; install tor and try again")
        names = {
            "obfs4": ["lyrebird"],
            "snowflake": ["lyrebird"],
            "webtunnel": ["lyrebird"],
        }
        return {
            "tor": tor,
            "transports": {key: _resolve_in_paths(candidates, paths) for key, candidates in names.items()},
        }

    search_paths = [BIN_DIR, Path("/usr/bin"), Path("/usr/sbin")]
    tor = _resolve_in_paths(["tor"], search_paths)
    if tor is None:
        tor = _resolve_in_paths(
            ["tor"], [Path(value) for value in os.environ.get("PATH", "").split(os.pathsep) if value]
        )
    if not tor:
        raise BinaryError("Tor not found; run ./tor-ubuntu-touch --download-binaries")

    names = {
        "lyrebird": ["lyrebird"],
        "obfs4": ["lyrebird", "obfs4proxy"],
        "snowflake": ["lyrebird", "snowflake-client"],
        "webtunnel": ["lyrebird", "webtunnel-client", "webtunnel"],
    }
    transport_paths = [BIN_DIR, Path("/usr/bin"), Path("/usr/sbin")]
    env_paths = [Path(value) for value in os.environ.get("PATH", "").split(os.pathsep) if value]
    transport_paths.extend(env_paths)
    return {
        "tor": tor,
        "transports": {key: _resolve_in_paths(candidates, transport_paths) for key, candidates in names.items()},
    }
