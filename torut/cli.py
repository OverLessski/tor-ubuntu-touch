import argparse
import subprocess

from . import __version__
from .binaries import BinaryError, download_binaries
from .config import BRIDGE_TYPES, ConfigError, ensure_config, load_config
from .firewall import FirewallError
from .output import die, error, info, success
from .runtime import RuntimeErrorBase, show_logs, start, status, stop


def parser():
    result = argparse.ArgumentParser(
        prog="tor-ubuntu-touch",
        description="Transparent Tor proxy for Ubuntu Touch",
    )
    actions = result.add_mutually_exclusive_group(required=True)
    actions.add_argument("--start", action="store_true", help="start the transparent proxy")
    actions.add_argument("--stop", action="store_true", help="stop Tor and remove firewall rules")
    actions.add_argument("--status", action="store_true", help="show service status")
    actions.add_argument("--logs", action="store_true", help="show the Tor log")
    actions.add_argument("--download-binaries", action="store_true", help="download Tor and pluggable-transport binaries into .bin")
    actions.add_argument("--init-config", action="store_true", help="create config.json from the example")
    result.add_argument(
        "--use-bridges",
        nargs="+",
        choices=(*BRIDGE_TYPES, "all"),
        metavar="TYPE",
        help="use configured bridge types: plain, obfs4, webtunnel, snowflake, or all",
    )
    result.add_argument("--nix-binaries", action="store_true", help="use Tor and transport binaries from Nix profiles")
    result.add_argument("--follow", action="store_true", help="follow the Tor log; use with --logs")
    result.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    if args.use_bridges and not args.start:
        die("--use-bridges can only be used with --start", 2)
    if args.nix_binaries and not args.start:
        die("--nix-binaries can only be used with --start", 2)
    if args.follow and not args.logs:
        die("--follow can only be used with --logs", 2)
    if args.use_bridges and "all" in args.use_bridges and len(args.use_bridges) > 1:
        die("'all' cannot be combined with individual bridge types", 2)
    try:
        if args.init_config:
            created = ensure_config()
            if created:
                success("Configuration file created")
            else:
                info("config.json already exists")
            return 0
        if args.download_binaries:
            download_binaries()
            return 0
        if args.logs:
            show_logs(follow=args.follow)
            return 0
        if args.start:
            cfg = load_config()
            start(cfg, use_bridges=args.use_bridges or [], use_nix=args.nix_binaries)
            return 0
        if args.stop:
            stop()
            return 0
        if args.status:
            status()
            return 0
    except (ConfigError, BinaryError, RuntimeErrorBase, FirewallError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        error(str(exc))
        return 1
    return 0
