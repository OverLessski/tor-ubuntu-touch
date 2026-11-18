import os
import sys


_ENABLED = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _print(message, code):
    if _ENABLED:
        print(f"\033[{code}m{message}\033[0m")
    else:
        print(message)


def info(message):
    _print(f"[*] {message}", "1;37")


def success(message):
    _print(f"[+] {message}", "32")


def warning(message):
    _print(f"[!] {message}", "33")


def error(message):
    _print(f"[-] {message}", "31")


def die(message, code=1):
    error(message)
    raise SystemExit(code)
