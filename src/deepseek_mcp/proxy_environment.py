"""Normalize proxy environment values that HTTP transports cannot parse."""
from __future__ import annotations

import contextlib
import logging
import os
import re
import urllib.request
from collections.abc import Iterator, Mapping
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

NO_PROXY_NAMES = ("NO_PROXY", "no_proxy")
PROXY_NAMES = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "all_proxy",
)
MAX_LOGGED_ENTRIES = 8
_BRACKETED_IPV6 = re.compile(r"^\[(?P<host>[^\]]*:[^\]]*)\](?::(?P<port>\d+))?$")


def normalize_no_proxy(value: str) -> tuple[str, list[str]]:
    """Unbracket IPv6 hosts in a ``no_proxy`` value, listing what changed.

    Docker Desktop writes ``NO_PROXY=localhost,127.0.0.1,[::1]`` and httpx
    parses every entry as a URL, so the bracketed literal raised
    ``InvalidURL: Invalid port: ':1]'`` inside the provider child. That was
    swallowed as ``category=client``, which reads like a DeepSeek outage
    instead of a local proxy configuration accident.
    """
    entries: list[str] = []
    changed: list[str] = []
    for raw in value.split(","):
        entry = raw.strip()
        if not entry:
            continue
        match = _BRACKETED_IPV6.fullmatch(entry)
        if match:
            port = match.group("port")
            host = match.group("host")
            entry = f"{host}:{port}" if port else host
            changed.append(raw.strip())
        entries.append(entry)
    return ",".join(entries), changed


def sanitize_environment(environment: Mapping[str, str]) -> dict[str, str]:
    """Return a copy of ``environment`` with parsable ``no_proxy`` spellings."""
    result = dict(environment)
    for name in NO_PROXY_NAMES:
        value = result.get(name)
        if value is None:
            continue
        normalized, changed = normalize_no_proxy(value)
        if changed:
            result[name] = normalized
            _note_normalized(name, changed)
    return result


def proxy_host_port(value: str) -> str:
    """Return the authoritative ``host:port`` of a proxy value, dropping any scheme.

    Args:
        value: ``http://127.0.0.1:7892``, ``https://127.0.0.1:7892``,
            or a bare ``127.0.0.1:7892``.

    Returns:
        The ``host:port`` portion, or an empty string when it cannot be parsed.
    """
    text = value.strip()
    if not text:
        return ""
    if "://" not in text:
        return text
    try:
        parsed = urlsplit(text)
    except ValueError:
        return ""
    host = parsed.hostname
    if not host:
        return ""
    port = parsed.port
    return f"{host}:{port}" if port else host


def repair_registry_proxy() -> list[str]:
    """Normalize the Windows registry proxy into a usable HTTP proxy in this process.

    Returns:
        The environment variable names that were written.

    Why this exists:
        ``urllib.request.getproxies()`` on Windows applies a scheme by field
        name. With a registry value of ``127.0.0.1:7897`` it yields
        ``{"http": "http://127.0.0.1:7897", "https": "https://127.0.0.1:7897"}``
        (see ``getproxies_registry`` in CPython). That ``https://`` entry is
        wrong: a local proxy port is a plain HTTP endpoint, not a TLS server.
        httpx then attempts TLS to the proxy itself and fails with
        ``ValueError: check_hostname requires server_hostname``, which the agent
        loop reports as ``category=connection``.

        Host agents such as Codex and Claude Code usually export no proxy
        variables, so the child process falls back to the registry and hits this
        path every time. Take only the host:port and publish it as a plain HTTP
        proxy. Nothing is written when the process already has proxy variables,
        so an explicit user configuration always wins.
    """
    if os.name != "nt":
        return []
    if any(os.environ.get(name) for name in PROXY_NAMES):
        return []

    try:
        detected = urllib.request.getproxies()
    except Exception:
        return []

    candidate = detected.get("http") or detected.get("https") or ""
    host_port = proxy_host_port(candidate)
    if not host_port:
        return []

    url = f"http://{host_port}"
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        os.environ[name] = url
    logger.info("repaired proxy environment from Windows registry: %s", url)
    return ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]


@contextlib.contextmanager
def sanitized_no_proxy_scope() -> Iterator[None]:
    """Fix this process's ``no_proxy`` only while a client reads the environment.

    httpx has no way to inject an environment, so the value must be corrected
    in place; restoring it immediately keeps a request from mutating the
    process for anything else running in it.
    """
    original = {name: os.environ.get(name) for name in NO_PROXY_NAMES}
    sanitized = sanitize_environment(
        {name: value for name, value in original.items() if value is not None}
    )
    try:
        for name, value in sanitized.items():
            os.environ[name] = value
        yield
    finally:
        for name, value in original.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _note_normalized(name: str, changed: list[str]) -> None:
    shown = ", ".join(changed[:MAX_LOGGED_ENTRIES])
    suffix = ", ..." if len(changed) > MAX_LOGGED_ENTRIES else ""
    logger.warning(
        "normalized %d unparsable %s entries: %s%s", len(changed), name, shown, suffix
    )
