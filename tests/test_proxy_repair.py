"""Tests for Windows registry proxy normalization.

Covers the defect where a host agent exports no HTTP(S)_PROXY variables:
``urllib.request.getproxies()`` then reads the Windows registry and derives
``https://127.0.0.1:7897`` from a plain ``127.0.0.1:7897`` entry. That fake TLS
proxy endpoint makes the provider child fail with ``category=connection``.
"""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from deepseek_mcp.proxy_environment import (
    PROXY_NAMES,
    proxy_host_port,
    repair_registry_proxy,
)


class ProxyHostPortTests(unittest.TestCase):
    """The scheme-stripping helper must accept every spelling urllib produces."""

    def test_strips_http_scheme(self) -> None:
        self.assertEqual(proxy_host_port("http://127.0.0.1:7892"), "127.0.0.1:7892")

    def test_strips_bogus_https_scheme(self) -> None:
        """urllib derives https:// from the field name; strip it back to host:port."""
        self.assertEqual(proxy_host_port("https://127.0.0.1:7897"), "127.0.0.1:7897")

    def test_bare_host_port(self) -> None:
        self.assertEqual(proxy_host_port("127.0.0.1:7892"), "127.0.0.1:7892")

    def test_host_without_port(self) -> None:
        self.assertEqual(proxy_host_port("http://proxy.local"), "proxy.local")

    def test_empty_and_invalid(self) -> None:
        self.assertEqual(proxy_host_port(""), "")
        self.assertEqual(proxy_host_port("   "), "")


@unittest.skipUnless(os.name == "nt", "registry proxies only exist on Windows")
class RepairRegistryProxyTests(unittest.TestCase):
    """The repair must only act when no proxy variable is set, and must emit HTTP."""

    def test_repairs_when_no_proxy_env(self) -> None:
        with patch.dict(os.environ, {}, clear=True), patch(
            "deepseek_mcp.proxy_environment.urllib.request.getproxies",
            return_value={
                "http": "http://127.0.0.1:7897",
                "https": "https://127.0.0.1:7897",
            },
        ):
            applied = repair_registry_proxy()
            self.assertTrue(applied)
            for name in ("HTTP_PROXY", "HTTPS_PROXY"):
                self.assertEqual(os.environ[name], "http://127.0.0.1:7897")

    def test_does_not_override_existing_env(self) -> None:
        """An explicit user configuration always wins over the registry."""
        with patch.dict(
            os.environ, {"HTTPS_PROXY": "http://10.0.0.1:8080"}, clear=True
        ), patch(
            "deepseek_mcp.proxy_environment.urllib.request.getproxies",
            return_value={"http": "http://127.0.0.1:7897"},
        ):
            self.assertEqual(repair_registry_proxy(), [])
            self.assertEqual(os.environ["HTTPS_PROXY"], "http://10.0.0.1:8080")

    def test_returns_empty_when_registry_has_no_proxy(self) -> None:
        with patch.dict(os.environ, {}, clear=True), patch(
            "deepseek_mcp.proxy_environment.urllib.request.getproxies",
            return_value={},
        ):
            self.assertEqual(repair_registry_proxy(), [])

    def test_all_proxy_names_covered(self) -> None:
        """PROXY_NAMES must cover both cases, or the guard would miss a variable."""
        self.assertIn("HTTP_PROXY", PROXY_NAMES)
        self.assertIn("https_proxy", PROXY_NAMES)


if __name__ == "__main__":
    unittest.main()
