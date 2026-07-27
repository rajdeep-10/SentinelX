"""Unit tests for config.py — no live target needed."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import TargetConfig, DVWA_CONFIG, generic_config, SEVERITY_WEIGHT


class TestSEVERITY_WEIGHT:
    def test_has_all_levels(self):
        assert "CRITICAL" in SEVERITY_WEIGHT
        assert "HIGH" in SEVERITY_WEIGHT
        assert "MEDIUM" in SEVERITY_WEIGHT
        assert "LOW" in SEVERITY_WEIGHT
        assert "UNKNOWN" not in SEVERITY_WEIGHT

    def test_ordering(self):
        assert SEVERITY_WEIGHT["CRITICAL"] > SEVERITY_WEIGHT["HIGH"]
        assert SEVERITY_WEIGHT["HIGH"] > SEVERITY_WEIGHT["MEDIUM"]
        assert SEVERITY_WEIGHT["MEDIUM"] > SEVERITY_WEIGHT["LOW"]

    def test_values(self):
        assert SEVERITY_WEIGHT == {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}


class TestTargetConfig:
    def test_default_dvwa(self):
        cfg = TargetConfig()
        assert cfg.name == "DVWA"
        assert cfg.base_url == "http://127.0.0.1"
        assert cfg.login_url == "/login.php"
        assert cfg.crawl_mode == "fixed"

    def test_full_url_with_path(self):
        cfg = TargetConfig(base_url="http://10.0.0.1")
        assert cfg.full_url("/test.php") == "http://10.0.0.1/test.php"

    def test_full_url_without_slash(self):
        cfg = TargetConfig(base_url="http://10.0.0.1")
        assert cfg.full_url("test.php") == "http://10.0.0.1/test.php"

    def test_full_url_already_full(self):
        cfg = TargetConfig(base_url="http://10.0.0.1")
        assert cfg.full_url("http://other.com/path") == "http://other.com/path"

    def test_strips_trailing_slash(self):
        cfg = TargetConfig(base_url="http://example.com/")
        assert cfg.base_url == "http://example.com"

    def test_base_url_with_port(self):
        cfg = TargetConfig(base_url="http://127.0.0.1:8080")
        assert cfg.base_url == "http://127.0.0.1:8080"

    def test_custom_values(self):
        cfg = TargetConfig(
            name="Custom",
            base_url="http://10.0.0.5",
            login_url="/auth.php",
            username_field="user",
            password_field="pass",
            crawl_mode="discover",
            discover_depth=3,
        )
        assert cfg.name == "Custom"
        assert cfg.login_url == "/auth.php"
        assert cfg.username_field == "user"
        assert cfg.password_field == "pass"
        assert cfg.crawl_mode == "discover"
        assert cfg.discover_depth == 3


class TestDVWA_CONFIG:
    def test_is_target_config(self):
        assert isinstance(DVWA_CONFIG, TargetConfig)

    def test_dvwa_values(self):
        assert DVWA_CONFIG.name == "DVWA"
        assert DVWA_CONFIG.login_url == "/login.php"
        assert DVWA_CONFIG.security_level_url == "/security.php"
        assert len(DVWA_CONFIG.fixed_pages) == 10  # 10 vulnerability pages

    def test_brute_config(self):
        assert DVWA_CONFIG.brute_url == "/vulnerabilities/brute/"
        assert DVWA_CONFIG.brute_success_text == "Welcome to the password protected area"


class TestGenericConfig:
    def test_basic(self):
        cfg = generic_config("http://10.0.0.1")
        assert cfg.name == "Generic Target"
        assert cfg.base_url == "http://10.0.0.1"
        assert cfg.login_url is None
        assert cfg.crawl_mode == "discover"

    def test_without_http(self):
        cfg = generic_config("10.0.0.1")
        assert cfg.base_url == "10.0.0.1"

    def test_discover_depth_default(self):
        cfg = generic_config("http://target")
        assert cfg.discover_depth == 2
