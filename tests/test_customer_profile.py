"""Tests for the customer-profile loader (config-driven organization identity)."""

from __future__ import annotations

from src.core.config import CustomerProfile, get_customer_profile


def test_shipped_profile_defaults_to_illumina():
    profile = get_customer_profile()
    assert profile.name == "Illumina"
    assert profile.brand_color_hex == "005DAA"
    assert profile.security_contact == "secops@illumina.com"
    assert profile.osint_source_name == "Illumina-OSINT"
    assert "illumina" in profile.product_keywords
    assert "dragen" in profile.product_keywords


def test_missing_profile_file_falls_back_to_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("CUSTOMER_PROFILE_PATH", str(tmp_path / "does_not_exist.yaml"))
    profile = get_customer_profile()
    assert profile == CustomerProfile()  # frozen dataclass equality → all defaults


def test_profile_loaded_from_yaml(monkeypatch, tmp_path):
    profile_file = tmp_path / "customer_profile.yaml"
    profile_file.write_text(
        "name: Acme Genomics\n"
        'brand_color_hex: "112233"\n'
        "security_contact: soc@acme.example\n"
        "osint_source_name: Acme-OSINT\n"
        "product_keywords:\n  - acme\n  - acmeseq\n"
    )
    monkeypatch.setenv("CUSTOMER_PROFILE_PATH", str(profile_file))
    profile = get_customer_profile()
    assert profile.name == "Acme Genomics"
    assert profile.brand_color_hex == "112233"
    assert profile.security_contact == "soc@acme.example"
    assert profile.osint_source_name == "Acme-OSINT"
    # Keywords are lowercased and replace (not extend) the defaults.
    assert profile.product_keywords == ("acme", "acmeseq")


def test_partial_yaml_uses_defaults_for_missing_fields(monkeypatch, tmp_path):
    profile_file = tmp_path / "customer_profile.yaml"
    profile_file.write_text("name: Partial Co\n")
    monkeypatch.setenv("CUSTOMER_PROFILE_PATH", str(profile_file))
    profile = get_customer_profile()
    assert profile.name == "Partial Co"
    # Unspecified fields fall back to the defaults.
    assert profile.brand_color_hex == CustomerProfile().brand_color_hex
    assert profile.security_contact == CustomerProfile().security_contact
