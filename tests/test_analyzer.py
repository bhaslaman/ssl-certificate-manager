"""Tests for the certificate analyzer service."""

import pytest
from app.services.analyzer import CertificateAnalyzer
from app.services.generator import CertificateGenerator


class TestCertificateAnalyzer:
    """Test cases for CertificateAnalyzer."""

    @pytest.fixture
    def sample_cert(self):
        """Generate a sample certificate for testing."""
        key_pem, cert_pem = CertificateGenerator.generate_key_and_self_signed(
            subject_info={
                "CN": "test.example.com",
                "O": "Test Organization",
                "OU": "Test Unit",
                "C": "TR",
                "ST": "Istanbul",
                "L": "Kadikoy"
            },
            key_type="RSA-2048",
            validity_days=365,
            san_list=[
                {"type": "DNS", "value": "test.example.com"},
                {"type": "DNS", "value": "www.test.example.com"},
                {"type": "IP", "value": "192.168.1.1"}
            ]
        )
        return key_pem, cert_pem

    def test_analyze_certificate(self, sample_cert):
        """Test certificate analysis."""
        key_pem, cert_pem = sample_cert

        info = CertificateAnalyzer.analyze_certificate(cert_pem.encode())

        assert info is not None
        assert info["subject"]["CN"] == "test.example.com"
        assert info["subject"]["O"] == "Test Organization"
        assert info["issuer"]["CN"] == "test.example.com"  # Self-signed
        assert info["is_self_signed"] is True

    def test_analyze_validity(self, sample_cert):
        """Test validity period analysis."""
        key_pem, cert_pem = sample_cert

        info = CertificateAnalyzer.analyze_certificate(cert_pem.encode())

        assert "validity" in info
        assert "not_before" in info["validity"]
        assert "not_after" in info["validity"]
        assert info["validity"]["is_valid"] is True
        assert info["validity"]["days_remaining"] > 0

    def test_analyze_fingerprints(self, sample_cert):
        """Test fingerprint generation."""
        key_pem, cert_pem = sample_cert

        info = CertificateAnalyzer.analyze_certificate(cert_pem.encode())

        assert "fingerprints" in info
        assert "sha1" in info["fingerprints"]
        assert "sha256" in info["fingerprints"]
        assert "md5" in info["fingerprints"]
        assert len(info["fingerprints"]["sha256"]) == 64  # 256 bits = 64 hex chars

    def test_analyze_san(self, sample_cert):
        """Test SAN extraction."""
        key_pem, cert_pem = sample_cert

        info = CertificateAnalyzer.analyze_certificate(cert_pem.encode())

        assert "extensions" in info
        assert "subject_alternative_names" in info["extensions"]
        san_list = info["extensions"]["subject_alternative_names"]
        assert len(san_list) == 3

        dns_names = [s["value"] for s in san_list if s["type"] == "DNS"]
        assert "test.example.com" in dns_names
        assert "www.test.example.com" in dns_names

    def test_analyze_csr(self):
        """Test CSR analysis."""
        key_pem = CertificateGenerator.generate_private_key("RSA-2048")
        csr_pem = CertificateGenerator.generate_csr(
            key_pem.encode(),
            subject_info={"CN": "csr.example.com", "O": "CSR Org"},
            san_list=[{"type": "DNS", "value": "csr.example.com"}]
        )

        info = CertificateAnalyzer.analyze_csr(csr_pem.encode())

        assert info is not None
        assert info["subject"]["CN"] == "csr.example.com"
        assert info["is_signature_valid"] is True

    def test_verify_key_match(self, sample_cert):
        """Test key matching verification."""
        key_pem, cert_pem = sample_cert

        # Matching key
        is_match = CertificateAnalyzer.verify_key_match(
            cert_pem.encode(), key_pem.encode()
        )
        assert is_match is True

        # Non-matching key
        other_key = CertificateGenerator.generate_private_key("RSA-2048")
        is_match = CertificateAnalyzer.verify_key_match(
            cert_pem.encode(), other_key.encode()
        )
        assert is_match is False


class TestAnalyzerErrors:
    """Test error handling in analyzer."""

    def test_invalid_certificate_data(self):
        """Test error with invalid certificate data."""
        with pytest.raises(ValueError):
            CertificateAnalyzer.analyze_certificate(b"invalid data")

    def test_invalid_csr_data(self):
        """Test error with invalid CSR data."""
        with pytest.raises(ValueError):
            CertificateAnalyzer.analyze_csr(b"invalid data")


class TestCertificateChain:
    """Test certificate chain analysis."""

    def test_analyze_chain(self):
        """Test chain analysis with multiple certificates."""
        # Generate CA
        ca_key = CertificateGenerator.generate_private_key("RSA-2048")
        ca_cert = CertificateGenerator.generate_ca_certificate(
            ca_key.encode(),
            {"CN": "Test Root CA", "O": "Test CA Org"},
            validity_days=3650
        )

        # Generate end-entity cert
        ee_key, ee_cert = CertificateGenerator.generate_key_and_self_signed(
            {"CN": "test.example.com"},
            validity_days=365
        )

        # Combine into chain
        chain_pem = ee_cert + ca_cert

        chain_info = CertificateAnalyzer.analyze_chain(chain_pem.encode())

        assert len(chain_info) == 2
        assert chain_info[0]["subject"]["CN"] == "test.example.com"
        assert chain_info[1]["subject"]["CN"] == "Test Root CA"
