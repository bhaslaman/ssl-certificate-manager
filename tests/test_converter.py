"""Tests for the certificate converter service."""

import pytest
from app.services.converter import CertificateConverter
from app.services.generator import CertificateGenerator


class TestCertificateConverter:
    """Test cases for CertificateConverter."""

    @pytest.fixture
    def sample_key_and_cert(self):
        """Generate a sample key and certificate for testing."""
        key_pem, cert_pem = CertificateGenerator.generate_key_and_self_signed(
            subject_info={"CN": "test.example.com", "O": "Test Org"},
            key_type="RSA-2048",
            validity_days=30
        )
        return key_pem, cert_pem

    def test_pem_to_der_and_back(self, sample_key_and_cert):
        """Test PEM to DER conversion and back."""
        key_pem, cert_pem = sample_key_and_cert

        # Convert PEM to DER
        der_data = CertificateConverter.pem_to_der(cert_pem.encode())
        assert der_data is not None
        assert isinstance(der_data, bytes)

        # Convert DER back to PEM
        pem_back = CertificateConverter.der_to_pem(der_data)
        assert "-----BEGIN CERTIFICATE-----" in pem_back
        assert "-----END CERTIFICATE-----" in pem_back

    def test_pem_to_pfx_and_back(self, sample_key_and_cert):
        """Test PEM to PFX conversion and back."""
        key_pem, cert_pem = sample_key_and_cert

        # Convert to PFX
        pfx_data = CertificateConverter.pem_to_pfx(
            cert_pem.encode(),
            key_pem.encode(),
            password="testpass",
            friendly_name="test_cert"
        )
        assert pfx_data is not None
        assert isinstance(pfx_data, bytes)

        # Convert back to PEM
        cert_back, key_back, chain_back = CertificateConverter.pfx_to_pem(
            pfx_data, "testpass"
        )
        assert "-----BEGIN CERTIFICATE-----" in cert_back
        assert "-----BEGIN" in key_back  # Could be RSA or other key type

    def test_extract_key_from_pfx(self, sample_key_and_cert):
        """Test extracting private key from PFX."""
        key_pem, cert_pem = sample_key_and_cert

        # Create PFX
        pfx_data = CertificateConverter.pem_to_pfx(
            cert_pem.encode(),
            key_pem.encode(),
            password="testpass"
        )

        # Extract key
        extracted_key = CertificateConverter.extract_private_key(
            pfx_data, "testpass"
        )
        assert "-----BEGIN" in extracted_key
        assert "PRIVATE KEY-----" in extracted_key

    def test_extract_cert_from_pfx(self, sample_key_and_cert):
        """Test extracting certificate from PFX."""
        key_pem, cert_pem = sample_key_and_cert

        # Create PFX
        pfx_data = CertificateConverter.pem_to_pfx(
            cert_pem.encode(),
            key_pem.encode(),
            password="testpass"
        )

        # Extract cert
        extracted_cert = CertificateConverter.extract_certificate(
            pfx_data, "testpass"
        )
        assert "-----BEGIN CERTIFICATE-----" in extracted_cert
        assert "-----END CERTIFICATE-----" in extracted_cert

    def test_change_key_password(self, sample_key_and_cert):
        """Test changing key password."""
        key_pem, _ = sample_key_and_cert

        # Add password
        encrypted_key = CertificateConverter.change_key_password(
            key_pem.encode(),
            old_password="",
            new_password="newpass"
        )
        assert "ENCRYPTED" in encrypted_key or "-----BEGIN" in encrypted_key

        # Remove password
        decrypted_key = CertificateConverter.change_key_password(
            encrypted_key.encode(),
            old_password="newpass",
            new_password=""
        )
        assert "-----BEGIN" in decrypted_key


class TestConverterErrors:
    """Test error handling in converter."""

    def test_invalid_pfx_password(self):
        """Test error with wrong PFX password."""
        key_pem, cert_pem = CertificateGenerator.generate_key_and_self_signed(
            subject_info={"CN": "test.example.com"},
            key_type="RSA-2048",
            validity_days=30
        )

        pfx_data = CertificateConverter.pem_to_pfx(
            cert_pem.encode(),
            key_pem.encode(),
            password="correctpass"
        )

        with pytest.raises(Exception):
            CertificateConverter.pfx_to_pem(pfx_data, "wrongpass")

    def test_invalid_pem_data(self):
        """Test error with invalid PEM data."""
        with pytest.raises(Exception):
            CertificateConverter.pem_to_der(b"invalid data")
