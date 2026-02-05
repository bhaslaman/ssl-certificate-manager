"""SSL Certificate and key generation service."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
import ipaddress


class CertificateGenerator:
    """Handles certificate and key generation."""

    SUPPORTED_KEY_TYPES = ["RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384"]

    @staticmethod
    def generate_private_key(
        key_type: str = "RSA-2048",
        password: str = ""
    ) -> str:
        """
        Generate a new private key.

        Args:
            key_type: One of RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384
            password: Optional password to encrypt the key

        Returns:
            PEM encoded private key
        """
        if key_type == "RSA-2048":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
        elif key_type == "RSA-4096":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
        elif key_type == "ECDSA-P256":
            private_key = ec.generate_private_key(
                ec.SECP256R1(),
                backend=default_backend()
            )
        elif key_type == "ECDSA-P384":
            private_key = ec.generate_private_key(
                ec.SECP384R1(),
                backend=default_backend()
            )
        else:
            raise ValueError(f"Unsupported key type: {key_type}")

        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption
        ).decode()

    @staticmethod
    def _build_subject(subject_info: Dict[str, str]) -> x509.Name:
        """Build X.509 Name from dictionary."""
        name_attrs = []

        mappings = [
            ("CN", NameOID.COMMON_NAME),
            ("O", NameOID.ORGANIZATION_NAME),
            ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME),
            ("C", NameOID.COUNTRY_NAME),
            ("ST", NameOID.STATE_OR_PROVINCE_NAME),
            ("L", NameOID.LOCALITY_NAME),
            ("Email", NameOID.EMAIL_ADDRESS),
        ]

        for key, oid in mappings:
            value = subject_info.get(key)
            if value:
                name_attrs.append(x509.NameAttribute(oid, value))

        return x509.Name(name_attrs)

    @staticmethod
    def _build_san_extension(san_list: List[Dict[str, str]]) -> x509.SubjectAlternativeName:
        """Build Subject Alternative Name extension."""
        names = []
        for san in san_list:
            san_type = san.get("type", "DNS")
            value = san.get("value", "")

            if san_type == "DNS":
                names.append(x509.DNSName(value))
            elif san_type == "IP":
                names.append(x509.IPAddress(ipaddress.ip_address(value)))
            elif san_type == "Email":
                names.append(x509.RFC822Name(value))
            elif san_type == "URI":
                names.append(x509.UniformResourceIdentifier(value))

        return x509.SubjectAlternativeName(names)

    @classmethod
    def generate_csr(
        cls,
        private_key_pem: bytes,
        subject_info: Dict[str, str],
        san_list: List[Dict[str, str]] = None,
        key_password: str = ""
    ) -> str:
        """
        Generate a Certificate Signing Request.

        Args:
            private_key_pem: PEM encoded private key
            subject_info: Dictionary with CN, O, OU, C, ST, L, Email
            san_list: List of SANs with type and value
            key_password: Password for the private key if encrypted

        Returns:
            PEM encoded CSR
        """
        pwd = key_password.encode() if key_password else None
        private_key = serialization.load_pem_private_key(
            private_key_pem, password=pwd, backend=default_backend()
        )

        subject = cls._build_subject(subject_info)

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)

        # Add SAN if provided
        if san_list:
            san_ext = cls._build_san_extension(san_list)
            builder = builder.add_extension(san_ext, critical=False)

        csr = builder.sign(private_key, hashes.SHA256(), default_backend())

        return csr.public_bytes(serialization.Encoding.PEM).decode()

    @classmethod
    def generate_self_signed(
        cls,
        private_key_pem: bytes,
        subject_info: Dict[str, str],
        validity_days: int = 365,
        san_list: List[Dict[str, str]] = None,
        key_password: str = "",
        is_ca: bool = False
    ) -> str:
        """
        Generate a self-signed certificate.

        Args:
            private_key_pem: PEM encoded private key
            subject_info: Dictionary with CN, O, OU, C, ST, L, Email
            validity_days: Certificate validity in days
            san_list: List of SANs with type and value
            key_password: Password for the private key if encrypted
            is_ca: Whether this is a CA certificate

        Returns:
            PEM encoded certificate
        """
        pwd = key_password.encode() if key_password else None
        private_key = serialization.load_pem_private_key(
            private_key_pem, password=pwd, backend=default_backend()
        )

        subject = issuer = cls._build_subject(subject_info)

        now = datetime.now(timezone.utc)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + timedelta(days=validity_days))

        # Basic Constraints
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None),
            critical=True
        )

        # Key Usage
        if is_ca:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
        else:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )

        # Extended Key Usage for non-CA
        if not is_ca:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False
            )

        # Subject Alternative Names
        if san_list:
            san_ext = cls._build_san_extension(san_list)
            builder = builder.add_extension(san_ext, critical=False)

        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )

        # Authority Key Identifier (same as subject for self-signed)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False
        )

        certificate = builder.sign(private_key, hashes.SHA256(), default_backend())

        return certificate.public_bytes(serialization.Encoding.PEM).decode()

    @classmethod
    def generate_ca_certificate(
        cls,
        private_key_pem: bytes,
        subject_info: Dict[str, str],
        validity_days: int = 3650,
        key_password: str = "",
        path_length: int = 0
    ) -> str:
        """
        Generate a CA certificate.

        Args:
            private_key_pem: PEM encoded private key
            subject_info: Dictionary with CN, O, OU, C, ST, L, Email
            validity_days: Certificate validity in days (default 10 years)
            key_password: Password for the private key if encrypted
            path_length: Maximum number of intermediate CAs

        Returns:
            PEM encoded CA certificate
        """
        pwd = key_password.encode() if key_password else None
        private_key = serialization.load_pem_private_key(
            private_key_pem, password=pwd, backend=default_backend()
        )

        subject = issuer = cls._build_subject(subject_info)

        now = datetime.now(timezone.utc)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + timedelta(days=validity_days))

        # Basic Constraints - CA=True
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True
        )

        # Key Usage for CA
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )

        # Authority Key Identifier
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False
        )

        certificate = builder.sign(private_key, hashes.SHA256(), default_backend())

        return certificate.public_bytes(serialization.Encoding.PEM).decode()

    @classmethod
    def sign_csr_with_ca(
        cls,
        csr_pem: bytes,
        ca_cert_pem: bytes,
        ca_key_pem: bytes,
        validity_days: int = 365,
        ca_key_password: str = ""
    ) -> str:
        """
        Sign a CSR with a CA certificate.

        Args:
            csr_pem: PEM encoded CSR
            ca_cert_pem: PEM encoded CA certificate
            ca_key_pem: PEM encoded CA private key
            validity_days: Certificate validity in days
            ca_key_password: Password for CA private key

        Returns:
            PEM encoded signed certificate
        """
        csr = x509.load_pem_x509_csr(csr_pem, default_backend())
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())

        pwd = ca_key_password.encode() if ca_key_password else None
        ca_key = serialization.load_pem_private_key(
            ca_key_pem, password=pwd, backend=default_backend()
        )

        now = datetime.now(timezone.utc)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + timedelta(days=validity_days))

        # Copy extensions from CSR
        for ext in csr.extensions:
            builder = builder.add_extension(ext.value, ext.critical)

        # Basic Constraints - not a CA
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )

        # Key Usage
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        # Extended Key Usage
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False
        )

        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False
        )

        # Authority Key Identifier
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER
                ).value
            ),
            critical=False
        )

        certificate = builder.sign(ca_key, hashes.SHA256(), default_backend())

        return certificate.public_bytes(serialization.Encoding.PEM).decode()

    @classmethod
    def generate_key_and_self_signed(
        cls,
        subject_info: Dict[str, str],
        key_type: str = "RSA-2048",
        validity_days: int = 365,
        san_list: List[Dict[str, str]] = None,
        key_password: str = ""
    ) -> Tuple[str, str]:
        """
        Generate a private key and self-signed certificate in one operation.

        Returns:
            Tuple of (private_key_pem, certificate_pem)
        """
        key_pem = cls.generate_private_key(key_type, key_password)

        cert_pem = cls.generate_self_signed(
            key_pem.encode(),
            subject_info,
            validity_days,
            san_list,
            key_password
        )

        return key_pem, cert_pem
