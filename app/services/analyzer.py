"""SSL Certificate analysis service."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from datetime import datetime
from typing import Dict, List, Any, Optional
import hashlib

from .converter import CertificateConverter


class CertificateAnalyzer:
    """Handles certificate analysis and information extraction."""

    KEY_USAGE_NAMES = {
        "digital_signature": "Digital Signature",
        "content_commitment": "Non Repudiation",
        "key_encipherment": "Key Encipherment",
        "data_encipherment": "Data Encipherment",
        "key_agreement": "Key Agreement",
        "key_cert_sign": "Certificate Sign",
        "crl_sign": "CRL Sign",
        "encipher_only": "Encipher Only",
        "decipher_only": "Decipher Only",
    }

    EXTENDED_KEY_USAGE_NAMES = {
        "1.3.6.1.5.5.7.3.1": "Server Authentication",
        "1.3.6.1.5.5.7.3.2": "Client Authentication",
        "1.3.6.1.5.5.7.3.3": "Code Signing",
        "1.3.6.1.5.5.7.3.4": "Email Protection",
        "1.3.6.1.5.5.7.3.8": "Time Stamping",
        "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    }

    @staticmethod
    def _get_name_attribute(name: x509.Name, oid) -> Optional[str]:
        """Get a single attribute from X.509 Name."""
        try:
            attrs = name.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else None
        except Exception:
            return None

    @staticmethod
    def _parse_name(name: x509.Name) -> Dict[str, str]:
        """Parse X.509 Name into dictionary."""
        result = {}
        mappings = [
            (NameOID.COMMON_NAME, "CN"),
            (NameOID.ORGANIZATION_NAME, "O"),
            (NameOID.ORGANIZATIONAL_UNIT_NAME, "OU"),
            (NameOID.COUNTRY_NAME, "C"),
            (NameOID.STATE_OR_PROVINCE_NAME, "ST"),
            (NameOID.LOCALITY_NAME, "L"),
            (NameOID.EMAIL_ADDRESS, "Email"),
        ]

        for oid, key in mappings:
            value = CertificateAnalyzer._get_name_attribute(name, oid)
            if value:
                result[key] = value

        return result

    @classmethod
    def analyze_certificate(cls, cert_data: bytes, password: str = "") -> Dict[str, Any]:
        """
        Analyze a certificate and return detailed information.
        Supports PEM, DER, and PFX formats.
        """
        certificate = None

        # Try PEM format first
        try:
            certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
        except Exception:
            pass

        # Try DER format
        if not certificate:
            try:
                certificate = x509.load_der_x509_certificate(cert_data, default_backend())
            except Exception:
                pass

        # Try PFX format (with legacy encryption support)
        if not certificate:
            try:
                cert_pem, _, _ = CertificateConverter.pfx_to_pem(cert_data, password)
                if cert_pem:
                    certificate = x509.load_pem_x509_certificate(
                        cert_pem.encode(), default_backend()
                    )
            except Exception:
                pass

        if not certificate:
            raise ValueError("Unable to parse certificate. Unsupported format.")

        return cls._extract_cert_info(certificate)

    @classmethod
    def _extract_cert_info(cls, certificate: x509.Certificate) -> Dict[str, Any]:
        """Extract all information from a certificate."""
        cert_der = certificate.public_bytes(serialization.Encoding.DER)

        info = {
            "subject": cls._parse_name(certificate.subject),
            "issuer": cls._parse_name(certificate.issuer),
            "serial_number": format(certificate.serial_number, 'X'),
            "version": certificate.version.name,
            "validity": {
                "not_before": certificate.not_valid_before_utc.isoformat(),
                "not_after": certificate.not_valid_after_utc.isoformat(),
                "is_valid": (
                    certificate.not_valid_before_utc <= datetime.utcnow().replace(tzinfo=certificate.not_valid_before_utc.tzinfo)
                    <= certificate.not_valid_after_utc
                ),
                "days_remaining": (
                    certificate.not_valid_after_utc - datetime.utcnow().replace(tzinfo=certificate.not_valid_after_utc.tzinfo)
                ).days,
            },
            "fingerprints": {
                "sha1": hashlib.sha1(cert_der).hexdigest().upper(),
                "sha256": hashlib.sha256(cert_der).hexdigest().upper(),
                "md5": hashlib.md5(cert_der).hexdigest().upper(),
            },
            "public_key": cls._get_public_key_info(certificate),
            "signature_algorithm": certificate.signature_algorithm_oid._name,
            "is_self_signed": certificate.subject == certificate.issuer,
            "extensions": {},
        }

        # Extract extensions
        info["extensions"] = cls._extract_extensions(certificate)

        return info

    @classmethod
    def _get_public_key_info(cls, certificate: x509.Certificate) -> Dict[str, Any]:
        """Extract public key information."""
        public_key = certificate.public_key()
        key_info = {
            "algorithm": type(public_key).__name__.replace("_", " "),
        }

        try:
            key_info["key_size"] = public_key.key_size
        except AttributeError:
            pass

        return key_info

    @classmethod
    def _extract_extensions(cls, certificate: x509.Certificate) -> Dict[str, Any]:
        """Extract certificate extensions."""
        extensions = {}

        # Subject Alternative Names
        try:
            san_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_list = []
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_list.append({"type": "DNS", "value": name.value})
                elif isinstance(name, x509.IPAddress):
                    san_list.append({"type": "IP", "value": str(name.value)})
                elif isinstance(name, x509.RFC822Name):
                    san_list.append({"type": "Email", "value": name.value})
                elif isinstance(name, x509.UniformResourceIdentifier):
                    san_list.append({"type": "URI", "value": name.value})
            extensions["subject_alternative_names"] = san_list
        except x509.ExtensionNotFound:
            pass

        # Key Usage
        try:
            ku_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            )
            key_usages = []
            for attr, name in cls.KEY_USAGE_NAMES.items():
                try:
                    if getattr(ku_ext.value, attr):
                        key_usages.append(name)
                except ValueError:
                    pass
            extensions["key_usage"] = {
                "usages": key_usages,
                "critical": ku_ext.critical,
            }
        except x509.ExtensionNotFound:
            pass

        # Extended Key Usage
        try:
            eku_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )
            eku_list = []
            for usage in eku_ext.value:
                oid_str = usage.dotted_string
                name = cls.EXTENDED_KEY_USAGE_NAMES.get(oid_str, oid_str)
                eku_list.append(name)
            extensions["extended_key_usage"] = {
                "usages": eku_list,
                "critical": eku_ext.critical,
            }
        except x509.ExtensionNotFound:
            pass

        # Basic Constraints
        try:
            bc_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            extensions["basic_constraints"] = {
                "ca": bc_ext.value.ca,
                "path_length": bc_ext.value.path_length,
                "critical": bc_ext.critical,
            }
        except x509.ExtensionNotFound:
            pass

        # Authority Key Identifier
        try:
            aki_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER
            )
            if aki_ext.value.key_identifier:
                extensions["authority_key_identifier"] = (
                    aki_ext.value.key_identifier.hex().upper()
                )
        except x509.ExtensionNotFound:
            pass

        # Subject Key Identifier
        try:
            ski_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_KEY_IDENTIFIER
            )
            extensions["subject_key_identifier"] = ski_ext.value.digest.hex().upper()
        except x509.ExtensionNotFound:
            pass

        return extensions

    @classmethod
    def analyze_csr(cls, csr_data: bytes) -> Dict[str, Any]:
        """Analyze a Certificate Signing Request."""
        csr = None

        # Try PEM format
        try:
            csr = x509.load_pem_x509_csr(csr_data, default_backend())
        except Exception:
            pass

        # Try DER format
        if not csr:
            try:
                csr = x509.load_der_x509_csr(csr_data, default_backend())
            except Exception:
                pass

        if not csr:
            raise ValueError("Unable to parse CSR. Unsupported format.")

        info = {
            "subject": cls._parse_name(csr.subject),
            "is_signature_valid": csr.is_signature_valid,
            "public_key": {
                "algorithm": type(csr.public_key()).__name__.replace("_", " "),
            },
            "signature_algorithm": csr.signature_algorithm_oid._name,
            "extensions": {},
        }

        try:
            info["public_key"]["key_size"] = csr.public_key().key_size
        except AttributeError:
            pass

        # Extract CSR extensions
        try:
            for ext in csr.extensions:
                if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    san_list = []
                    for name in ext.value:
                        if isinstance(name, x509.DNSName):
                            san_list.append({"type": "DNS", "value": name.value})
                        elif isinstance(name, x509.IPAddress):
                            san_list.append({"type": "IP", "value": str(name.value)})
                    info["extensions"]["subject_alternative_names"] = san_list
        except Exception:
            pass

        return info

    @classmethod
    def analyze_chain(cls, chain_data: bytes, password: str = "") -> List[Dict[str, Any]]:
        """Analyze a certificate chain."""
        certificates = []

        # Try to split PEM certificates
        if b"-----BEGIN CERTIFICATE-----" in chain_data:
            pem_certs = chain_data.decode().split("-----END CERTIFICATE-----")
            for pem in pem_certs:
                pem = pem.strip()
                if pem:
                    pem += "\n-----END CERTIFICATE-----\n"
                    try:
                        cert = x509.load_pem_x509_certificate(
                            pem.encode(), default_backend()
                        )
                        certificates.append(cls._extract_cert_info(cert))
                    except Exception:
                        pass
        else:
            # Try PFX format (with legacy encryption support)
            try:
                cert_pem, _, chain_pem = CertificateConverter.pfx_to_pem(chain_data, password)
                if cert_pem:
                    main_cert = x509.load_pem_x509_certificate(
                        cert_pem.encode(), default_backend()
                    )
                    certificates.append(cls._extract_cert_info(main_cert))
                if chain_pem:
                    chain_certs = chain_pem.split("-----END CERTIFICATE-----")
                    for pem in chain_certs:
                        pem = pem.strip()
                        if pem:
                            pem += "\n-----END CERTIFICATE-----\n"
                            cert = x509.load_pem_x509_certificate(
                                pem.encode(), default_backend()
                            )
                            certificates.append(cls._extract_cert_info(cert))
            except Exception:
                pass

        if not certificates:
            raise ValueError("Unable to parse certificate chain.")

        return certificates

    @classmethod
    def verify_key_match(cls, cert_data: bytes, key_data: bytes, key_password: str = "") -> bool:
        """Verify if a private key matches a certificate."""
        # Load certificate
        try:
            certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
        except Exception:
            certificate = x509.load_der_x509_certificate(cert_data, default_backend())

        # Load private key
        pwd = key_password.encode() if key_password else None
        try:
            private_key = serialization.load_pem_private_key(
                key_data, password=pwd, backend=default_backend()
            )
        except Exception:
            private_key = serialization.load_der_private_key(
                key_data, password=pwd, backend=default_backend()
            )

        # Compare public keys
        cert_public_key = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return cert_public_key == key_public_key
