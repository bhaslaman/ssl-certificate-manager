"""SSL Certificate Comparison Service."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from datetime import datetime
from typing import Dict, List, Any, Optional
import hashlib

from .converter import CertificateConverter


class CertificateComparator:
    """Handles certificate comparison and matching operations."""

    @classmethod
    def compare_certificates(
        cls,
        cert1_data: bytes,
        cert2_data: bytes,
        cert1_password: str = "",
        cert2_password: str = ""
    ) -> Dict[str, Any]:
        """
        Compare two certificates and return detailed differences.

        Returns comparison results with matched and different fields.
        """
        cert1 = cls._load_certificate(cert1_data, cert1_password)
        cert2 = cls._load_certificate(cert2_data, cert2_password)

        if not cert1 or not cert2:
            raise ValueError("Unable to load one or both certificates.")

        # Extract info from both certificates
        info1 = cls._extract_cert_info(cert1)
        info2 = cls._extract_cert_info(cert2)

        # Compare fields
        comparison = {
            "are_identical": False,
            "certificate1": info1,
            "certificate2": info2,
            "differences": [],
            "matches": []
        }

        # Compare fingerprints first (quick identity check)
        if info1["fingerprint_sha256"] == info2["fingerprint_sha256"]:
            comparison["are_identical"] = True
            comparison["matches"].append({
                "field": "fingerprint",
                "description": "Certificates are identical (same SHA-256 fingerprint)"
            })
            return comparison

        # Compare individual fields
        fields_to_compare = [
            ("subject", "Subject"),
            ("issuer", "Issuer"),
            ("serial_number", "Serial Number"),
            ("not_before", "Valid From"),
            ("not_after", "Valid Until"),
            ("public_key_algorithm", "Public Key Algorithm"),
            ("public_key_size", "Public Key Size"),
            ("signature_algorithm", "Signature Algorithm"),
            ("is_ca", "Is CA"),
            ("san", "Subject Alternative Names")
        ]

        for field, display_name in fields_to_compare:
            val1 = info1.get(field)
            val2 = info2.get(field)

            if val1 == val2:
                comparison["matches"].append({
                    "field": field,
                    "display_name": display_name,
                    "value": val1
                })
            else:
                comparison["differences"].append({
                    "field": field,
                    "display_name": display_name,
                    "cert1_value": val1,
                    "cert2_value": val2
                })

        # Check public key match
        pub_key1 = cert1.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_key2 = cert2.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        comparison["same_public_key"] = pub_key1 == pub_key2

        if comparison["same_public_key"]:
            comparison["matches"].append({
                "field": "public_key",
                "display_name": "Public Key",
                "description": "Certificates have the same public key"
            })
        else:
            comparison["differences"].append({
                "field": "public_key",
                "display_name": "Public Key",
                "description": "Certificates have different public keys"
            })

        return comparison

    @classmethod
    def verify_key_matches_cert(
        cls,
        cert_data: bytes,
        key_data: bytes,
        cert_password: str = "",
        key_password: str = ""
    ) -> Dict[str, Any]:
        """
        Verify if a private key matches a certificate.

        Returns detailed matching information.
        """
        result = {
            "match": False,
            "certificate": {},
            "key": {},
            "error": None
        }

        # Load certificate
        try:
            cert = cls._load_certificate(cert_data, cert_password)
            if not cert:
                raise ValueError("Unable to load certificate")

            cert_info = cls._extract_cert_info(cert)
            result["certificate"] = {
                "subject": cert_info["subject"],
                "issuer": cert_info["issuer"],
                "not_after": cert_info["not_after"],
                "public_key_algorithm": cert_info["public_key_algorithm"],
                "public_key_size": cert_info["public_key_size"]
            }

            cert_public_key = cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except Exception as e:
            result["error"] = f"Certificate error: {str(e)}"
            return result

        # Load private key
        try:
            pwd = key_password.encode() if key_password else None

            # Try PEM format
            try:
                private_key = serialization.load_pem_private_key(
                    key_data, password=pwd, backend=default_backend()
                )
            except Exception:
                # Try DER format
                private_key = serialization.load_der_private_key(
                    key_data, password=pwd, backend=default_backend()
                )

            key_public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Get key info
            key_type = type(private_key).__name__.replace("_", " ")
            try:
                key_size = private_key.key_size
            except AttributeError:
                key_size = None

            result["key"] = {
                "algorithm": key_type,
                "key_size": key_size,
                "encrypted": pwd is not None
            }

        except Exception as e:
            result["error"] = f"Private key error: {str(e)}"
            return result

        # Compare public keys
        result["match"] = cert_public_key == key_public_key

        if result["match"]:
            result["message"] = "Private key matches the certificate"
        else:
            result["message"] = "Private key does NOT match the certificate"
            result["details"] = "The public key derived from the private key does not match the certificate's public key"

        return result

    @classmethod
    def verify_csr_matches_cert(
        cls,
        csr_data: bytes,
        cert_data: bytes,
        cert_password: str = ""
    ) -> Dict[str, Any]:
        """
        Verify if a CSR matches a certificate.

        Compares subject, public key, and other relevant fields.
        """
        result = {
            "match": False,
            "csr": {},
            "certificate": {},
            "differences": [],
            "matches": [],
            "error": None
        }

        # Load CSR
        try:
            try:
                csr = x509.load_pem_x509_csr(csr_data, default_backend())
            except Exception:
                csr = x509.load_der_x509_csr(csr_data, default_backend())

            csr_info = cls._extract_csr_info(csr)
            result["csr"] = csr_info

        except Exception as e:
            result["error"] = f"CSR error: {str(e)}"
            return result

        # Load certificate
        try:
            cert = cls._load_certificate(cert_data, cert_password)
            if not cert:
                raise ValueError("Unable to load certificate")

            cert_info = cls._extract_cert_info(cert)
            result["certificate"] = {
                "subject": cert_info["subject"],
                "issuer": cert_info["issuer"],
                "not_after": cert_info["not_after"],
                "san": cert_info.get("san", [])
            }

        except Exception as e:
            result["error"] = f"Certificate error: {str(e)}"
            return result

        # Compare subject
        if csr_info["subject"] == cert_info["subject"]:
            result["matches"].append({
                "field": "subject",
                "display_name": "Subject",
                "value": csr_info["subject"]
            })
        else:
            result["differences"].append({
                "field": "subject",
                "display_name": "Subject",
                "csr_value": csr_info["subject"],
                "cert_value": cert_info["subject"]
            })

        # Compare public keys
        csr_public_key = csr.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cert_public_key = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if csr_public_key == cert_public_key:
            result["matches"].append({
                "field": "public_key",
                "display_name": "Public Key",
                "description": "CSR and certificate have the same public key"
            })
            result["public_key_match"] = True
        else:
            result["differences"].append({
                "field": "public_key",
                "display_name": "Public Key",
                "description": "CSR and certificate have different public keys"
            })
            result["public_key_match"] = False

        # Compare SANs if present in both
        csr_sans = set(csr_info.get("san", []))
        cert_sans = set(cert_info.get("san", []))

        if csr_sans and cert_sans:
            if csr_sans == cert_sans:
                result["matches"].append({
                    "field": "san",
                    "display_name": "Subject Alternative Names",
                    "value": list(csr_sans)
                })
            else:
                result["differences"].append({
                    "field": "san",
                    "display_name": "Subject Alternative Names",
                    "csr_value": list(csr_sans),
                    "cert_value": list(cert_sans),
                    "only_in_csr": list(csr_sans - cert_sans),
                    "only_in_cert": list(cert_sans - csr_sans)
                })

        # Overall match determination
        # CSR matches cert if public key matches and subject matches
        result["match"] = (
            result.get("public_key_match", False) and
            len([d for d in result["differences"] if d["field"] == "subject"]) == 0
        )

        if result["match"]:
            result["message"] = "CSR matches the certificate"
        else:
            result["message"] = "CSR does NOT fully match the certificate"

        return result

    @classmethod
    def _load_certificate(cls, cert_data: bytes, password: str = "") -> Optional[x509.Certificate]:
        """Load certificate from various formats."""
        # Try PEM format
        try:
            return x509.load_pem_x509_certificate(cert_data, default_backend())
        except Exception:
            pass

        # Try DER format
        try:
            return x509.load_der_x509_certificate(cert_data, default_backend())
        except Exception:
            pass

        # Try PFX format
        try:
            cert_pem, _, _ = CertificateConverter.pfx_to_pem(cert_data, password)
            if cert_pem:
                return x509.load_pem_x509_certificate(
                    cert_pem.encode(), default_backend()
                )
        except Exception:
            pass

        return None

    @classmethod
    def _extract_cert_info(cls, cert: x509.Certificate) -> Dict[str, Any]:
        """Extract certificate information for comparison."""
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        info = {
            "subject": cls._name_to_dict(cert.subject),
            "issuer": cls._name_to_dict(cert.issuer),
            "serial_number": format(cert.serial_number, 'X'),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "fingerprint_sha256": hashlib.sha256(cert_der).hexdigest().upper(),
            "fingerprint_sha1": hashlib.sha1(cert_der).hexdigest().upper(),
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "is_ca": cls._is_ca(cert),
            "san": []
        }

        # Public key info
        public_key = cert.public_key()
        info["public_key_algorithm"] = type(public_key).__name__.replace("_", " ")
        try:
            info["public_key_size"] = public_key.key_size
        except AttributeError:
            info["public_key_size"] = None

        # SANs
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    info["san"].append(f"DNS:{name.value}")
                elif isinstance(name, x509.IPAddress):
                    info["san"].append(f"IP:{name.value}")
                elif isinstance(name, x509.RFC822Name):
                    info["san"].append(f"Email:{name.value}")
        except x509.ExtensionNotFound:
            pass

        return info

    @classmethod
    def _extract_csr_info(cls, csr: x509.CertificateSigningRequest) -> Dict[str, Any]:
        """Extract CSR information for comparison."""
        info = {
            "subject": cls._name_to_dict(csr.subject),
            "is_signature_valid": csr.is_signature_valid,
            "san": []
        }

        # Public key info
        public_key = csr.public_key()
        info["public_key_algorithm"] = type(public_key).__name__.replace("_", " ")
        try:
            info["public_key_size"] = public_key.key_size
        except AttributeError:
            info["public_key_size"] = None

        # SANs from CSR extensions
        try:
            for ext in csr.extensions:
                if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    for name in ext.value:
                        if isinstance(name, x509.DNSName):
                            info["san"].append(f"DNS:{name.value}")
                        elif isinstance(name, x509.IPAddress):
                            info["san"].append(f"IP:{name.value}")
        except Exception:
            pass

        return info

    @classmethod
    def _name_to_dict(cls, name: x509.Name) -> Dict[str, str]:
        """Convert X.509 Name to dictionary."""
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
            try:
                attrs = name.get_attributes_for_oid(oid)
                if attrs:
                    result[key] = attrs[0].value
            except Exception:
                pass

        return result

    @classmethod
    def _is_ca(cls, cert: x509.Certificate) -> bool:
        """Check if certificate is a CA."""
        try:
            bc_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            return bc_ext.value.ca
        except x509.ExtensionNotFound:
            return False
