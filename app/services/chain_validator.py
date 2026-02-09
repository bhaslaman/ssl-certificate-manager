"""SSL Certificate Chain Validation Service."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import hashlib

from .converter import CertificateConverter


class ChainValidator:
    """Handles certificate chain validation and verification."""

    @classmethod
    def validate_chain(cls, chain_data: bytes, password: str = "") -> Dict[str, Any]:
        """
        Validate a certificate chain completely.

        Returns comprehensive validation results including:
        - Chain completeness
        - Signature validity
        - Chain order
        - Missing intermediates
        - Root trust status
        """
        certificates = cls._load_certificates(chain_data, password)

        if not certificates:
            raise ValueError("Unable to parse certificate chain.")

        result = {
            "certificate_count": len(certificates),
            "chain_complete": False,
            "chain_order_valid": False,
            "all_signatures_valid": False,
            "root_is_self_signed": False,
            "certificates": [],
            "issues": [],
            "warnings": []
        }

        # Extract certificate info
        for i, cert in enumerate(certificates):
            cert_info = cls._extract_basic_info(cert, i)
            result["certificates"].append(cert_info)

        # Check chain order
        order_result = cls.check_chain_order(certificates)
        result["chain_order_valid"] = order_result["is_valid"]
        if not order_result["is_valid"]:
            result["issues"].append(order_result["message"])
            # Try to reorder if needed
            if order_result.get("suggested_order"):
                certificates = [certificates[i] for i in order_result["suggested_order"]]

        # Verify signature chain
        signature_results = cls.verify_signature_chain(certificates)
        result["signature_verification"] = signature_results
        result["all_signatures_valid"] = all(s["valid"] for s in signature_results)

        if not result["all_signatures_valid"]:
            for sig in signature_results:
                if not sig["valid"]:
                    result["issues"].append(f"Signature verification failed: {sig['subject']} signed by {sig['issuer']}")

        # Check for missing intermediates
        missing = cls.detect_missing_intermediates(certificates)
        if missing:
            result["missing_intermediates"] = missing
            result["issues"].append(f"Missing intermediate certificates: {', '.join(missing)}")
        else:
            result["missing_intermediates"] = []

        # Check if chain ends with self-signed (root)
        if certificates:
            last_cert = certificates[-1]
            result["root_is_self_signed"] = last_cert.subject == last_cert.issuer

        # Check root trust
        if result["root_is_self_signed"]:
            trust_result = cls.check_root_trust(certificates[-1])
            result["root_trust"] = trust_result
            if not trust_result["trusted"]:
                result["warnings"].append("Root certificate is not in the system trust store")

        # Determine if chain is complete
        result["chain_complete"] = (
            result["chain_order_valid"] and
            result["all_signatures_valid"] and
            len(result.get("missing_intermediates", [])) == 0 and
            result["root_is_self_signed"]
        )

        # Check validity dates
        now = datetime.utcnow()
        for i, cert in enumerate(certificates):
            not_before = cert.not_valid_before_utc.replace(tzinfo=None)
            not_after = cert.not_valid_after_utc.replace(tzinfo=None)

            if now < not_before:
                result["warnings"].append(f"Certificate {i+1} is not yet valid")
            elif now > not_after:
                result["issues"].append(f"Certificate {i+1} has expired")

        return result

    @classmethod
    def verify_signature_chain(cls, certificates: List[x509.Certificate]) -> List[Dict]:
        """
        Verify the signature chain between certificates.

        Each certificate should be signed by the next certificate in the chain.
        """
        results = []

        for i in range(len(certificates) - 1):
            cert = certificates[i]
            issuer_cert = certificates[i + 1]

            result = {
                "index": i,
                "subject": cls._get_cn(cert.subject),
                "issuer": cls._get_cn(cert.issuer),
                "expected_issuer": cls._get_cn(issuer_cert.subject),
                "valid": False,
                "error": None
            }

            # Check if issuer matches
            if cert.issuer != issuer_cert.subject:
                result["error"] = "Issuer name mismatch"
                results.append(result)
                continue

            # Verify signature
            try:
                issuer_public_key = issuer_cert.public_key()

                if isinstance(issuer_public_key, rsa.RSAPublicKey):
                    issuer_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm
                    )
                elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                    issuer_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        ec.ECDSA(cert.signature_hash_algorithm)
                    )
                else:
                    result["error"] = f"Unsupported key type: {type(issuer_public_key)}"
                    results.append(result)
                    continue

                result["valid"] = True
            except Exception as e:
                result["error"] = str(e)

            results.append(result)

        # Check if last certificate is self-signed
        if certificates:
            last_cert = certificates[-1]
            is_self_signed = last_cert.subject == last_cert.issuer

            result = {
                "index": len(certificates) - 1,
                "subject": cls._get_cn(last_cert.subject),
                "issuer": cls._get_cn(last_cert.issuer),
                "is_root": is_self_signed,
                "valid": True,
                "error": None
            }

            if is_self_signed:
                # Verify self-signature
                try:
                    public_key = last_cert.public_key()

                    if isinstance(public_key, rsa.RSAPublicKey):
                        public_key.verify(
                            last_cert.signature,
                            last_cert.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            last_cert.signature_hash_algorithm
                        )
                    elif isinstance(public_key, ec.EllipticCurvePublicKey):
                        public_key.verify(
                            last_cert.signature,
                            last_cert.tbs_certificate_bytes,
                            ec.ECDSA(last_cert.signature_hash_algorithm)
                        )

                    result["valid"] = True
                except Exception as e:
                    result["valid"] = False
                    result["error"] = str(e)

            results.append(result)

        return results

    @classmethod
    def check_chain_order(cls, certificates: List[x509.Certificate]) -> Dict:
        """
        Check if certificates are in the correct order (leaf to root).

        Returns order validation result with suggested reordering if needed.
        """
        if len(certificates) <= 1:
            return {
                "is_valid": True,
                "message": "Single certificate, no chain order to verify"
            }

        # Build a map of subject -> certificate
        subject_map = {}
        for i, cert in enumerate(certificates):
            subject_key = cert.subject.rfc4514_string()
            subject_map[subject_key] = (i, cert)

        # Check current order
        order_issues = []
        for i in range(len(certificates) - 1):
            cert = certificates[i]
            issuer_key = cert.issuer.rfc4514_string()

            if issuer_key in subject_map:
                expected_next_index = subject_map[issuer_key][0]
                if expected_next_index != i + 1:
                    order_issues.append(f"Certificate {i} issuer found at index {expected_next_index}, expected {i+1}")

        if not order_issues:
            return {
                "is_valid": True,
                "message": "Chain is in correct order (leaf to root)"
            }

        # Try to determine correct order
        suggested_order = cls._suggest_chain_order(certificates)

        return {
            "is_valid": False,
            "message": "Chain is not in correct order",
            "issues": order_issues,
            "suggested_order": suggested_order
        }

    @classmethod
    def _suggest_chain_order(cls, certificates: List[x509.Certificate]) -> List[int]:
        """Suggest the correct order for certificates."""
        if not certificates:
            return []

        # Build issuer -> subject relationships
        subject_to_idx = {}
        issuer_to_idx = {}

        for i, cert in enumerate(certificates):
            subject_key = cert.subject.rfc4514_string()
            issuer_key = cert.issuer.rfc4514_string()
            subject_to_idx[subject_key] = i
            issuer_to_idx.setdefault(issuer_key, []).append(i)

        # Find leaf certificate (one that is not an issuer of any other)
        all_issuers = set()
        for cert in certificates:
            all_issuers.add(cert.issuer.rfc4514_string())

        leaf_idx = None
        for i, cert in enumerate(certificates):
            subject_key = cert.subject.rfc4514_string()
            if subject_key not in all_issuers or cert.subject == cert.issuer:
                # This is a potential leaf (not issuing any other cert)
                # But skip self-signed (root)
                if cert.subject != cert.issuer:
                    leaf_idx = i
                    break

        if leaf_idx is None:
            # If no clear leaf, use the first non-self-signed
            for i, cert in enumerate(certificates):
                if cert.subject != cert.issuer:
                    leaf_idx = i
                    break

        if leaf_idx is None:
            leaf_idx = 0

        # Build chain from leaf
        ordered = [leaf_idx]
        visited = {leaf_idx}
        current = certificates[leaf_idx]

        while len(ordered) < len(certificates):
            issuer_key = current.issuer.rfc4514_string()

            if issuer_key in subject_to_idx:
                next_idx = subject_to_idx[issuer_key]
                if next_idx not in visited:
                    ordered.append(next_idx)
                    visited.add(next_idx)
                    current = certificates[next_idx]
                    continue

            # If we can't find the next certificate, add remaining ones
            for i in range(len(certificates)):
                if i not in visited:
                    ordered.append(i)
                    visited.add(i)
            break

        return ordered

    @classmethod
    def detect_missing_intermediates(cls, certificates: List[x509.Certificate]) -> List[str]:
        """
        Detect missing intermediate certificates in the chain.

        Returns list of missing certificate descriptions.
        """
        missing = []

        for i, cert in enumerate(certificates[:-1] if len(certificates) > 1 else certificates):
            # Check if this certificate's issuer is in the chain
            issuer_found = False

            for other_cert in certificates:
                if cert.issuer == other_cert.subject:
                    issuer_found = True
                    break

            if not issuer_found and cert.subject != cert.issuer:
                # Try to get AIA extension for issuer location
                issuer_info = cls._get_cn(cert.issuer)

                try:
                    aia_ext = cert.extensions.get_extension_for_oid(
                        ExtensionOID.AUTHORITY_INFORMATION_ACCESS
                    )
                    for access_description in aia_ext.value:
                        if access_description.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                            issuer_info += f" (URL: {access_description.access_location.value})"
                            break
                except x509.ExtensionNotFound:
                    pass

                missing.append(issuer_info)

        return missing

    @classmethod
    def check_root_trust(cls, root_cert: x509.Certificate, trust_store: str = "system") -> Dict:
        """
        Check if a root certificate is trusted.

        For now, this does a basic self-signature verification.
        Full trust store checking would require platform-specific implementations.
        """
        result = {
            "trusted": False,
            "is_self_signed": root_cert.subject == root_cert.issuer,
            "subject": cls._get_cn(root_cert.subject),
            "fingerprint_sha256": hashlib.sha256(
                root_cert.public_bytes(serialization.Encoding.DER)
            ).hexdigest().upper(),
            "check_method": trust_store
        }

        if not result["is_self_signed"]:
            result["error"] = "Certificate is not self-signed, not a root CA"
            return result

        # Verify self-signature
        try:
            public_key = root_cert.public_key()

            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    root_cert.signature,
                    root_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    root_cert.signature_hash_algorithm
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    root_cert.signature,
                    root_cert.tbs_certificate_bytes,
                    ec.ECDSA(root_cert.signature_hash_algorithm)
                )

            # Self-signature is valid
            # For system trust store check, we'd need platform-specific code
            # For now, we just mark as self-signed valid
            result["self_signature_valid"] = True
            result["trusted"] = True  # Basic trust - self-signed and valid

        except Exception as e:
            result["error"] = f"Signature verification failed: {str(e)}"
            result["self_signature_valid"] = False

        return result

    @classmethod
    def _load_certificates(cls, chain_data: bytes, password: str = "") -> List[x509.Certificate]:
        """Load certificates from various formats."""
        certificates = []

        # Try PEM format
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
                        certificates.append(cert)
                    except Exception:
                        pass
            return certificates

        # Try DER format (single certificate)
        try:
            cert = x509.load_der_x509_certificate(chain_data, default_backend())
            return [cert]
        except Exception:
            pass

        # Try PFX format
        try:
            cert_pem, _, chain_pem = CertificateConverter.pfx_to_pem(chain_data, password)
            if cert_pem:
                main_cert = x509.load_pem_x509_certificate(
                    cert_pem.encode(), default_backend()
                )
                certificates.append(main_cert)
            if chain_pem:
                chain_certs = chain_pem.split("-----END CERTIFICATE-----")
                for pem in chain_certs:
                    pem = pem.strip()
                    if pem:
                        pem += "\n-----END CERTIFICATE-----\n"
                        cert = x509.load_pem_x509_certificate(
                            pem.encode(), default_backend()
                        )
                        certificates.append(cert)
            return certificates
        except Exception:
            pass

        return certificates

    @classmethod
    def _extract_basic_info(cls, cert: x509.Certificate, index: int) -> Dict:
        """Extract basic certificate information."""
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        return {
            "index": index,
            "subject": cls._get_cn(cert.subject),
            "issuer": cls._get_cn(cert.issuer),
            "serial_number": format(cert.serial_number, 'X'),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "is_self_signed": cert.subject == cert.issuer,
            "is_ca": cls._is_ca(cert),
            "fingerprint_sha256": hashlib.sha256(cert_der).hexdigest().upper()
        }

    @classmethod
    def _get_cn(cls, name: x509.Name) -> str:
        """Get Common Name from X.509 Name."""
        try:
            cn_attrs = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn_attrs:
                return cn_attrs[0].value
        except Exception:
            pass
        return name.rfc4514_string()

    @classmethod
    def _is_ca(cls, cert: x509.Certificate) -> bool:
        """Check if certificate is a CA."""
        try:
            bc_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            return bc_ext.value.ca
        except x509.ExtensionNotFound:
            return False
