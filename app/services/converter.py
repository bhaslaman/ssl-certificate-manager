"""SSL Certificate format conversion service."""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto
from typing import Tuple, Optional
import tempfile
import subprocess
import os
import io
import zipfile


class CertificateConverter:
    """Handles all certificate format conversions."""

    @staticmethod
    def pfx_to_pem(
        pfx_data: bytes,
        password: str = "",
        key_format: str = "pkcs8"
    ) -> Tuple[str, str, str]:
        """
        Convert PFX/P12 to PEM format.
        Returns: (certificate_pem, private_key_pem, chain_pem)
        Supports legacy encryption algorithms (RC2, 3DES, etc.)

        Args:
            pfx_data: PFX file bytes
            password: PFX password
            key_format: "pkcs8" (default) or "traditional" for TraditionalOpenSSL
        """
        pwd = password.encode() if password else None

        # Determine key format
        private_format = (
            serialization.PrivateFormat.PKCS8
            if key_format == "pkcs8"
            else serialization.PrivateFormat.TraditionalOpenSSL
        )

        # Try modern cryptography library first
        try:
            private_key, certificate, chain = pkcs12.load_key_and_certificates(
                pfx_data, pwd, default_backend()
            )

            cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()

            key_pem = ""
            if private_key:
                key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=private_format,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode()

            chain_pem = ""
            if chain:
                for ca_cert in chain:
                    chain_pem += ca_cert.public_bytes(serialization.Encoding.PEM).decode()

            return cert_pem, key_pem, chain_pem

        except Exception as e:
            # Fallback to pyOpenSSL for legacy encryption (RC2, DES, etc.)
            try:
                return CertificateConverter._pfx_to_pem_legacy(pfx_data, password, key_format)
            except Exception:
                # Last resort: use openssl command with legacy provider
                return CertificateConverter._pfx_to_pem_openssl(pfx_data, password, key_format)

    @staticmethod
    def _pfx_to_pem_legacy(
        pfx_data: bytes,
        password: str = "",
        key_format: str = "pkcs8"
    ) -> Tuple[str, str, str]:
        """Fallback using pyOpenSSL for legacy encrypted PFX files."""
        p12 = crypto.load_pkcs12(pfx_data, password.encode() if password else b"")

        cert_pem = ""
        key_pem = ""
        chain_pem = ""

        # Extract certificate
        cert = p12.get_certificate()
        if cert:
            cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()

        # Extract private key
        pkey = p12.get_privatekey()
        if pkey:
            # pyOpenSSL outputs TraditionalOpenSSL format by default
            key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey).decode()

            # Convert to PKCS8 if requested
            if key_format == "pkcs8":
                private_key = serialization.load_pem_private_key(
                    key_pem.encode(), password=None, backend=default_backend()
                )
                key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode()

        # Extract CA chain
        ca_certs = p12.get_ca_certificates()
        if ca_certs:
            for ca in ca_certs:
                chain_pem += crypto.dump_certificate(crypto.FILETYPE_PEM, ca).decode()

        return cert_pem, key_pem, chain_pem

    @staticmethod
    def _pfx_to_pem_openssl(
        pfx_data: bytes,
        password: str = "",
        key_format: str = "pkcs8"
    ) -> Tuple[str, str, str]:
        """Last resort: use openssl CLI with legacy provider for very old PFX files."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pfx') as pfx_file:
            pfx_file.write(pfx_data)
            pfx_path = pfx_file.name

        try:
            pass_arg = f"-passin pass:{password}" if password else "-passin pass:"

            # Extract certificate
            cert_result = subprocess.run(
                f'openssl pkcs12 -in "{pfx_path}" -clcerts -nokeys {pass_arg} -legacy 2>/dev/null || '
                f'openssl pkcs12 -in "{pfx_path}" -clcerts -nokeys {pass_arg}',
                shell=True, capture_output=True, text=True
            )
            cert_pem = cert_result.stdout

            # Extract private key
            key_result = subprocess.run(
                f'openssl pkcs12 -in "{pfx_path}" -nocerts -nodes {pass_arg} -legacy 2>/dev/null || '
                f'openssl pkcs12 -in "{pfx_path}" -nocerts -nodes {pass_arg}',
                shell=True, capture_output=True, text=True
            )
            key_pem = key_result.stdout

            # Convert to PKCS8 if requested
            if key_pem and key_format == "pkcs8":
                try:
                    private_key = serialization.load_pem_private_key(
                        key_pem.encode(), password=None, backend=default_backend()
                    )
                    key_pem = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ).decode()
                except Exception:
                    pass  # Keep original format if conversion fails

            # Extract CA chain
            chain_result = subprocess.run(
                f'openssl pkcs12 -in "{pfx_path}" -cacerts -nokeys {pass_arg} -legacy 2>/dev/null || '
                f'openssl pkcs12 -in "{pfx_path}" -cacerts -nokeys {pass_arg}',
                shell=True, capture_output=True, text=True
            )
            chain_pem = chain_result.stdout

            if not cert_pem and not key_pem:
                raise ValueError("Failed to extract data from PFX file")

            return cert_pem, key_pem, chain_pem

        finally:
            os.unlink(pfx_path)

    @staticmethod
    def pfx_to_pem_split(
        pfx_data: bytes,
        password: str = "",
        key_format: str = "pkcs8",
        base_filename: str = "certificate"
    ) -> bytes:
        """
        Convert PFX/P12 to separate PEM files packaged in a ZIP.

        Args:
            pfx_data: PFX file bytes
            password: PFX password
            key_format: "pkcs8" (default) or "traditional" for TraditionalOpenSSL
            base_filename: Base name for output files

        Returns:
            ZIP file bytes containing cert.pem, key.pem, and optionally chain.pem
        """
        cert_pem, key_pem, chain_pem = CertificateConverter.pfx_to_pem(
            pfx_data, password, key_format
        )

        # Create ZIP in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            if cert_pem:
                zf.writestr(f"{base_filename}.pem", cert_pem)
            if key_pem:
                zf.writestr(f"{base_filename}.key", key_pem)
            if chain_pem:
                zf.writestr(f"{base_filename}-chain.pem", chain_pem)

        zip_buffer.seek(0)
        return zip_buffer.getvalue()

    @staticmethod
    def pem_to_pfx(
        cert_pem: bytes,
        key_pem: bytes,
        password: str = "",
        chain_pem: bytes = None,
        friendly_name: str = "certificate"
    ) -> bytes:
        """Convert PEM certificate and key to PFX/P12 format."""
        certificate = x509.load_pem_x509_certificate(cert_pem, default_backend())
        private_key = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())

        chain = None
        if chain_pem:
            chain = []
            pem_certs = chain_pem.decode().split("-----END CERTIFICATE-----")
            for pem in pem_certs:
                pem = pem.strip()
                if pem:
                    pem += "\n-----END CERTIFICATE-----\n"
                    chain.append(x509.load_pem_x509_certificate(pem.encode(), default_backend()))

        pwd = password.encode() if password else None
        encryption = (
            serialization.BestAvailableEncryption(pwd)
            if pwd
            else serialization.NoEncryption()
        )

        pfx_data = pkcs12.serialize_key_and_certificates(
            name=friendly_name.encode(),
            key=private_key,
            cert=certificate,
            cas=chain,
            encryption_algorithm=encryption
        )

        return pfx_data

    @staticmethod
    def pem_to_der(pem_data: bytes) -> bytes:
        """Convert PEM certificate to DER format."""
        certificate = x509.load_pem_x509_certificate(pem_data, default_backend())
        return certificate.public_bytes(serialization.Encoding.DER)

    @staticmethod
    def der_to_pem(der_data: bytes) -> str:
        """Convert DER certificate to PEM format."""
        certificate = x509.load_der_x509_certificate(der_data, default_backend())
        return certificate.public_bytes(serialization.Encoding.PEM).decode()

    @staticmethod
    def pem_to_p7b(pem_data: bytes, chain_pem: bytes = None) -> bytes:
        """Convert PEM certificate(s) to P7B/PKCS#7 format."""
        certs = []

        # Load main certificate
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        certs.append(cert)

        # Load chain certificates if provided
        if chain_pem:
            pem_certs = chain_pem.decode().split("-----END CERTIFICATE-----")
            for pem in pem_certs:
                pem = pem.strip()
                if pem:
                    pem += "\n-----END CERTIFICATE-----\n"
                    certs.append(x509.load_pem_x509_certificate(pem.encode(), default_backend()))

        # Use OpenSSL for P7B creation
        p7 = crypto.PKCS7()
        p7.set_type(crypto.PKCS7_SIGNED)

        for c in certs:
            openssl_cert = crypto.load_certificate(
                crypto.FILETYPE_PEM,
                c.public_bytes(serialization.Encoding.PEM)
            )
            p7.add_certificate(openssl_cert)

        return crypto.dump_pkcs7(crypto.FILETYPE_PEM, p7)

    @staticmethod
    def p7b_to_pem(p7b_data: bytes) -> str:
        """Convert P7B/PKCS#7 to PEM format."""
        p7 = crypto.load_pkcs7_data(crypto.FILETYPE_PEM, p7b_data)

        certs = []
        for i in range(p7.get_certificate_count()):
            cert = p7.get_certificate(i)
            certs.append(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode())

        return "\n".join(certs)

    @staticmethod
    def extract_private_key(
        pfx_data: bytes,
        password: str = "",
        new_password: str = "",
        key_format: str = "pkcs8"
    ) -> str:
        """
        Extract private key from PFX file. Supports legacy encryption.

        Args:
            pfx_data: PFX file bytes
            password: PFX password
            new_password: Optional password to encrypt the extracted key
            key_format: "pkcs8" (default) or "traditional" for TraditionalOpenSSL
        """
        # Use pfx_to_pem which handles legacy encryption
        _, key_pem, _ = CertificateConverter.pfx_to_pem(pfx_data, password, key_format)

        if not key_pem:
            raise ValueError("No private key found in PFX file")

        # Determine key format
        private_format = (
            serialization.PrivateFormat.PKCS8
            if key_format == "pkcs8"
            else serialization.PrivateFormat.TraditionalOpenSSL
        )

        # If new password requested, re-encrypt the key
        if new_password:
            private_key = serialization.load_pem_private_key(
                key_pem.encode(), password=None, backend=default_backend()
            )
            encryption = serialization.BestAvailableEncryption(new_password.encode())
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=private_format,
                encryption_algorithm=encryption
            ).decode()

        return key_pem

    @staticmethod
    def extract_certificate(pfx_data: bytes, password: str = "") -> str:
        """Extract certificate from PFX file. Supports legacy encryption."""
        # Use pfx_to_pem which handles legacy encryption
        cert_pem, _, _ = CertificateConverter.pfx_to_pem(pfx_data, password)

        if not cert_pem:
            raise ValueError("No certificate found in PFX file")

        return cert_pem

    @staticmethod
    def change_key_password(
        key_pem: bytes,
        old_password: str = "",
        new_password: str = ""
    ) -> str:
        """Change or remove password from private key."""
        old_pwd = old_password.encode() if old_password else None

        private_key = serialization.load_pem_private_key(
            key_pem, password=old_pwd, backend=default_backend()
        )

        if new_password:
            encryption = serialization.BestAvailableEncryption(new_password.encode())
        else:
            encryption = serialization.NoEncryption()

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption
        ).decode()

    @staticmethod
    def key_pem_to_der(key_pem: bytes, password: str = "") -> bytes:
        """Convert PEM private key to DER format."""
        pwd = password.encode() if password else None

        private_key = serialization.load_pem_private_key(
            key_pem, password=pwd, backend=default_backend()
        )

        return private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    @staticmethod
    def key_der_to_pem(key_der: bytes) -> str:
        """Convert DER private key to PEM format."""
        private_key = serialization.load_der_private_key(
            key_der, password=None, backend=default_backend()
        )

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
