"""JKS (Java KeyStore) conversion service."""

import subprocess
import tempfile
import os
from typing import List, Dict, Optional
from pathlib import Path


class JKSConverter:
    """Handles JKS (Java KeyStore) format conversions using keytool."""

    @staticmethod
    def _run_keytool(args: List[str], input_data: bytes = None) -> subprocess.CompletedProcess:
        """Run keytool command with given arguments."""
        cmd = ["keytool"] + args
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=False
        )
        return result

    @staticmethod
    def pfx_to_jks(
        pfx_data: bytes,
        pfx_password: str = "",
        jks_password: str = "",
        alias: str = "certificate"
    ) -> bytes:
        """
        Convert PFX/P12 to JKS format.

        Args:
            pfx_data: PFX file bytes
            pfx_password: PFX password
            jks_password: Password for the output JKS
            alias: Alias for the entry in JKS

        Returns:
            JKS file bytes
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            pfx_path = Path(tmpdir) / "input.pfx"
            jks_path = Path(tmpdir) / "output.jks"

            # Write PFX file
            pfx_path.write_bytes(pfx_data)

            # Convert using keytool
            src_pass = pfx_password if pfx_password else "changeit"
            dest_pass = jks_password if jks_password else "changeit"

            result = subprocess.run([
                "keytool",
                "-importkeystore",
                "-srckeystore", str(pfx_path),
                "-srcstoretype", "PKCS12",
                "-srcstorepass", src_pass,
                "-destkeystore", str(jks_path),
                "-deststoretype", "JKS",
                "-deststorepass", dest_pass,
                "-srcalias", alias if alias else "",
                "-destalias", alias if alias else "",
                "-noprompt"
            ], capture_output=True, text=True)

            # If alias-specific import fails, try importing all entries
            if result.returncode != 0:
                result = subprocess.run([
                    "keytool",
                    "-importkeystore",
                    "-srckeystore", str(pfx_path),
                    "-srcstoretype", "PKCS12",
                    "-srcstorepass", src_pass,
                    "-destkeystore", str(jks_path),
                    "-deststoretype", "JKS",
                    "-deststorepass", dest_pass,
                    "-noprompt"
                ], capture_output=True, text=True)

            if result.returncode != 0:
                raise ValueError(f"Failed to convert PFX to JKS: {result.stderr}")

            return jks_path.read_bytes()

    @staticmethod
    def jks_to_pfx(
        jks_data: bytes,
        jks_password: str = "",
        pfx_password: str = "",
        alias: str = ""
    ) -> bytes:
        """
        Convert JKS to PFX/P12 format.

        Args:
            jks_data: JKS file bytes
            jks_password: JKS password
            pfx_password: Password for the output PFX
            alias: Alias of the entry to export (optional, exports all if empty)

        Returns:
            PFX file bytes
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            jks_path = Path(tmpdir) / "input.jks"
            pfx_path = Path(tmpdir) / "output.pfx"

            # Write JKS file
            jks_path.write_bytes(jks_data)

            src_pass = jks_password if jks_password else "changeit"
            dest_pass = pfx_password if pfx_password else "changeit"

            cmd = [
                "keytool",
                "-importkeystore",
                "-srckeystore", str(jks_path),
                "-srcstoretype", "JKS",
                "-srcstorepass", src_pass,
                "-destkeystore", str(pfx_path),
                "-deststoretype", "PKCS12",
                "-deststorepass", dest_pass,
                "-noprompt"
            ]

            if alias:
                cmd.extend(["-srcalias", alias])

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                raise ValueError(f"Failed to convert JKS to PFX: {result.stderr}")

            return pfx_path.read_bytes()

    @staticmethod
    def pem_to_jks(
        cert_pem: bytes,
        key_pem: bytes,
        jks_password: str = "",
        alias: str = "certificate",
        chain_pem: bytes = None
    ) -> bytes:
        """
        Convert PEM certificate and key to JKS format.

        Args:
            cert_pem: Certificate PEM bytes
            key_pem: Private key PEM bytes
            jks_password: Password for the output JKS
            alias: Alias for the entry
            chain_pem: Optional certificate chain PEM

        Returns:
            JKS file bytes
        """
        # First convert PEM to PKCS12, then PKCS12 to JKS
        from .converter import CertificateConverter

        pfx_password = jks_password if jks_password else "changeit"

        # Convert PEM to PFX
        pfx_data = CertificateConverter.pem_to_pfx(
            cert_pem, key_pem, pfx_password, chain_pem, alias
        )

        # Convert PFX to JKS
        return JKSConverter.pfx_to_jks(pfx_data, pfx_password, jks_password, alias)

    @staticmethod
    def import_cert_to_jks(
        cert_pem: bytes,
        jks_password: str = "",
        alias: str = "certificate"
    ) -> bytes:
        """
        Import a trusted certificate (without private key) to JKS.

        Args:
            cert_pem: Certificate PEM bytes
            jks_password: Password for the output JKS
            alias: Alias for the trusted certificate

        Returns:
            JKS file bytes
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "cert.pem"
            jks_path = Path(tmpdir) / "output.jks"

            cert_path.write_bytes(cert_pem)
            jks_pass = jks_password if jks_password else "changeit"

            result = subprocess.run([
                "keytool",
                "-importcert",
                "-file", str(cert_path),
                "-keystore", str(jks_path),
                "-storepass", jks_pass,
                "-alias", alias,
                "-noprompt"
            ], capture_output=True, text=True)

            if result.returncode != 0:
                raise ValueError(f"Failed to import certificate to JKS: {result.stderr}")

            return jks_path.read_bytes()

    @staticmethod
    def list_aliases(jks_data: bytes, jks_password: str = "") -> List[Dict]:
        """
        List all aliases in a JKS keystore.

        Args:
            jks_data: JKS file bytes
            jks_password: JKS password

        Returns:
            List of dicts with alias info (alias, type, creation_date)
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            jks_path = Path(tmpdir) / "input.jks"
            jks_path.write_bytes(jks_data)

            jks_pass = jks_password if jks_password else "changeit"

            result = subprocess.run([
                "keytool",
                "-list",
                "-keystore", str(jks_path),
                "-storepass", jks_pass
            ], capture_output=True, text=True)

            if result.returncode != 0:
                raise ValueError(f"Failed to list JKS aliases: {result.stderr}")

            # Parse output
            aliases = []
            lines = result.stdout.split('\n')
            for line in lines:
                line = line.strip()
                if ',' in line and ('PrivateKeyEntry' in line or 'trustedCertEntry' in line):
                    parts = line.split(',')
                    if len(parts) >= 2:
                        alias_part = parts[0].strip()
                        date_part = parts[1].strip() if len(parts) > 1 else ""
                        entry_type = "PrivateKeyEntry" if "PrivateKeyEntry" in line else "trustedCertEntry"
                        aliases.append({
                            "alias": alias_part,
                            "type": entry_type,
                            "creation_date": date_part
                        })

            return aliases

    @staticmethod
    def get_certificate_info(jks_data: bytes, jks_password: str = "", alias: str = "") -> str:
        """
        Get detailed certificate information from JKS.

        Args:
            jks_data: JKS file bytes
            jks_password: JKS password
            alias: Specific alias to get info for (optional)

        Returns:
            Certificate details as string
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            jks_path = Path(tmpdir) / "input.jks"
            jks_path.write_bytes(jks_data)

            jks_pass = jks_password if jks_password else "changeit"

            cmd = [
                "keytool",
                "-list",
                "-v",
                "-keystore", str(jks_path),
                "-storepass", jks_pass
            ]

            if alias:
                cmd.extend(["-alias", alias])

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                raise ValueError(f"Failed to get JKS info: {result.stderr}")

            return result.stdout
