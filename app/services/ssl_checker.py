"""SSL URL checker service."""

import ssl
import socket
import ipaddress
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class SSLChecker:
    """Check SSL certificates from URLs."""

    # Private IP ranges to block (SSRF prevention)
    PRIVATE_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),  # Link-local
        ipaddress.ip_network('::1/128'),  # IPv6 localhost
        ipaddress.ip_network('fc00::/7'),  # IPv6 private
        ipaddress.ip_network('fe80::/10'),  # IPv6 link-local
    ]

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is in private/reserved ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in SSLChecker.PRIVATE_RANGES:
                if ip_obj in network:
                    return True
            return False
        except ValueError:
            return True  # Invalid IP, block it

    @staticmethod
    def _resolve_hostname(hostname: str) -> List[str]:
        """Resolve hostname to IP addresses."""
        try:
            results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = list(set(result[4][0] for result in results))
            return ips
        except socket.gaierror:
            return []

    @staticmethod
    def check_url(
        hostname: str,
        port: int = 443,
        timeout: int = 10,
        check_dns: bool = False
    ) -> Dict:
        """
        Check SSL certificate of a URL.

        Args:
            hostname: The hostname to check
            port: The port to connect to (default: 443)
            timeout: Connection timeout in seconds
            check_dns: Whether to include DNS information

        Returns:
            Dictionary with certificate info, chain, validation status
        """
        # Clean hostname
        hostname = hostname.strip().lower()
        if hostname.startswith('https://'):
            hostname = hostname[8:]
        if hostname.startswith('http://'):
            hostname = hostname[7:]
        if '/' in hostname:
            hostname = hostname.split('/')[0]
        if ':' in hostname:
            parts = hostname.rsplit(':', 1)
            hostname = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        # Resolve hostname and check for private IPs (SSRF prevention)
        resolved_ips = SSLChecker._resolve_hostname(hostname)
        if not resolved_ips:
            raise ValueError(f"Could not resolve hostname: {hostname}")

        # Check all resolved IPs for private ranges
        for ip in resolved_ips:
            if SSLChecker._is_private_ip(ip):
                raise ValueError(f"Connection to private/internal IP addresses is not allowed")

        result = {
            "hostname": hostname,
            "port": port,
            "certificate": None,
            "chain": [],
            "validation": None,
            "dns_info": None
        }

        # Get certificate
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # We'll validate manually

        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate chain
                    der_cert = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())

                    # Parse certificate
                    result["certificate"] = SSLChecker._parse_certificate(cert, hostname)

                    # Try to get chain with verification
                    try:
                        chain_certs = SSLChecker._get_certificate_chain(hostname, port, timeout)
                        result["chain"] = chain_certs
                    except Exception:
                        pass

        except socket.timeout:
            raise ValueError(f"Connection timed out after {timeout} seconds")
        except socket.error as e:
            raise ValueError(f"Connection failed: {str(e)}")
        except ssl.SSLError as e:
            raise ValueError(f"SSL error: {str(e)}")

        # Validate certificate
        result["validation"] = SSLChecker._validate_certificate(hostname, port, timeout)

        # DNS info if requested
        if check_dns:
            result["dns_info"] = {
                "resolved_ips": resolved_ips,
                "hostname": hostname
            }

        return result

    @staticmethod
    def _parse_certificate(cert: x509.Certificate, hostname: str = "") -> Dict:
        """Parse certificate into readable format."""
        now = datetime.utcnow()
        not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after

        # Handle timezone-aware vs naive datetime comparison
        if not_before.tzinfo is not None:
            from datetime import timezone
            now = datetime.now(timezone.utc)

        days_remaining = (not_after - now).days
        is_valid = now >= not_before and now <= not_after

        # Extract subject
        subject = {}
        for attr in cert.subject:
            name = attr.oid._name
            subject[name] = attr.value

        # Extract issuer
        issuer = {}
        for attr in cert.issuer:
            name = attr.oid._name
            issuer[name] = attr.value

        # Check if self-signed
        is_self_signed = cert.subject == cert.issuer

        # Get SANs
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    sans.append({"type": "DNS", "value": name.value})
                elif isinstance(name, x509.IPAddress):
                    sans.append({"type": "IP", "value": str(name.value)})
        except x509.ExtensionNotFound:
            pass

        # Fingerprints
        fingerprints = {
            "sha256": cert.fingerprint(hashes.SHA256()).hex(':').upper(),
            "sha1": cert.fingerprint(hashes.SHA1()).hex(':').upper(),
            "md5": cert.fingerprint(hashes.MD5()).hex(':').upper()
        }

        # Public key info
        public_key = cert.public_key()
        key_info = {
            "algorithm": type(public_key).__name__.replace('_', ' ').replace('PublicKey', '').strip()
        }
        if hasattr(public_key, 'key_size'):
            key_info["key_size"] = public_key.key_size

        return {
            "subject": subject,
            "issuer": issuer,
            "validity": {
                "not_before": not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "not_after": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "days_remaining": days_remaining,
                "is_valid": is_valid
            },
            "serial_number": format(cert.serial_number, 'x').upper(),
            "fingerprints": fingerprints,
            "public_key": key_info,
            "sans": sans,
            "is_self_signed": is_self_signed,
            "version": cert.version.name
        }

    @staticmethod
    def _get_certificate_chain(hostname: str, port: int, timeout: int) -> List[Dict]:
        """Get the full certificate chain."""
        chain = []
        context = ssl.create_default_context()

        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get peer certificate chain if available
                    peer_cert = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(peer_cert, default_backend())

                    # Add end-entity certificate
                    chain.append({
                        "type": "end-entity",
                        "subject": SSLChecker._get_subject_cn(cert),
                        "issuer": SSLChecker._get_issuer_cn(cert)
                    })

        except Exception:
            pass

        return chain

    @staticmethod
    def _get_subject_cn(cert: x509.Certificate) -> str:
        """Get Common Name from subject."""
        try:
            for attr in cert.subject:
                if attr.oid._name == 'commonName':
                    return attr.value
        except Exception:
            pass
        return "Unknown"

    @staticmethod
    def _get_issuer_cn(cert: x509.Certificate) -> str:
        """Get Common Name from issuer."""
        try:
            for attr in cert.issuer:
                if attr.oid._name == 'commonName':
                    return attr.value
        except Exception:
            pass
        return "Unknown"

    @staticmethod
    def _validate_certificate(hostname: str, port: int, timeout: int) -> Dict:
        """Validate certificate trust chain and hostname."""
        result = {
            "trusted": False,
            "hostname_match": False,
            "errors": []
        }

        context = ssl.create_default_context()

        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result["trusted"] = True
                    result["hostname_match"] = True
        except ssl.SSLCertVerificationError as e:
            result["errors"].append(str(e))
            if "hostname" in str(e).lower():
                result["hostname_match"] = False
        except ssl.SSLError as e:
            result["errors"].append(str(e))
        except Exception as e:
            result["errors"].append(str(e))

        return result
