"""ACME Client for Let's Encrypt Integration."""

import json
import base64
import hashlib
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import httpx

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from .acme_store import get_store


class ACMEClient:
    """
    ACME protocol client for Let's Encrypt certificate issuance.

    Supports HTTP-01 challenge for domain validation.
    """

    # Let's Encrypt directory URLs
    LETS_ENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
    LETS_ENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"

    def __init__(self, environment: str = "staging"):
        """
        Initialize the ACME client.

        Args:
            environment: 'staging' or 'production'
        """
        self.environment = environment
        self.directory_url = (
            self.LETS_ENCRYPT_PRODUCTION if environment == "production"
            else self.LETS_ENCRYPT_STAGING
        )
        self.directory = None
        self.nonce = None
        self.store = get_store()

    async def _get_directory(self) -> Dict:
        """Fetch the ACME directory."""
        if self.directory:
            return self.directory

        async with httpx.AsyncClient() as client:
            response = await client.get(self.directory_url)
            response.raise_for_status()
            self.directory = response.json()
            return self.directory

    async def _get_nonce(self) -> str:
        """Get a fresh nonce for signing requests."""
        if self.nonce:
            nonce = self.nonce
            self.nonce = None
            return nonce

        directory = await self._get_directory()
        async with httpx.AsyncClient() as client:
            response = await client.head(directory["newNonce"])
            return response.headers["Replay-Nonce"]

    def _update_nonce(self, response: httpx.Response) -> None:
        """Update nonce from response header."""
        if "Replay-Nonce" in response.headers:
            self.nonce = response.headers["Replay-Nonce"]

    def _generate_account_key(self) -> Tuple[rsa.RSAPrivateKey, str]:
        """Generate a new RSA key pair for the account."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        return private_key, private_key_pem

    def _get_jwk(self, private_key: rsa.RSAPrivateKey) -> Dict:
        """Get the JWK representation of the public key."""
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        # Convert to base64url
        def to_base64url(n: int, length: int) -> str:
            data = n.to_bytes(length, byteorder='big')
            return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

        return {
            "kty": "RSA",
            "n": to_base64url(public_numbers.n, 256),
            "e": to_base64url(public_numbers.e, 3)
        }

    def _get_thumbprint(self, jwk: Dict) -> str:
        """Calculate the JWK thumbprint."""
        # Canonical JSON
        jwk_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
        digest = hashlib.sha256(jwk_json.encode()).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()

    def _sign_request(
        self,
        private_key: rsa.RSAPrivateKey,
        url: str,
        payload: Optional[Dict],
        kid: str = None,
        nonce: str = None
    ) -> Dict:
        """Create a signed JWS request."""
        protected = {
            "alg": "RS256",
            "nonce": nonce,
            "url": url
        }

        if kid:
            protected["kid"] = kid
        else:
            protected["jwk"] = self._get_jwk(private_key)

        protected_b64 = base64.urlsafe_b64encode(
            json.dumps(protected).encode()
        ).rstrip(b'=').decode()

        if payload is None:
            payload_b64 = ""
        elif payload == "":
            payload_b64 = ""
        else:
            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).rstrip(b'=').decode()

        signing_input = f"{protected_b64}.{payload_b64}".encode()

        signature = private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

        return {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64
        }

    async def _post(
        self,
        url: str,
        payload: Optional[Dict],
        private_key: rsa.RSAPrivateKey,
        kid: str = None
    ) -> httpx.Response:
        """Make a signed POST request to the ACME server."""
        nonce = await self._get_nonce()
        body = self._sign_request(private_key, url, payload, kid, nonce)

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=body,
                headers={"Content-Type": "application/jose+json"}
            )
            self._update_nonce(response)
            return response

    async def register_account(self, email: str) -> Dict:
        """
        Register a new ACME account.

        Args:
            email: Contact email address

        Returns:
            Account information including account URL
        """
        # Check if account already exists
        existing = self.store.get_account_by_email(email, self.environment)
        if existing:
            return {
                "success": True,
                "message": "Account already exists",
                "account_id": existing["account_id"],
                "account_url": existing.get("account_url"),
                "email": email,
                "environment": self.environment
            }

        # Generate new key pair
        private_key, private_key_pem = self._generate_account_key()

        # Register with ACME server
        directory = await self._get_directory()

        payload = {
            "termsOfServiceAgreed": True,
            "contact": [f"mailto:{email}"]
        }

        response = await self._post(
            directory["newAccount"],
            payload,
            private_key
        )

        if response.status_code not in [200, 201]:
            error = response.json()
            raise Exception(f"Account registration failed: {error.get('detail', 'Unknown error')}")

        account_url = response.headers.get("Location")
        account_data = response.json()

        # Save account
        account_info = {
            "email": email,
            "environment": self.environment,
            "account_url": account_url,
            "private_key_pem": private_key_pem,
            "status": account_data.get("status", "valid"),
            "orders_url": account_data.get("orders")
        }

        account_id = self.store.save_account(account_info)

        return {
            "success": True,
            "message": "Account registered successfully",
            "account_id": account_id,
            "account_url": account_url,
            "email": email,
            "environment": self.environment
        }

    async def create_order(self, account_id: str, domains: List[str]) -> Dict:
        """
        Create a new certificate order.

        Args:
            account_id: ACME account ID
            domains: List of domain names

        Returns:
            Order information including order URL and authorizations
        """
        account = self.store.get_account(account_id)
        if not account:
            raise ValueError("Account not found")

        # Load private key
        private_key = serialization.load_pem_private_key(
            account["private_key_pem"].encode(),
            password=None,
            backend=default_backend()
        )

        directory = await self._get_directory()

        # Create order
        identifiers = [{"type": "dns", "value": domain} for domain in domains]
        payload = {"identifiers": identifiers}

        response = await self._post(
            directory["newOrder"],
            payload,
            private_key,
            kid=account["account_url"]
        )

        if response.status_code not in [200, 201]:
            error = response.json()
            raise Exception(f"Order creation failed: {error.get('detail', 'Unknown error')}")

        order_url = response.headers.get("Location")
        order_data = response.json()

        # Save order
        order_info = {
            "account_id": account_id,
            "order_url": order_url,
            "domains": domains,
            "status": order_data.get("status"),
            "expires": order_data.get("expires"),
            "authorizations": order_data.get("authorizations", []),
            "finalize_url": order_data.get("finalize")
        }

        order_id = self.store.save_order(order_info)

        return {
            "success": True,
            "order_id": order_id,
            "order_url": order_url,
            "domains": domains,
            "status": order_data.get("status"),
            "authorizations": order_data.get("authorizations", [])
        }

    async def get_http01_challenge(self, account_id: str, order_id: str) -> Dict:
        """
        Get HTTP-01 challenge information for all domains in an order.

        Returns challenge tokens and expected responses.
        """
        account = self.store.get_account(account_id)
        if not account:
            raise ValueError("Account not found")

        order = self.store.get_order(order_id)
        if not order:
            raise ValueError("Order not found")

        private_key = serialization.load_pem_private_key(
            account["private_key_pem"].encode(),
            password=None,
            backend=default_backend()
        )

        jwk = self._get_jwk(private_key)
        thumbprint = self._get_thumbprint(jwk)

        challenges = {}

        for authz_url in order.get("authorizations", []):
            # Fetch authorization
            response = await self._post(
                authz_url,
                "",  # POST-as-GET
                private_key,
                kid=account["account_url"]
            )

            if response.status_code != 200:
                continue

            authz_data = response.json()
            domain = authz_data.get("identifier", {}).get("value")

            # Find HTTP-01 challenge
            for challenge in authz_data.get("challenges", []):
                if challenge.get("type") == "http-01":
                    token = challenge.get("token")
                    key_authorization = f"{token}.{thumbprint}"

                    challenge_info = {
                        "domain": domain,
                        "type": "http-01",
                        "token": token,
                        "key_authorization": key_authorization,
                        "challenge_url": challenge.get("url"),
                        "status": challenge.get("status"),
                        "validation_url": f"http://{domain}/.well-known/acme-challenge/{token}",
                        "expected_content": key_authorization
                    }

                    challenges[domain] = challenge_info
                    self.store.save_challenge(order_id, domain, challenge_info)
                    break

        return {
            "success": True,
            "order_id": order_id,
            "challenges": challenges
        }

    async def verify_challenge(self, account_id: str, order_id: str, domain: str = None) -> Dict:
        """
        Trigger challenge verification for a domain.

        If domain is None, verifies all pending challenges.
        """
        account = self.store.get_account(account_id)
        if not account:
            raise ValueError("Account not found")

        order = self.store.get_order(order_id)
        if not order:
            raise ValueError("Order not found")

        private_key = serialization.load_pem_private_key(
            account["private_key_pem"].encode(),
            password=None,
            backend=default_backend()
        )

        challenges = order.get("challenges", {})
        if domain:
            challenges = {domain: challenges.get(domain)} if domain in challenges else {}

        results = {}

        for dom, challenge in challenges.items():
            if not challenge or challenge.get("status") == "valid":
                results[dom] = {"status": "already_valid"}
                continue

            # Respond to challenge
            response = await self._post(
                challenge["challenge_url"],
                {},  # Empty object to trigger validation
                private_key,
                kid=account["account_url"]
            )

            if response.status_code == 200:
                challenge_data = response.json()
                results[dom] = {
                    "status": challenge_data.get("status"),
                    "validated": challenge_data.get("validated")
                }

                # Update stored challenge
                self.store.save_challenge(order_id, dom, {
                    **challenge,
                    "status": challenge_data.get("status")
                })
            else:
                error = response.json()
                results[dom] = {
                    "status": "error",
                    "error": error.get("detail", "Unknown error")
                }

        return {
            "success": True,
            "order_id": order_id,
            "results": results
        }

    async def finalize_order(self, account_id: str, order_id: str, csr_pem: bytes = None) -> Dict:
        """
        Finalize the order and get the certificate.

        Args:
            account_id: Account ID
            order_id: Order ID
            csr_pem: Optional CSR in PEM format. If not provided, generates one.

        Returns:
            Certificate information
        """
        account = self.store.get_account(account_id)
        if not account:
            raise ValueError("Account not found")

        order = self.store.get_order(order_id)
        if not order:
            raise ValueError("Order not found")

        private_key = serialization.load_pem_private_key(
            account["private_key_pem"].encode(),
            password=None,
            backend=default_backend()
        )

        # Check order status
        response = await self._post(
            order["order_url"],
            "",  # POST-as-GET
            private_key,
            kid=account["account_url"]
        )

        order_data = response.json()
        status = order_data.get("status")

        if status == "invalid":
            raise Exception("Order is invalid. Domain validation may have failed.")

        if status == "valid":
            # Certificate already issued
            cert_url = order_data.get("certificate")
            if cert_url:
                return await self._download_certificate(account, order_id, cert_url, private_key)

        if status != "ready":
            return {
                "success": False,
                "message": f"Order not ready for finalization. Status: {status}",
                "status": status
            }

        # Generate CSR if not provided
        if not csr_pem:
            csr_pem, cert_key_pem = self._generate_csr(order["domains"])
            self.store.update_order(order_id, {"certificate_key_pem": cert_key_pem})
        else:
            if isinstance(csr_pem, str):
                csr_pem = csr_pem.encode()

        # Convert CSR to DER and base64url
        csr = x509.load_pem_x509_csr(csr_pem, default_backend())
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        csr_b64 = base64.urlsafe_b64encode(csr_der).rstrip(b'=').decode()

        # Finalize order
        response = await self._post(
            order["finalize_url"],
            {"csr": csr_b64},
            private_key,
            kid=account["account_url"]
        )

        if response.status_code not in [200, 201]:
            error = response.json()
            raise Exception(f"Finalization failed: {error.get('detail', 'Unknown error')}")

        order_data = response.json()
        status = order_data.get("status")

        # Poll for certificate
        cert_url = order_data.get("certificate")
        if not cert_url and status == "processing":
            # Wait for processing
            for _ in range(10):
                await self._async_sleep(3)
                response = await self._post(
                    order["order_url"],
                    "",
                    private_key,
                    kid=account["account_url"]
                )
                order_data = response.json()
                if order_data.get("certificate"):
                    cert_url = order_data["certificate"]
                    break
                if order_data.get("status") == "invalid":
                    raise Exception("Order became invalid during processing")

        if cert_url:
            return await self._download_certificate(account, order_id, cert_url, private_key)

        return {
            "success": False,
            "message": "Certificate not yet available",
            "status": order_data.get("status")
        }

    async def _download_certificate(
        self,
        account: Dict,
        order_id: str,
        cert_url: str,
        private_key: rsa.RSAPrivateKey
    ) -> Dict:
        """Download the issued certificate."""
        response = await self._post(
            cert_url,
            "",
            private_key,
            kid=account["account_url"]
        )

        if response.status_code != 200:
            raise Exception("Failed to download certificate")

        certificate_pem = response.text
        self.store.save_certificate(order_id, certificate_pem)

        order = self.store.get_order(order_id)

        return {
            "success": True,
            "order_id": order_id,
            "certificate_pem": certificate_pem,
            "private_key_pem": order.get("certificate_key_pem"),
            "message": "Certificate issued successfully"
        }

    def _generate_csr(self, domains: List[str]) -> Tuple[bytes, str]:
        """Generate a CSR for the given domains."""
        from cryptography.x509.oid import NameOID

        # Generate key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        # Build CSR
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domains[0])
        ])

        # Add SANs
        san_list = [x509.DNSName(domain) for domain in domains]

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False
            )
            .sign(key, hashes.SHA256(), default_backend())
        )

        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        return csr_pem, key_pem

    async def _async_sleep(self, seconds: int):
        """Async sleep helper."""
        import asyncio
        await asyncio.sleep(seconds)

    async def download_certificate(self, order_id: str) -> Dict:
        """Get the certificate for an order."""
        order = self.store.get_order(order_id)
        if not order:
            raise ValueError("Order not found")

        certificate_pem = order.get("certificate_pem")
        if not certificate_pem:
            return {
                "success": False,
                "message": "Certificate not yet issued"
            }

        return {
            "success": True,
            "order_id": order_id,
            "certificate_pem": certificate_pem,
            "private_key_pem": order.get("certificate_key_pem"),
            "domains": order.get("domains", [])
        }

    async def get_order_status(self, account_id: str, order_id: str) -> Dict:
        """Get the current status of an order."""
        account = self.store.get_account(account_id)
        if not account:
            raise ValueError("Account not found")

        order = self.store.get_order(order_id)
        if not order:
            raise ValueError("Order not found")

        private_key = serialization.load_pem_private_key(
            account["private_key_pem"].encode(),
            password=None,
            backend=default_backend()
        )

        response = await self._post(
            order["order_url"],
            "",
            private_key,
            kid=account["account_url"]
        )

        order_data = response.json()

        # Update stored order status
        self.store.update_order(order_id, {"status": order_data.get("status")})

        return {
            "success": True,
            "order_id": order_id,
            "status": order_data.get("status"),
            "expires": order_data.get("expires"),
            "certificate_url": order_data.get("certificate")
        }
