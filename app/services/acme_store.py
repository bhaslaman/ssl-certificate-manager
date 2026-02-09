"""ACME Account and Order Storage Service."""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
import hashlib


class ACMEStore:
    """Handles persistent storage of ACME accounts and orders."""

    def __init__(self, storage_dir: str = None):
        """
        Initialize the ACME store.

        Args:
            storage_dir: Directory for storing ACME data. Defaults to app/data/acme
        """
        if storage_dir is None:
            # Default to app/data/acme relative to this file
            base_dir = Path(__file__).parent.parent
            storage_dir = base_dir / "data" / "acme"

        self.storage_dir = Path(storage_dir)
        self.accounts_dir = self.storage_dir / "accounts"
        self.orders_dir = self.storage_dir / "orders"

        # Create directories if they don't exist
        self.accounts_dir.mkdir(parents=True, exist_ok=True)
        self.orders_dir.mkdir(parents=True, exist_ok=True)

    # ==================== Account Management ====================

    def save_account(self, account_data: Dict) -> str:
        """
        Save an ACME account.

        Args:
            account_data: Account data including email, key, and registration info

        Returns:
            Account ID
        """
        # Generate account ID from email
        email = account_data.get("email", "")
        environment = account_data.get("environment", "staging")
        account_id = self._generate_account_id(email, environment)

        account_data["account_id"] = account_id
        account_data["created_at"] = datetime.utcnow().isoformat()
        account_data["updated_at"] = datetime.utcnow().isoformat()

        # Save to file
        account_file = self.accounts_dir / f"{account_id}.json"
        with open(account_file, "w", encoding="utf-8") as f:
            json.dump(account_data, f, indent=2)

        return account_id

    def get_account(self, account_id: str) -> Optional[Dict]:
        """Get an account by ID."""
        account_file = self.accounts_dir / f"{account_id}.json"
        if not account_file.exists():
            return None

        with open(account_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def get_account_by_email(self, email: str, environment: str = "staging") -> Optional[Dict]:
        """Get an account by email and environment."""
        account_id = self._generate_account_id(email, environment)
        return self.get_account(account_id)

    def list_accounts(self) -> List[Dict]:
        """List all saved accounts."""
        accounts = []
        for account_file in self.accounts_dir.glob("*.json"):
            with open(account_file, "r", encoding="utf-8") as f:
                account = json.load(f)
                # Don't include private key in list
                account.pop("private_key_pem", None)
                accounts.append(account)
        return accounts

    def delete_account(self, account_id: str) -> bool:
        """Delete an account."""
        account_file = self.accounts_dir / f"{account_id}.json"
        if account_file.exists():
            account_file.unlink()
            return True
        return False

    def update_account(self, account_id: str, updates: Dict) -> Optional[Dict]:
        """Update an account."""
        account = self.get_account(account_id)
        if not account:
            return None

        account.update(updates)
        account["updated_at"] = datetime.utcnow().isoformat()

        account_file = self.accounts_dir / f"{account_id}.json"
        with open(account_file, "w", encoding="utf-8") as f:
            json.dump(account, f, indent=2)

        return account

    # ==================== Order Management ====================

    def save_order(self, order_data: Dict) -> str:
        """
        Save an ACME order.

        Args:
            order_data: Order data including domains, status, and challenge info

        Returns:
            Order ID
        """
        order_id = order_data.get("order_id") or self._generate_order_id()
        order_data["order_id"] = order_id
        order_data["created_at"] = order_data.get("created_at", datetime.utcnow().isoformat())
        order_data["updated_at"] = datetime.utcnow().isoformat()

        # Save to file
        order_file = self.orders_dir / f"{order_id}.json"
        with open(order_file, "w", encoding="utf-8") as f:
            json.dump(order_data, f, indent=2)

        return order_id

    def get_order(self, order_id: str) -> Optional[Dict]:
        """Get an order by ID."""
        order_file = self.orders_dir / f"{order_id}.json"
        if not order_file.exists():
            return None

        with open(order_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def list_orders(self, account_id: str = None, status: str = None) -> List[Dict]:
        """
        List orders, optionally filtered by account and/or status.

        Args:
            account_id: Filter by account ID
            status: Filter by status (pending, ready, processing, valid, invalid)
        """
        orders = []
        for order_file in self.orders_dir.glob("*.json"):
            with open(order_file, "r", encoding="utf-8") as f:
                order = json.load(f)

                if account_id and order.get("account_id") != account_id:
                    continue
                if status and order.get("status") != status:
                    continue

                orders.append(order)

        # Sort by created_at descending
        orders.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return orders

    def update_order(self, order_id: str, updates: Dict) -> Optional[Dict]:
        """Update an order."""
        order = self.get_order(order_id)
        if not order:
            return None

        order.update(updates)
        order["updated_at"] = datetime.utcnow().isoformat()

        order_file = self.orders_dir / f"{order_id}.json"
        with open(order_file, "w", encoding="utf-8") as f:
            json.dump(order, f, indent=2)

        return order

    def delete_order(self, order_id: str) -> bool:
        """Delete an order."""
        order_file = self.orders_dir / f"{order_id}.json"
        if order_file.exists():
            order_file.unlink()
            return True
        return False

    # ==================== Challenge Management ====================

    def save_challenge(self, order_id: str, domain: str, challenge_data: Dict) -> None:
        """Save challenge data for a domain in an order."""
        order = self.get_order(order_id)
        if not order:
            raise ValueError(f"Order not found: {order_id}")

        if "challenges" not in order:
            order["challenges"] = {}

        order["challenges"][domain] = {
            **challenge_data,
            "updated_at": datetime.utcnow().isoformat()
        }

        self.update_order(order_id, {"challenges": order["challenges"]})

    def get_challenge(self, order_id: str, domain: str) -> Optional[Dict]:
        """Get challenge data for a domain."""
        order = self.get_order(order_id)
        if not order:
            return None

        return order.get("challenges", {}).get(domain)

    # ==================== Certificate Storage ====================

    def save_certificate(self, order_id: str, certificate_pem: str) -> None:
        """Save the issued certificate for an order."""
        self.update_order(order_id, {
            "certificate_pem": certificate_pem,
            "certificate_issued_at": datetime.utcnow().isoformat(),
            "status": "valid"
        })

    def get_certificate(self, order_id: str) -> Optional[str]:
        """Get the certificate for an order."""
        order = self.get_order(order_id)
        if not order:
            return None
        return order.get("certificate_pem")

    # ==================== Helper Methods ====================

    def _generate_account_id(self, email: str, environment: str) -> str:
        """Generate a deterministic account ID from email and environment."""
        data = f"{email}:{environment}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _generate_order_id(self) -> str:
        """Generate a unique order ID."""
        import uuid
        return str(uuid.uuid4())[:8]

    def cleanup_old_orders(self, days: int = 30) -> int:
        """
        Delete orders older than specified days.

        Returns number of deleted orders.
        """
        from datetime import timedelta

        cutoff = datetime.utcnow() - timedelta(days=days)
        deleted = 0

        for order_file in self.orders_dir.glob("*.json"):
            with open(order_file, "r", encoding="utf-8") as f:
                order = json.load(f)

            created_at = order.get("created_at", "")
            if created_at:
                try:
                    order_date = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                    if order_date.replace(tzinfo=None) < cutoff:
                        order_file.unlink()
                        deleted += 1
                except ValueError:
                    pass

        return deleted


# Global store instance
_store = None


def get_store() -> ACMEStore:
    """Get the global ACME store instance."""
    global _store
    if _store is None:
        _store = ACMEStore()
    return _store
