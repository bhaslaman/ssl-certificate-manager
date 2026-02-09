"""API endpoints for ACME/Let's Encrypt integration."""

from fastapi import APIRouter, Form, HTTPException, UploadFile, File
from typing import List, Optional

from ..services.acme_client import ACMEClient
from ..services.acme_store import get_store

router = APIRouter(prefix="/api/acme", tags=["acme"])


@router.post("/register")
async def register_account(
    email: str = Form(...),
    environment: str = Form("staging")
):
    """
    Register a new ACME account with Let's Encrypt.

    Args:
        email: Contact email address
        environment: 'staging' for testing, 'production' for real certificates
    """
    if environment not in ["staging", "production"]:
        raise HTTPException(status_code=400, detail="Invalid environment")

    try:
        client = ACMEClient(environment=environment)
        result = await client.register_account(email)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/accounts")
async def list_accounts():
    """List all registered ACME accounts."""
    try:
        store = get_store()
        accounts = store.list_accounts()
        return {"accounts": accounts}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/accounts/{account_id}")
async def delete_account(account_id: str):
    """Delete an ACME account."""
    try:
        store = get_store()
        success = store.delete_account(account_id)
        if not success:
            raise HTTPException(status_code=404, detail="Account not found")
        return {"success": True, "message": "Account deleted"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/order/create")
async def create_order(
    account_id: str = Form(...),
    domains: str = Form(...)
):
    """
    Create a new certificate order.

    Args:
        account_id: ACME account ID
        domains: Comma-separated list of domain names
    """
    try:
        domain_list = [d.strip() for d in domains.split(",") if d.strip()]
        if not domain_list:
            raise HTTPException(status_code=400, detail="No domains specified")

        # Get account to determine environment
        store = get_store()
        account = store.get_account(account_id)
        if not account:
            raise HTTPException(status_code=404, detail="Account not found")

        client = ACMEClient(environment=account.get("environment", "staging"))
        result = await client.create_order(account_id, domain_list)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/order/{order_id}/challenge")
async def get_challenge(order_id: str, account_id: str):
    """
    Get HTTP-01 challenge information for an order.

    Returns the token and expected response for each domain.
    """
    try:
        store = get_store()
        account = store.get_account(account_id)
        if not account:
            raise HTTPException(status_code=404, detail="Account not found")

        client = ACMEClient(environment=account.get("environment", "staging"))
        result = await client.get_http01_challenge(account_id, order_id)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/order/{order_id}/verify")
async def verify_challenge(
    order_id: str,
    account_id: str = Form(...),
    domain: Optional[str] = Form(None)
):
    """
    Trigger challenge verification for a domain.

    The domain must have the challenge file in place before calling this.
    """
    try:
        store = get_store()
        account = store.get_account(account_id)
        if not account:
            raise HTTPException(status_code=404, detail="Account not found")

        client = ACMEClient(environment=account.get("environment", "staging"))
        result = await client.verify_challenge(account_id, order_id, domain)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/order/{order_id}/finalize")
async def finalize_order(
    order_id: str,
    account_id: str = Form(...),
    csr_file: Optional[UploadFile] = File(None)
):
    """
    Finalize the order and obtain the certificate.

    If no CSR is provided, one will be generated automatically.
    """
    try:
        store = get_store()
        account = store.get_account(account_id)
        if not account:
            raise HTTPException(status_code=404, detail="Account not found")

        csr_pem = None
        if csr_file:
            csr_pem = await csr_file.read()

        client = ACMEClient(environment=account.get("environment", "staging"))
        result = await client.finalize_order(account_id, order_id, csr_pem)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/order/{order_id}/status")
async def get_order_status(order_id: str, account_id: str):
    """Get the current status of an order."""
    try:
        store = get_store()
        account = store.get_account(account_id)
        if not account:
            raise HTTPException(status_code=404, detail="Account not found")

        client = ACMEClient(environment=account.get("environment", "staging"))
        result = await client.get_order_status(account_id, order_id)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/order/{order_id}/certificate")
async def download_certificate(order_id: str):
    """Download the issued certificate for an order."""
    try:
        store = get_store()
        order = store.get_order(order_id)
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        account_id = order.get("account_id")
        account = store.get_account(account_id)
        if not account:
            raise HTTPException(status_code=404, detail="Account not found")

        client = ACMEClient(environment=account.get("environment", "staging"))
        result = await client.download_certificate(order_id)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/orders")
async def list_orders(account_id: Optional[str] = None, status: Optional[str] = None):
    """List all orders, optionally filtered by account and/or status."""
    try:
        store = get_store()
        orders = store.list_orders(account_id=account_id, status=status)

        # Remove sensitive data
        for order in orders:
            order.pop("certificate_key_pem", None)

        return {"orders": orders}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/orders/{order_id}")
async def delete_order(order_id: str):
    """Delete an order."""
    try:
        store = get_store()
        success = store.delete_order(order_id)
        if not success:
            raise HTTPException(status_code=404, detail="Order not found")
        return {"success": True, "message": "Order deleted"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
