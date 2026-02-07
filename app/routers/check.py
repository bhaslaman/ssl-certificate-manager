"""API endpoints for SSL URL checking."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from ..services.ssl_checker import SSLChecker

router = APIRouter(prefix="/api/check", tags=["check"])


class URLCheckRequest(BaseModel):
    """Request model for URL SSL check."""
    hostname: str
    port: int = 443
    check_dns: bool = False


@router.post("/url")
async def check_url(request: URLCheckRequest):
    """
    Check SSL certificate of a URL.

    Args:
        hostname: The hostname to check (e.g., google.com)
        port: The port to connect to (default: 443)
        check_dns: Whether to include DNS resolution info

    Returns:
        Certificate info, chain, validation status, and optionally DNS info
    """
    try:
        result = SSLChecker.check_url(
            hostname=request.hostname,
            port=request.port,
            check_dns=request.check_dns
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to check SSL: {str(e)}")
