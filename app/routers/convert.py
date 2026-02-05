"""API endpoints for certificate format conversion."""

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import Response
from typing import Optional
from ..services.converter import CertificateConverter

router = APIRouter(prefix="/api/convert", tags=["conversion"])


@router.post("/pfx-to-pem")
async def pfx_to_pem(
    file: UploadFile = File(...),
    password: str = Form("")
):
    """Convert PFX/P12 to PEM format."""
    try:
        pfx_data = await file.read()
        cert_pem, key_pem, chain_pem = CertificateConverter.pfx_to_pem(pfx_data, password)

        return {
            "certificate": cert_pem,
            "private_key": key_pem,
            "chain": chain_pem,
            "filename": file.filename.rsplit(".", 1)[0] if file.filename else "certificate"
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/pem-to-pfx")
async def pem_to_pfx(
    cert_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    chain_file: Optional[UploadFile] = File(None),
    password: str = Form(""),
    friendly_name: str = Form("certificate")
):
    """Convert PEM certificate and key to PFX/P12 format."""
    try:
        cert_pem = await cert_file.read()
        key_pem = await key_file.read()
        chain_pem = await chain_file.read() if chain_file else None

        pfx_data = CertificateConverter.pem_to_pfx(
            cert_pem, key_pem, password, chain_pem, friendly_name
        )

        return Response(
            content=pfx_data,
            media_type="application/x-pkcs12",
            headers={
                "Content-Disposition": f'attachment; filename="{friendly_name}.pfx"'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/pem-to-der")
async def pem_to_der(
    file: UploadFile = File(...)
):
    """Convert PEM certificate to DER format."""
    try:
        pem_data = await file.read()
        der_data = CertificateConverter.pem_to_der(pem_data)

        filename = file.filename.rsplit(".", 1)[0] if file.filename else "certificate"

        return Response(
            content=der_data,
            media_type="application/x-x509-ca-cert",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}.der"'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/der-to-pem")
async def der_to_pem(
    file: UploadFile = File(...)
):
    """Convert DER certificate to PEM format."""
    try:
        der_data = await file.read()
        pem_data = CertificateConverter.der_to_pem(der_data)

        filename = file.filename.rsplit(".", 1)[0] if file.filename else "certificate"

        return {
            "certificate": pem_data,
            "filename": filename
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/pem-to-p7b")
async def pem_to_p7b(
    cert_file: UploadFile = File(...),
    chain_file: Optional[UploadFile] = File(None)
):
    """Convert PEM certificate(s) to P7B/PKCS#7 format."""
    try:
        cert_pem = await cert_file.read()
        chain_pem = await chain_file.read() if chain_file else None

        p7b_data = CertificateConverter.pem_to_p7b(cert_pem, chain_pem)

        filename = cert_file.filename.rsplit(".", 1)[0] if cert_file.filename else "certificate"

        return Response(
            content=p7b_data,
            media_type="application/x-pkcs7-certificates",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}.p7b"'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/p7b-to-pem")
async def p7b_to_pem(
    file: UploadFile = File(...)
):
    """Convert P7B/PKCS#7 to PEM format."""
    try:
        p7b_data = await file.read()
        pem_data = CertificateConverter.p7b_to_pem(p7b_data)

        filename = file.filename.rsplit(".", 1)[0] if file.filename else "certificate"

        return {
            "certificates": pem_data,
            "filename": filename
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/extract-key")
async def extract_key(
    file: UploadFile = File(...),
    password: str = Form(""),
    new_password: str = Form("")
):
    """Extract private key from PFX file."""
    try:
        pfx_data = await file.read()
        key_pem = CertificateConverter.extract_private_key(pfx_data, password, new_password)

        filename = file.filename.rsplit(".", 1)[0] if file.filename else "private_key"

        return {
            "private_key": key_pem,
            "filename": filename
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/extract-cert")
async def extract_cert(
    file: UploadFile = File(...),
    password: str = Form("")
):
    """Extract certificate from PFX file."""
    try:
        pfx_data = await file.read()
        cert_pem = CertificateConverter.extract_certificate(pfx_data, password)

        filename = file.filename.rsplit(".", 1)[0] if file.filename else "certificate"

        return {
            "certificate": cert_pem,
            "filename": filename
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/change-key-password")
async def change_key_password(
    file: UploadFile = File(...),
    old_password: str = Form(""),
    new_password: str = Form("")
):
    """Change or remove password from private key."""
    try:
        key_pem = await file.read()
        new_key_pem = CertificateConverter.change_key_password(key_pem, old_password, new_password)

        filename = file.filename.rsplit(".", 1)[0] if file.filename else "private_key"

        return {
            "private_key": new_key_pem,
            "filename": filename
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/key-pem-to-der")
async def key_pem_to_der(
    file: UploadFile = File(...),
    password: str = Form("")
):
    """Convert PEM private key to DER format."""
    try:
        key_pem = await file.read()
        key_der = CertificateConverter.key_pem_to_der(key_pem, password)

        filename = file.filename.rsplit(".", 1)[0] if file.filename else "private_key"

        return Response(
            content=key_der,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}.der"'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/key-der-to-pem")
async def key_der_to_pem(
    file: UploadFile = File(...)
):
    """Convert DER private key to PEM format."""
    try:
        key_der = await file.read()
        key_pem = CertificateConverter.key_der_to_pem(key_der)

        filename = file.filename.rsplit(".", 1)[0] if file.filename else "private_key"

        return {
            "private_key": key_pem,
            "filename": filename
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
