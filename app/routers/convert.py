"""API endpoints for certificate format conversion."""

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import Response
from typing import Optional
from ..services.converter import CertificateConverter
from ..services.jks_converter import JKSConverter

router = APIRouter(prefix="/api/convert", tags=["conversion"])


@router.post("/pfx-to-pem")
async def pfx_to_pem(
    file: UploadFile = File(...),
    password: str = Form(""),
    key_format: str = Form("pkcs8"),
    export_mode: str = Form("bundle")
):
    """
    Convert PFX/P12 to PEM format.

    Args:
        file: PFX/P12 file
        password: PFX password
        key_format: "pkcs8" (default) or "traditional" for TraditionalOpenSSL format
        export_mode: "bundle" (default) returns JSON, "split" returns ZIP with separate files
    """
    try:
        pfx_data = await file.read()
        base_filename = file.filename.rsplit(".", 1)[0] if file.filename else "certificate"

        # Split mode: return ZIP file with separate cert, key, chain files
        if export_mode == "split":
            zip_data = CertificateConverter.pfx_to_pem_split(
                pfx_data, password, key_format, base_filename
            )
            return Response(
                content=zip_data,
                media_type="application/zip",
                headers={
                    "Content-Disposition": f'attachment; filename="{base_filename}.zip"'
                }
            )

        # Bundle mode: return JSON with all PEM data
        cert_pem, key_pem, chain_pem = CertificateConverter.pfx_to_pem(
            pfx_data, password, key_format
        )

        return {
            "certificate": cert_pem,
            "private_key": key_pem,
            "chain": chain_pem,
            "filename": base_filename
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
    new_password: str = Form(""),
    key_format: str = Form("pkcs8")
):
    """
    Extract private key from PFX file.

    Args:
        file: PFX/P12 file
        password: PFX password
        new_password: Optional password to encrypt the extracted key
        key_format: "pkcs8" (default) or "traditional" for TraditionalOpenSSL format
    """
    try:
        pfx_data = await file.read()
        key_pem = CertificateConverter.extract_private_key(
            pfx_data, password, new_password, key_format
        )

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


# ==================== JKS ENDPOINTS ====================

@router.post("/pfx-to-jks")
async def pfx_to_jks(
    file: UploadFile = File(...),
    pfx_password: str = Form(""),
    jks_password: str = Form(""),
    alias: str = Form("certificate")
):
    """
    Convert PFX/P12 to JKS (Java KeyStore) format.

    Args:
        file: PFX/P12 file
        pfx_password: PFX password
        jks_password: Password for output JKS
        alias: Alias for the entry in JKS
    """
    try:
        pfx_data = await file.read()
        jks_data = JKSConverter.pfx_to_jks(pfx_data, pfx_password, jks_password, alias)

        filename = file.filename.rsplit(".", 1)[0] if file.filename else "keystore"

        return Response(
            content=jks_data,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}.jks"'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/jks-to-pfx")
async def jks_to_pfx(
    file: UploadFile = File(...),
    jks_password: str = Form(""),
    pfx_password: str = Form(""),
    alias: str = Form("")
):
    """
    Convert JKS (Java KeyStore) to PFX/P12 format.

    Args:
        file: JKS file
        jks_password: JKS password
        pfx_password: Password for output PFX
        alias: Specific alias to export (optional, exports all if empty)
    """
    try:
        jks_data = await file.read()
        pfx_data = JKSConverter.jks_to_pfx(jks_data, jks_password, pfx_password, alias)

        filename = file.filename.rsplit(".", 1)[0] if file.filename else "certificate"

        return Response(
            content=pfx_data,
            media_type="application/x-pkcs12",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}.pfx"'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/pem-to-jks")
async def pem_to_jks(
    cert_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    chain_file: Optional[UploadFile] = File(None),
    jks_password: str = Form(""),
    alias: str = Form("certificate")
):
    """
    Convert PEM certificate and key to JKS format.

    Args:
        cert_file: Certificate PEM file
        key_file: Private key PEM file
        chain_file: Optional certificate chain PEM file
        jks_password: Password for output JKS
        alias: Alias for the entry
    """
    try:
        cert_pem = await cert_file.read()
        key_pem = await key_file.read()
        chain_pem = await chain_file.read() if chain_file else None

        jks_data = JKSConverter.pem_to_jks(cert_pem, key_pem, jks_password, alias, chain_pem)

        filename = cert_file.filename.rsplit(".", 1)[0] if cert_file.filename else "keystore"

        return Response(
            content=jks_data,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}.jks"'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/jks-aliases")
async def jks_aliases(
    file: UploadFile = File(...),
    jks_password: str = Form("")
):
    """
    List all aliases in a JKS keystore.

    Args:
        file: JKS file
        jks_password: JKS password

    Returns:
        List of aliases with type and creation date
    """
    try:
        jks_data = await file.read()
        aliases = JKSConverter.list_aliases(jks_data, jks_password)

        return {
            "aliases": aliases,
            "filename": file.filename
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
