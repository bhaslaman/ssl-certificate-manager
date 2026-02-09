"""API endpoints for certificate comparison."""

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from ..services.comparator import CertificateComparator

router = APIRouter(prefix="/api/compare", tags=["comparison"])


@router.post("/certificates")
async def compare_certificates(
    cert1_file: UploadFile = File(...),
    cert2_file: UploadFile = File(...),
    cert1_password: str = Form(""),
    cert2_password: str = Form("")
):
    """Compare two certificates and return differences."""
    try:
        cert1_data = await cert1_file.read()
        cert2_data = await cert2_file.read()

        result = CertificateComparator.compare_certificates(
            cert1_data, cert2_data,
            cert1_password, cert2_password
        )

        return {
            "cert1_filename": cert1_file.filename,
            "cert2_filename": cert2_file.filename,
            "comparison": result
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/cert-key")
async def compare_cert_key(
    cert_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    cert_password: str = Form(""),
    key_password: str = Form("")
):
    """Verify if a private key matches a certificate."""
    try:
        cert_data = await cert_file.read()
        key_data = await key_file.read()

        result = CertificateComparator.verify_key_matches_cert(
            cert_data, key_data,
            cert_password, key_password
        )

        return {
            "cert_filename": cert_file.filename,
            "key_filename": key_file.filename,
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/cert-csr")
async def compare_cert_csr(
    csr_file: UploadFile = File(...),
    cert_file: UploadFile = File(...),
    cert_password: str = Form("")
):
    """Verify if a CSR matches a certificate."""
    try:
        csr_data = await csr_file.read()
        cert_data = await cert_file.read()

        result = CertificateComparator.verify_csr_matches_cert(
            csr_data, cert_data, cert_password
        )

        return {
            "csr_filename": csr_file.filename,
            "cert_filename": cert_file.filename,
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
