"""API endpoints for certificate analysis."""

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from ..services.analyzer import CertificateAnalyzer
from ..services.chain_validator import ChainValidator

router = APIRouter(prefix="/api/analyze", tags=["analysis"])


@router.post("/certificate")
async def analyze_certificate(
    file: UploadFile = File(...),
    password: str = Form("")
):
    """Analyze a certificate and return detailed information."""
    try:
        cert_data = await file.read()
        info = CertificateAnalyzer.analyze_certificate(cert_data, password)

        return {
            "filename": file.filename,
            "info": info
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/csr")
async def analyze_csr(
    file: UploadFile = File(...)
):
    """Analyze a CSR and return detailed information."""
    try:
        csr_data = await file.read()
        info = CertificateAnalyzer.analyze_csr(csr_data)

        return {
            "filename": file.filename,
            "info": info
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/chain")
async def analyze_chain(
    file: UploadFile = File(...),
    password: str = Form("")
):
    """Analyze a certificate chain and return information for all certificates."""
    try:
        chain_data = await file.read()
        chain_info = CertificateAnalyzer.analyze_chain(chain_data, password)

        return {
            "filename": file.filename,
            "certificates": chain_info,
            "count": len(chain_info)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/verify-match")
async def verify_key_match(
    cert_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    key_password: str = Form("")
):
    """Verify if a private key matches a certificate."""
    try:
        cert_data = await cert_file.read()
        key_data = await key_file.read()

        is_match = CertificateAnalyzer.verify_key_match(cert_data, key_data, key_password)

        return {
            "certificate_file": cert_file.filename,
            "key_file": key_file.filename,
            "match": is_match
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/certificate-text")
async def analyze_certificate_text(
    certificate: str = Form(...)
):
    """Analyze a certificate from pasted PEM text."""
    try:
        cert_data = certificate.encode()
        info = CertificateAnalyzer.analyze_certificate(cert_data)

        return {
            "info": info
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/csr-text")
async def analyze_csr_text(
    csr: str = Form(...)
):
    """Analyze a CSR from pasted PEM text."""
    try:
        csr_data = csr.encode()
        info = CertificateAnalyzer.analyze_csr(csr_data)

        return {
            "info": info
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/validate-chain")
async def validate_chain(
    file: UploadFile = File(...),
    password: str = Form(""),
    trust_store: str = Form("system")
):
    """
    Validate a certificate chain.

    Checks:
    - Chain completeness
    - Signature validity
    - Chain order
    - Missing intermediates
    - Root trust status
    """
    try:
        chain_data = await file.read()
        result = ChainValidator.validate_chain(chain_data, password)

        return {
            "filename": file.filename,
            "validation": result
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
