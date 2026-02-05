"""API endpoints for certificate and key generation."""

from fastapi import APIRouter, Form, HTTPException, UploadFile, File
from fastapi.responses import Response
from typing import Optional, List
from pydantic import BaseModel
from ..services.generator import CertificateGenerator

router = APIRouter(prefix="/api/generate", tags=["generation"])


class SubjectInfo(BaseModel):
    CN: str
    O: Optional[str] = None
    OU: Optional[str] = None
    C: Optional[str] = None
    ST: Optional[str] = None
    L: Optional[str] = None
    Email: Optional[str] = None


class SANEntry(BaseModel):
    type: str  # DNS, IP, Email, URI
    value: str


@router.post("/private-key")
async def generate_private_key(
    key_type: str = Form("RSA-2048"),
    password: str = Form("")
):
    """Generate a new private key."""
    try:
        if key_type not in CertificateGenerator.SUPPORTED_KEY_TYPES:
            raise ValueError(f"Unsupported key type. Use one of: {', '.join(CertificateGenerator.SUPPORTED_KEY_TYPES)}")

        key_pem = CertificateGenerator.generate_private_key(key_type, password)

        return {
            "private_key": key_pem,
            "key_type": key_type,
            "encrypted": bool(password)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/csr")
async def generate_csr(
    key_file: UploadFile = File(...),
    cn: str = Form(...),
    o: str = Form(""),
    ou: str = Form(""),
    c: str = Form(""),
    st: str = Form(""),
    l: str = Form(""),
    email: str = Form(""),
    san_dns: str = Form(""),  # Comma-separated DNS names
    san_ip: str = Form(""),   # Comma-separated IP addresses
    key_password: str = Form("")
):
    """Generate a Certificate Signing Request."""
    try:
        key_pem = await key_file.read()

        subject_info = {"CN": cn}
        if o:
            subject_info["O"] = o
        if ou:
            subject_info["OU"] = ou
        if c:
            subject_info["C"] = c
        if st:
            subject_info["ST"] = st
        if l:
            subject_info["L"] = l
        if email:
            subject_info["Email"] = email

        san_list = []
        if san_dns:
            for dns in san_dns.split(","):
                dns = dns.strip()
                if dns:
                    san_list.append({"type": "DNS", "value": dns})
        if san_ip:
            for ip in san_ip.split(","):
                ip = ip.strip()
                if ip:
                    san_list.append({"type": "IP", "value": ip})

        csr_pem = CertificateGenerator.generate_csr(
            key_pem, subject_info, san_list if san_list else None, key_password
        )

        return {
            "csr": csr_pem,
            "subject": subject_info,
            "san": san_list
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/self-signed")
async def generate_self_signed(
    key_file: UploadFile = File(...),
    cn: str = Form(...),
    o: str = Form(""),
    ou: str = Form(""),
    c: str = Form(""),
    st: str = Form(""),
    l: str = Form(""),
    email: str = Form(""),
    validity_days: int = Form(365),
    san_dns: str = Form(""),
    san_ip: str = Form(""),
    key_password: str = Form(""),
    is_ca: bool = Form(False)
):
    """Generate a self-signed certificate."""
    try:
        key_pem = await key_file.read()

        subject_info = {"CN": cn}
        if o:
            subject_info["O"] = o
        if ou:
            subject_info["OU"] = ou
        if c:
            subject_info["C"] = c
        if st:
            subject_info["ST"] = st
        if l:
            subject_info["L"] = l
        if email:
            subject_info["Email"] = email

        san_list = []
        if san_dns:
            for dns in san_dns.split(","):
                dns = dns.strip()
                if dns:
                    san_list.append({"type": "DNS", "value": dns})
        if san_ip:
            for ip in san_ip.split(","):
                ip = ip.strip()
                if ip:
                    san_list.append({"type": "IP", "value": ip})

        cert_pem = CertificateGenerator.generate_self_signed(
            key_pem, subject_info, validity_days,
            san_list if san_list else None, key_password, is_ca
        )

        return {
            "certificate": cert_pem,
            "subject": subject_info,
            "validity_days": validity_days,
            "is_ca": is_ca
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/ca")
async def generate_ca(
    key_file: UploadFile = File(...),
    cn: str = Form(...),
    o: str = Form(""),
    ou: str = Form(""),
    c: str = Form(""),
    st: str = Form(""),
    l: str = Form(""),
    validity_days: int = Form(3650),
    key_password: str = Form(""),
    path_length: int = Form(0)
):
    """Generate a CA certificate."""
    try:
        key_pem = await key_file.read()

        subject_info = {"CN": cn}
        if o:
            subject_info["O"] = o
        if ou:
            subject_info["OU"] = ou
        if c:
            subject_info["C"] = c
        if st:
            subject_info["ST"] = st
        if l:
            subject_info["L"] = l

        ca_cert_pem = CertificateGenerator.generate_ca_certificate(
            key_pem, subject_info, validity_days, key_password, path_length
        )

        return {
            "certificate": ca_cert_pem,
            "subject": subject_info,
            "validity_days": validity_days,
            "path_length": path_length
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/key-and-cert")
async def generate_key_and_cert(
    cn: str = Form(...),
    o: str = Form(""),
    ou: str = Form(""),
    c: str = Form(""),
    st: str = Form(""),
    l: str = Form(""),
    email: str = Form(""),
    key_type: str = Form("RSA-2048"),
    validity_days: int = Form(365),
    san_dns: str = Form(""),
    san_ip: str = Form(""),
    key_password: str = Form("")
):
    """Generate both private key and self-signed certificate in one operation."""
    try:
        if key_type not in CertificateGenerator.SUPPORTED_KEY_TYPES:
            raise ValueError(f"Unsupported key type. Use one of: {', '.join(CertificateGenerator.SUPPORTED_KEY_TYPES)}")

        subject_info = {"CN": cn}
        if o:
            subject_info["O"] = o
        if ou:
            subject_info["OU"] = ou
        if c:
            subject_info["C"] = c
        if st:
            subject_info["ST"] = st
        if l:
            subject_info["L"] = l
        if email:
            subject_info["Email"] = email

        san_list = []
        if san_dns:
            for dns in san_dns.split(","):
                dns = dns.strip()
                if dns:
                    san_list.append({"type": "DNS", "value": dns})
        if san_ip:
            for ip in san_ip.split(","):
                ip = ip.strip()
                if ip:
                    san_list.append({"type": "IP", "value": ip})

        key_pem, cert_pem = CertificateGenerator.generate_key_and_self_signed(
            subject_info, key_type, validity_days,
            san_list if san_list else None, key_password
        )

        return {
            "private_key": key_pem,
            "certificate": cert_pem,
            "key_type": key_type,
            "subject": subject_info,
            "validity_days": validity_days
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/sign-csr")
async def sign_csr(
    csr_file: UploadFile = File(...),
    ca_cert_file: UploadFile = File(...),
    ca_key_file: UploadFile = File(...),
    validity_days: int = Form(365),
    ca_key_password: str = Form("")
):
    """Sign a CSR with a CA certificate."""
    try:
        csr_pem = await csr_file.read()
        ca_cert_pem = await ca_cert_file.read()
        ca_key_pem = await ca_key_file.read()

        cert_pem = CertificateGenerator.sign_csr_with_ca(
            csr_pem, ca_cert_pem, ca_key_pem, validity_days, ca_key_password
        )

        return {
            "certificate": cert_pem,
            "validity_days": validity_days
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
