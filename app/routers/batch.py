"""API endpoints for batch certificate processing."""

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse
from typing import List
import io

from ..services.batch_processor import BatchProcessor

router = APIRouter(prefix="/api/batch", tags=["batch"])


@router.post("/process")
async def process_batch(
    files: List[UploadFile] = File(...),
    operation: str = Form("analyze"),
    password: str = Form(""),
    target_format: str = Form("pem"),
    key_format: str = Form("pkcs8")
):
    """
    Process multiple certificate files.

    Operations:
    - analyze: Analyze all certificates
    - convert: Convert all certificates to target format
    - validate: Validate all certificate chains
    """
    if operation not in ["analyze", "convert", "validate"]:
        raise HTTPException(status_code=400, detail="Invalid operation")

    try:
        # Read all files
        file_list = []
        for f in files:
            content = await f.read()
            file_list.append((f.filename, content))

        # Process
        options = {
            "password": password,
            "target_format": target_format,
            "key_format": key_format
        }

        result = BatchProcessor.process_batch(file_list, operation, options)

        return result

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/process-zip")
async def process_zip(
    file: UploadFile = File(...),
    operation: str = Form("analyze"),
    password: str = Form(""),
    target_format: str = Form("pem"),
    key_format: str = Form("pkcs8"),
    download_results: bool = Form(False)
):
    """
    Process a ZIP file containing multiple certificates.

    If download_results is True, returns a ZIP with results.
    Otherwise returns JSON results.
    """
    if operation not in ["analyze", "convert", "validate"]:
        raise HTTPException(status_code=400, detail="Invalid operation")

    try:
        zip_data = await file.read()

        # Extract files from ZIP
        files = BatchProcessor.extract_from_zip(zip_data)

        # Process
        options = {
            "password": password,
            "target_format": target_format,
            "key_format": key_format
        }

        result = BatchProcessor.process_batch(files, operation, options)

        # Return ZIP if requested
        if download_results and operation == "convert":
            result_zip = BatchProcessor.create_result_zip(result["results"])
            return StreamingResponse(
                io.BytesIO(result_zip),
                media_type="application/zip",
                headers={
                    "Content-Disposition": f"attachment; filename=\"batch_results.zip\""
                }
            )

        return result

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/download-results")
async def download_results(
    results: List[dict]
):
    """
    Download batch processing results as a ZIP file.
    """
    try:
        result_zip = BatchProcessor.create_result_zip(results)
        return StreamingResponse(
            io.BytesIO(result_zip),
            media_type="application/zip",
            headers={
                "Content-Disposition": f"attachment; filename=\"batch_results.zip\""
            }
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
