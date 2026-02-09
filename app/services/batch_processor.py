"""SSL Certificate Batch Processing Service."""

import zipfile
import io
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime

from .analyzer import CertificateAnalyzer
from .chain_validator import ChainValidator
from .converter import CertificateConverter


class BatchProcessor:
    """Handles batch processing of multiple certificates."""

    SUPPORTED_EXTENSIONS = {
        '.pem', '.crt', '.cer', '.der', '.pfx', '.p12', '.p7b', '.p7c', '.csr'
    }

    @classmethod
    def process_batch(
        cls,
        files: List[Tuple[str, bytes]],
        operation: str,
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Process multiple files with the specified operation.

        Args:
            files: List of (filename, content) tuples
            operation: One of 'analyze', 'convert', 'validate'
            options: Operation-specific options

        Returns:
            Batch processing results with success/failure counts
        """
        options = options or {}
        results = {
            "operation": operation,
            "total": len(files),
            "success": 0,
            "failed": 0,
            "results": [],
            "errors": []
        }

        for filename, content in files:
            try:
                if operation == "analyze":
                    result = cls._analyze_file(filename, content, options)
                elif operation == "convert":
                    result = cls._convert_file(filename, content, options)
                elif operation == "validate":
                    result = cls._validate_file(filename, content, options)
                else:
                    raise ValueError(f"Unsupported operation: {operation}")

                result["filename"] = filename
                result["success"] = True
                results["results"].append(result)
                results["success"] += 1

            except Exception as e:
                results["errors"].append({
                    "filename": filename,
                    "error": str(e)
                })
                results["results"].append({
                    "filename": filename,
                    "success": False,
                    "error": str(e)
                })
                results["failed"] += 1

        return results

    @classmethod
    def extract_from_zip(cls, zip_data: bytes) -> List[Tuple[str, bytes]]:
        """
        Extract certificate files from a ZIP archive.

        Returns list of (filename, content) tuples for supported file types.
        """
        files = []

        try:
            with zipfile.ZipFile(io.BytesIO(zip_data), 'r') as zf:
                for file_info in zf.infolist():
                    # Skip directories
                    if file_info.is_dir():
                        continue

                    # Get filename without path
                    filename = file_info.filename.split('/')[-1]
                    if not filename:
                        continue

                    # Check extension
                    ext = '.' + filename.split('.')[-1].lower() if '.' in filename else ''
                    if ext not in cls.SUPPORTED_EXTENSIONS:
                        continue

                    # Extract content
                    content = zf.read(file_info.filename)
                    files.append((filename, content))

        except zipfile.BadZipFile:
            raise ValueError("Invalid ZIP file")

        if not files:
            raise ValueError("No supported certificate files found in ZIP")

        return files

    @classmethod
    def create_result_zip(cls, results: List[Dict]) -> bytes:
        """
        Create a ZIP file containing batch operation results.

        For conversion operations, includes converted files.
        For analysis/validation, includes a summary report.
        """
        zip_buffer = io.BytesIO()

        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add summary report
            summary = cls._create_summary_report(results)
            zf.writestr('summary.txt', summary)

            # Add converted files if present
            for result in results:
                if result.get("success") and result.get("output_files"):
                    for output_file in result["output_files"]:
                        filename = output_file.get("filename", "output")
                        content = output_file.get("content", "")

                        if isinstance(content, str):
                            content = content.encode()

                        zf.writestr(filename, content)

        zip_buffer.seek(0)
        return zip_buffer.getvalue()

    @classmethod
    def _analyze_file(
        cls,
        filename: str,
        content: bytes,
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze a single certificate file."""
        password = options.get("password", "")
        ext = '.' + filename.split('.')[-1].lower() if '.' in filename else ''

        if ext == '.csr':
            info = CertificateAnalyzer.analyze_csr(content)
            return {
                "type": "csr",
                "info": info
            }
        else:
            # Check if it contains multiple certificates
            if b"-----BEGIN CERTIFICATE-----" in content:
                cert_count = content.count(b"-----BEGIN CERTIFICATE-----")
                if cert_count > 1:
                    chain_info = CertificateAnalyzer.analyze_chain(content, password)
                    return {
                        "type": "chain",
                        "certificate_count": cert_count,
                        "certificates": chain_info
                    }

            info = CertificateAnalyzer.analyze_certificate(content, password)
            return {
                "type": "certificate",
                "info": info
            }

    @classmethod
    def _convert_file(
        cls,
        filename: str,
        content: bytes,
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Convert a single certificate file."""
        target_format = options.get("target_format", "pem")
        password = options.get("password", "")
        new_password = options.get("new_password", "")

        ext = '.' + filename.split('.')[-1].lower() if '.' in filename else ''
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename

        output_files = []

        # PFX/P12 to PEM
        if ext in ['.pfx', '.p12'] and target_format == 'pem':
            cert_pem, key_pem, chain_pem = CertificateConverter.pfx_to_pem(
                content, password,
                key_format=options.get("key_format", "pkcs8")
            )

            if cert_pem:
                output_files.append({
                    "filename": f"{base_name}.crt",
                    "content": cert_pem,
                    "type": "certificate"
                })
            if key_pem:
                output_files.append({
                    "filename": f"{base_name}.key",
                    "content": key_pem,
                    "type": "private_key"
                })
            if chain_pem:
                output_files.append({
                    "filename": f"{base_name}-chain.crt",
                    "content": chain_pem,
                    "type": "chain"
                })

        # PEM to DER
        elif ext in ['.pem', '.crt', '.cer'] and target_format == 'der':
            der_data = CertificateConverter.pem_to_der(content)
            output_files.append({
                "filename": f"{base_name}.der",
                "content": der_data,
                "type": "certificate"
            })

        # DER to PEM
        elif ext == '.der' and target_format == 'pem':
            pem_data = CertificateConverter.der_to_pem(content)
            output_files.append({
                "filename": f"{base_name}.pem",
                "content": pem_data,
                "type": "certificate"
            })

        # P7B to PEM
        elif ext in ['.p7b', '.p7c'] and target_format == 'pem':
            certs_pem = CertificateConverter.p7b_to_pem(content)
            output_files.append({
                "filename": f"{base_name}.pem",
                "content": certs_pem,
                "type": "certificates"
            })

        else:
            raise ValueError(f"Unsupported conversion: {ext} to {target_format}")

        return {
            "source_format": ext,
            "target_format": target_format,
            "output_files": output_files
        }

    @classmethod
    def _validate_file(
        cls,
        filename: str,
        content: bytes,
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate a certificate chain file."""
        password = options.get("password", "")

        validation = ChainValidator.validate_chain(content, password)

        return {
            "validation": validation,
            "chain_complete": validation.get("chain_complete", False),
            "certificate_count": validation.get("certificate_count", 0),
            "issues": validation.get("issues", []),
            "warnings": validation.get("warnings", [])
        }

    @classmethod
    def _create_summary_report(cls, results: List[Dict]) -> str:
        """Create a text summary report of batch results."""
        lines = [
            "=" * 60,
            "SSL Certificate Manager - Batch Processing Report",
            f"Generated: {datetime.utcnow().isoformat()}",
            "=" * 60,
            ""
        ]

        success_count = sum(1 for r in results if r.get("success"))
        failed_count = len(results) - success_count

        lines.extend([
            f"Total files processed: {len(results)}",
            f"Successful: {success_count}",
            f"Failed: {failed_count}",
            ""
        ])

        if success_count > 0:
            lines.extend([
                "-" * 40,
                "Successful Operations:",
                "-" * 40
            ])

            for result in results:
                if result.get("success"):
                    lines.append(f"  - {result.get('filename', 'unknown')}")

                    if result.get("type") == "certificate":
                        info = result.get("info", {})
                        subject = info.get("subject", {})
                        cn = subject.get("CN", "N/A")
                        lines.append(f"    Subject: {cn}")
                        validity = info.get("validity", {})
                        lines.append(f"    Valid: {validity.get('not_before', 'N/A')} to {validity.get('not_after', 'N/A')}")

                    elif result.get("type") == "chain":
                        lines.append(f"    Certificates in chain: {result.get('certificate_count', 0)}")

                    elif result.get("validation"):
                        val = result["validation"]
                        status = "Complete" if val.get("chain_complete") else "Incomplete"
                        lines.append(f"    Chain status: {status}")

                    lines.append("")

        if failed_count > 0:
            lines.extend([
                "-" * 40,
                "Failed Operations:",
                "-" * 40
            ])

            for result in results:
                if not result.get("success"):
                    lines.append(f"  - {result.get('filename', 'unknown')}")
                    lines.append(f"    Error: {result.get('error', 'Unknown error')}")
                    lines.append("")

        return "\n".join(lines)
