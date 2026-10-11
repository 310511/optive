"""Generate a synthetic vendor PDF with seeded PII canary values.

Creates a multi-page PDF with:
- Native text blocks with PII canaries
- A section structure (headings, body)
- A table with PII data
- An image-only page (simulates a scanned page) — blank pixel image

Usage:
    from tests.fixtures.make_pdf import make_synthetic_pdf, CANARIES
    path = make_synthetic_pdf()
"""

from __future__ import annotations

import io
import tempfile
from pathlib import Path
from typing import Final

# Canary values that must NEVER appear in LLM prompts, logs, DB outside vault,
# or OneTrust payloads. These are unique enough to be detectable.
CANARIES: Final[dict[str, str]] = {
    "EMAIL": "canary.pii.test@vendor-internal.example",
    "CREDIT_CARD": "4111-1111-1111-1111",
    "SSN": "987-65-4321",
    "PHONE": "650-555-0199",
    "API_KEY": "AKIAIOSFODNN7CANARY1",
    "IP": "10.42.88.199",
    "HOSTNAME": "db-primary.corp.acme.internal",
    "PERSON": "Jonathan Canary-Smith",
    "IBAN": "GB29 NWBK 6016 1331 9268 19",
}


def make_synthetic_pdf(output_dir: Path | None = None) -> Path:
    """Generate a synthetic vendor PDF and return its path."""
    try:
        from reportlab.lib.pagesizes import A4  # type: ignore[import-untyped]
        from reportlab.pdfgen import canvas  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError("reportlab is required for fixture generation: pip install reportlab") from exc

    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp())

    output_path = output_dir / "synthetic_vendor_soc2_report.pdf"
    c = canvas.Canvas(str(output_path), pagesize=A4)
    width, height = A4

    # ── Page 1: SOC2 Report Header + Access Controls ─────────────────────────
    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, height - 72, "SOC 2 Type II Report — FY2025")
    c.setFont("Helvetica", 10)
    c.drawString(72, height - 100, "Vendor: Acme Cloud Services Inc.")
    c.drawString(72, height - 115, "Auditor: Ernst & Partners LLP")
    c.drawString(72, height - 130, f"Primary Contact: {CANARIES['PERSON']}")
    c.drawString(72, height - 145, f"Contact Email: {CANARIES['EMAIL']}")
    c.drawString(72, height - 160, f"Contact Phone: {CANARIES['PHONE']}")

    c.setFont("Helvetica-Bold", 12)
    c.drawString(72, height - 200, "1. Access Controls")
    c.setFont("Helvetica", 10)
    c.drawString(72, height - 220, "The organization enforces multi-factor authentication for all privileged accounts.")
    c.drawString(72, height - 235, f"Administrative access is limited to hosts on {CANARIES['IP']} subnet.")
    c.drawString(72, height - 250, f"Primary database server: {CANARIES['HOSTNAME']}")
    c.drawString(72, height - 265, "Access reviews are conducted quarterly.")

    c.setFont("Helvetica-Bold", 12)
    c.drawString(72, height - 305, "2. Encryption")
    c.setFont("Helvetica", 10)
    c.drawString(72, height - 325, "All data at rest is encrypted with AES-256.")
    c.drawString(72, height - 340, "TLS 1.3 is enforced for all data in transit.")
    c.drawString(72, height - 355, f"AWS Access Key used for S3 bucket access: {CANARIES['API_KEY']}")

    # Table-like structure with PII
    c.setFont("Helvetica-Bold", 10)
    c.drawString(72, height - 395, "Employee ID")
    c.drawString(200, height - 395, "SSN")
    c.drawString(320, height - 395, "IBAN")
    c.setFont("Helvetica", 10)
    c.drawString(72, height - 410, "EMP-00442")
    c.drawString(200, height - 410, CANARIES["SSN"])
    c.drawString(320, height - 410, CANARIES["IBAN"])

    c.setFont("Helvetica-Bold", 10)
    c.drawString(72, height - 450, "Payment Details")
    c.setFont("Helvetica", 10)
    c.drawString(72, height - 465, f"Invoice settled by card: {CANARIES['CREDIT_CARD']}")

    c.showPage()

    # ── Page 2: Image-only page (simulate scanned document) ──────────────────
    # Draw a white rectangle as a stand-in "scanned" page (no extractable text)
    from reportlab.lib.colors import white  # type: ignore[import-untyped]

    c.setFillColor(white)
    c.rect(0, 0, width, height, fill=1)
    # Draw a tiny dot to make it non-trivially blank
    from reportlab.lib.colors import black  # type: ignore[import-untyped]

    c.setFillColor(black)
    c.circle(width / 2, height / 2, 1, fill=1)
    c.showPage()

    # ── Page 3: Incident Response section ────────────────────────────────────
    c.setFont("Helvetica-Bold", 12)
    c.drawString(72, height - 72, "3. Incident Response")
    c.setFont("Helvetica", 10)
    c.drawString(72, height - 92, "The vendor maintains a documented incident response plan.")
    c.drawString(72, height - 107, "Security incidents are reported to stakeholders within 72 hours.")
    c.drawString(72, height - 122, "SIEM solution: Splunk Enterprise with 90-day log retention.")

    c.setFont("Helvetica-Bold", 12)
    c.drawString(72, height - 162, "4. Subprocessors")
    c.setFont("Helvetica", 10)
    c.drawString(72, height - 182, "The following subprocessors are engaged under data processing agreements:")
    c.drawString(72, height - 197, "- AWS (Amazon Web Services) - Infrastructure")
    c.drawString(72, height - 212, "- Snowflake Inc. - Data Warehousing")

    c.showPage()
    c.save()

    return output_path


def make_synthetic_pdf_bytes() -> bytes:
    """Return PDF bytes without writing to disk."""
    path = make_synthetic_pdf()
    data = path.read_bytes()
    path.unlink()
    return data


if __name__ == "__main__":
    p = make_synthetic_pdf(Path("."))
    print(f"Generated: {p}")
