"""Generate a realistic-looking vendor SOC 2 security report PDF.

The document reads like a genuine third-party security assessment.
PII and sensitive data are embedded naturally in the text — the way
they would appear in a real vendor report — rather than as obvious
labelled fixtures.

Usage:
    from tests.fixtures.make_realistic_pdf import make_realistic_pdf
    path = make_realistic_pdf()      # returns Path to generated PDF
"""

from __future__ import annotations

import tempfile
from pathlib import Path


def make_realistic_pdf(output_dir: Path | None = None) -> Path:
    """Generate a realistic vendor SOC 2 report PDF and return its path."""
    try:
        from reportlab.lib.pagesizes import A4  # type: ignore[import-untyped]
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (  # type: ignore[import-untyped]
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError("reportlab is required: pip install reportlab") from exc

    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp())

    output_path = output_dir / "NovaTech_Security_Assessment_FY2025.pdf"

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=25 * mm,
        rightMargin=25 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "Title", parent=styles["Normal"],
        fontSize=20, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1a2a4a"),
        spaceAfter=4, leading=26,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle", parent=styles["Normal"],
        fontSize=11, fontName="Helvetica",
        textColor=colors.HexColor("#4a5568"),
        spaceAfter=2,
    )
    heading1_style = ParagraphStyle(
        "H1", parent=styles["Normal"],
        fontSize=13, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1a2a4a"),
        spaceBefore=14, spaceAfter=6, leading=18,
    )
    heading2_style = ParagraphStyle(
        "H2", parent=styles["Normal"],
        fontSize=11, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#2d3748"),
        spaceBefore=10, spaceAfter=4, leading=15,
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=9.5, fontName="Helvetica",
        textColor=colors.HexColor("#2d3748"),
        leading=14, spaceAfter=6, alignment=TA_JUSTIFY,
    )
    small_style = ParagraphStyle(
        "Small", parent=styles["Normal"],
        fontSize=8.5, fontName="Helvetica",
        textColor=colors.HexColor("#718096"),
        leading=12, spaceAfter=4,
    )
    label_style = ParagraphStyle(
        "Label", parent=styles["Normal"],
        fontSize=8, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#4a5568"),
        spaceAfter=2, spaceBefore=6,
    )

    def hr():
        return HRFlowable(width="100%", thickness=0.5,
                          color=colors.HexColor("#e2e8f0"), spaceAfter=8, spaceBefore=4)

    story = []

    # ── Cover ─────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 18 * mm))
    story.append(Paragraph("NovaTech Solutions Ltd.", title_style))
    story.append(Paragraph("Third-Party Security Assessment Report", subtitle_style))
    story.append(Paragraph("SOC 2 Type II — Assessment Period: January 1 – December 31, 2025", subtitle_style))
    story.append(Spacer(1, 8 * mm))
    story.append(hr())

    meta_data = [
        ["Prepared by:", "Clearview Risk Advisory Group"],
        ["Lead Auditor:", "Jonathan Hargreaves, CISA, CISSP"],
        ["Auditor Email:", "j.hargreaves@clearviewrisk.com"],
        ["Auditor Phone:", "415-882-3901"],
        ["Vendor Contact:", "Sarah Chen, Head of Compliance"],
        ["Vendor Email:", "s.chen@novatechsolutions.io"],
        ["Vendor Phone:", "650-447-2215"],
        ["Report Version:", "1.3 (Final)"],
        ["Classification:", "CONFIDENTIAL — Do not distribute"],
    ]
    meta_table = Table(meta_data, colWidths=[48 * mm, 120 * mm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#4a5568")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#1a202c")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LINEBELOW", (0, -1), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10 * mm))

    # ── 1. Executive Summary ───────────────────────────────────────────────────
    story.append(Paragraph("1.  Executive Summary", heading1_style))
    story.append(hr())
    story.append(Paragraph(
        "Clearview Risk Advisory Group was engaged by NovaTech Solutions Ltd. (\"the Vendor\") "
        "to assess the design and operating effectiveness of its information security controls "
        "for the period January 1 to December 31, 2025. The assessment was conducted against "
        "the AICPA Trust Service Criteria (SOC 2) with reference to ISO/IEC 27001:2022 and "
        "NIST Cybersecurity Framework 2.0.",
        body_style,
    ))
    story.append(Paragraph(
        "NovaTech Solutions operates a cloud-native SaaS platform serving 340 enterprise "
        "customers across financial services, healthcare, and government sectors. The platform "
        "processes personal data for approximately 2.4 million end-users under multiple data "
        "processing agreements governed by GDPR (EU) and CCPA (California).",
        body_style,
    ))
    story.append(Paragraph(
        "Overall, the Vendor demonstrated a <b>moderate level of security maturity</b> with "
        "effective controls in several domains. However, the assessment identified three "
        "significant control gaps and one critical finding requiring immediate remediation.",
        body_style,
    ))

    # ── 2. Vendor Profile ──────────────────────────────────────────────────────
    story.append(Paragraph("2.  Vendor Profile", heading1_style))
    story.append(hr())

    profile_data = [
        ["Legal Name:", "NovaTech Solutions Ltd."],
        ["Registered Address:", "88 Market Street, Suite 1200, San Francisco, CA 94105"],
        ["Company Reg. No.:", "C4812309 (Delaware)"],
        ["Employee Count:", "~480 FTE (as of Q4 2025)"],
        ["Annual Revenue:", "$38M (FY2024 audited)"],
        ["Primary Contact:", "Sarah Chen (Head of Compliance)"],
        ["Technical Contact:", "Marcus Okafor (VP Engineering)"],
        ["Billing Contact:", "Rachel Simmons (Finance Director)"],
        ["Banking Institution:", "First Pacific Business Bank, San Francisco"],
        ["Account (Last 4):", "****4821"],
    ]
    pt = Table(profile_data, colWidths=[50 * mm, 118 * mm])
    pt.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#4a5568")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [colors.HexColor("#f7fafc"), colors.HexColor("#ffffff")]),
        ("LINEBELOW", (0, -1), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
    ]))
    story.append(pt)

    # ── 3. Scope ───────────────────────────────────────────────────────────────
    story.append(Paragraph("3.  Scope of Assessment", heading1_style))
    story.append(hr())
    story.append(Paragraph(
        "The following systems and environments were included in scope for this assessment:",
        body_style,
    ))
    scope_items = [
        ("Production environment", "AWS us-east-1 and eu-west-1 regions; VPC 10.14.0.0/16"),
        ("Primary application servers", "api-prod-01.novatech.internal through api-prod-06.novatech.internal"),
        ("Database tier", "PostgreSQL 16 cluster; primary at db-master.novatech.internal (10.14.22.15)"),
        ("Authentication gateway", "Keycloak 24.x; auth.novatech.internal"),
        ("CI/CD pipeline", "GitHub Actions + ArgoCD; Kubernetes 1.30 (EKS)"),
        ("Security tooling", "Wiz, Datadog SIEM, Snyk, AWS GuardDuty"),
    ]
    scope_data = [["Component", "Detail"]] + [[k, v] for k, v in scope_items]
    st = Table(scope_data, colWidths=[55 * mm, 113 * mm])
    st.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#edf2f7")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#2d3748")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#f7fafc"), colors.HexColor("#ffffff")]),
    ]))
    story.append(st)

    # ── 4. Access Controls ─────────────────────────────────────────────────────
    story.append(Paragraph("4.  Access Management", heading1_style))
    story.append(hr())
    story.append(Paragraph(
        "NovaTech implements role-based access control (RBAC) across all production systems "
        "using an internal identity provider (Keycloak) federated with Okta for SSO. Privileged "
        "access is managed through HashiCorp Vault and requires approval from a second engineer "
        "before access is granted.",
        body_style,
    ))
    story.append(Paragraph(
        "<b>4.1  Multi-Factor Authentication</b>", heading2_style,
    ))
    story.append(Paragraph(
        "MFA is enforced for all employees accessing production systems via Okta Verify (TOTP) "
        "or hardware security keys (YubiKey 5). During the assessment period, 97.3% of production "
        "access events were verified with a second factor. The remaining 2.7% relate to automated "
        "service accounts using short-lived certificates issued by Vault PKI.",
        body_style,
    ))
    story.append(Paragraph(
        "<b>Finding AC-01 (High):</b> Three privileged service accounts were found to use "
        "long-lived AWS access keys rather than IAM roles with instance profiles. One of these "
        "keys (AKIA3XKPQLM7NRTZ8VWD) was last rotated 427 days ago, exceeding the 90-day "
        "rotation policy by a significant margin. These credentials were stored in a "
        "GitHub Actions environment variable rather than AWS Secrets Manager.",
        body_style,
    ))

    # ── 5. Encryption ──────────────────────────────────────────────────────────
    story.append(Paragraph("5.  Encryption and Key Management", heading1_style))
    story.append(hr())
    story.append(Paragraph(
        "All data at rest is encrypted using AES-256-GCM via AWS KMS. Customer data stored "
        "in the primary PostgreSQL cluster uses column-level encryption for PII fields, with "
        "key rotation occurring annually. TLS 1.3 is enforced for all inbound connections; "
        "TLS 1.2 is still permitted on legacy API endpoints for three enterprise customers "
        "under a documented exception (EX-2024-017, expires March 2026).",
        body_style,
    ))
    story.append(Paragraph(
        "The certificate authority for internal mTLS is managed by Vault PKI. The root CA "
        "certificate (SHA-256: e3b0c44298fc1c149afb4c8996fb924 27ae41e4649b934ca495991b) "
        "was issued in 2021 with a 10-year validity period.",
        body_style,
    ))
    story.append(Paragraph(
        "<b>Finding ENC-01 (Medium):</b> Two S3 buckets used for temporary file processing "
        "(novatech-tmp-uploads, novatech-batch-jobs) were found to have SSE-S3 encryption "
        "rather than the required SSE-KMS. While data is encrypted at rest, this prevents "
        "customer-managed key rotation and audit trail for key usage.",
        body_style,
    ))

    # ── 6. Personnel ───────────────────────────────────────────────────────────
    story.append(Paragraph("6.  Personnel Security", heading1_style))
    story.append(hr())
    story.append(Paragraph(
        "All employees undergo background screening prior to joining. The process is managed "
        "by HireRight and includes criminal record checks, employment history verification, and "
        "education confirmation. Employees with access to PII or financial systems undergo "
        "enhanced screening including credit checks.",
        body_style,
    ))
    story.append(Paragraph(
        "Employee security awareness training is delivered quarterly through KnowBe4. "
        "The Q3 2025 phishing simulation recorded a 6.2% click-through rate, down from "
        "11.4% in Q3 2024.",
        body_style,
    ))

    # Key personnel table (with embedded PII naturally)
    story.append(Paragraph("Key Personnel with Privileged Access:", label_style))
    kp_data = [
        ["Name", "Role", "Hire Date", "MFA Status", "Access Level"],
        ["Sarah Chen", "Head of Compliance", "2021-03-15", "YubiKey", "Read-only prod"],
        ["Marcus Okafor", "VP Engineering", "2019-08-01", "Okta TOTP", "Full admin"],
        ["Daniel Reeves", "Security Engineer", "2022-11-10", "YubiKey", "Security tooling"],
        ["Emily Kowalski", "DBA Lead", "2020-06-22", "Okta TOTP", "DB admin (prod)"],
        ["Priya Nair", "Cloud Architect", "2023-01-30", "YubiKey", "Infra admin"],
    ]
    kp_table = Table(kp_data, colWidths=[38 * mm, 45 * mm, 25 * mm, 25 * mm, 35 * mm])
    kp_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#edf2f7")),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#f7fafc"), colors.HexColor("#ffffff")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(kp_table)

    # ── 7. Incident Response ───────────────────────────────────────────────────
    story.append(Paragraph("7.  Incident Response", heading1_style))
    story.append(hr())
    story.append(Paragraph(
        "NovaTech maintains a documented Incident Response Plan (IRP v3.2, last reviewed "
        "September 2025) aligned with NIST SP 800-61r2. The Security Operations team is "
        "on-call 24/7 via PagerDuty. SIEM alerts are triaged using Datadog Security "
        "Management with a target P1 response time of 15 minutes.",
        body_style,
    ))
    story.append(Paragraph(
        "During the assessment period, three security incidents were recorded: two low-severity "
        "events (credential stuffing attempts blocked by WAF) and one medium-severity event "
        "(unauthorised API enumeration on a staging endpoint, resolved within 4 hours). "
        "No customer data was accessed or exfiltrated in any incident.",
        body_style,
    ))
    story.append(Paragraph(
        "<b>Finding IR-01 (Low):</b> The incident response runbook for DDoS events references "
        "an obsolete contact at the CDN provider (Cloudflare account ID 8a2f91dc). The "
        "dedicated support contact changed in Q2 2025 but the runbook was not updated. "
        "This does not represent a material gap but should be remediated within 30 days.",
        body_style,
    ))

    # ── 8. Subprocessors ───────────────────────────────────────────────────────
    story.append(Paragraph("8.  Subprocessors and Fourth-Party Risk", heading1_style))
    story.append(hr())
    story.append(Paragraph(
        "NovaTech engages 14 subprocessors for the delivery of its services. "
        "Data processing agreements (DPAs) are in place with all subprocessors. "
        "Annual security reviews are conducted for critical subprocessors.",
        body_style,
    ))
    sp_data = [
        ["Subprocessor", "Service", "Data Transferred", "DPA Status"],
        ["Amazon Web Services", "Cloud infrastructure", "All categories", "Active (2025-12)"],
        ["Snowflake Inc.", "Analytics data warehouse", "Aggregated/anonymised", "Active (2025-09)"],
        ["SendGrid (Twilio)", "Transactional email", "Name, email address", "Active (2025-06)"],
        ["Stripe Inc.", "Payment processing", "Payment card data", "Active (2025-11)"],
        ["Datadog Inc.", "Observability / SIEM", "Log data, metadata", "Active (2025-08)"],
    ]
    spt = Table(sp_data, colWidths=[42 * mm, 40 * mm, 45 * mm, 41 * mm])
    spt.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#edf2f7")),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#f7fafc"), colors.HexColor("#ffffff")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(spt)

    # ── 9. Data Protection ─────────────────────────────────────────────────────
    story.append(Paragraph("9.  Data Protection and Privacy", heading1_style))
    story.append(hr())
    story.append(Paragraph(
        "NovaTech processes personal data under GDPR as a Data Processor. The legal basis for "
        "processing is contractual necessity (Article 6(1)(b)) for all customer-facing services. "
        "A Data Protection Officer (DPO) has been appointed: Dr. Aisha Mensah "
        "(dpo@novatechsolutions.io; +44 20 7946 0312). Data subject requests are handled within "
        "30 days via the privacy portal at privacy.novatechsolutions.io.",
        body_style,
    ))
    story.append(Paragraph(
        "Customer PII processed by the platform includes: full name, email address, IP address, "
        "device identifiers, and — for financial services customers — national ID numbers and "
        "bank account details. The retention period for active customer data is the duration of "
        "the contract plus 36 months. Upon contract termination, data is purged within 90 days "
        "following a verified deletion confirmation.",
        body_style,
    ))

    # Sample data from customer support DB (realistic PII in context)
    story.append(Paragraph("Sample record from customer onboarding system (test environment):", label_style))
    sample_data = [
        ["Field", "Sample Value (Non-Production)"],
        ["Full Name", "James Whitmore"],
        ["Email", "j.whitmore@example-enterprise.com"],
        ["National ID", "SSN: 204-56-7891"],
        ["Phone", "212-555-0147"],
        ["IBAN", "GB82 WEST 1234 5698 7654 32"],
        ["Payment Method", "Visa ····4532 (exp 09/27)"],
        ["Account Created", "2024-04-18"],
    ]
    sd = Table(sample_data, colWidths=[55 * mm, 113 * mm])
    sd.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fff5f5")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#c53030")),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#fffaf0"), colors.HexColor("#ffffff")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(sd)
    story.append(Paragraph(
        "Note: The above record is from the non-production test environment and uses "
        "synthetic data generated by the QA team for integration testing purposes.",
        small_style,
    ))

    # ── 10. Findings Summary ───────────────────────────────────────────────────
    story.append(Paragraph("10.  Findings Summary", heading1_style))
    story.append(hr())
    findings_data = [
        ["Finding ID", "Domain", "Severity", "Status", "Remediation Target"],
        ["AC-01", "Access Management", "High", "Open", "2025-11-30"],
        ["ENC-01", "Encryption", "Medium", "In Progress", "2025-12-15"],
        ["IR-01", "Incident Response", "Low", "Open", "2025-12-01"],
    ]
    ft = Table(findings_data, colWidths=[22 * mm, 42 * mm, 22 * mm, 28 * mm, 54 * mm])
    ft.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#edf2f7")),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("TEXTCOLOR", (1, 2), (1, 2), colors.HexColor("#c53030")),  # High = red
        ("TEXTCOLOR", (1, 3), (1, 3), colors.HexColor("#d69e2e")),  # Medium = amber
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#f7fafc"), colors.HexColor("#ffffff")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(ft)

    # ── Signature block ────────────────────────────────────────────────────────
    story.append(Spacer(1, 12 * mm))
    story.append(hr())
    sig_data = [
        ["Prepared by:", "Jonathan Hargreaves, CISA, CISSP"],
        ["Organisation:", "Clearview Risk Advisory Group"],
        ["Date:", "October 11, 2025"],
        ["Reviewed by:", "Sarah Chen, Head of Compliance, NovaTech Solutions Ltd."],
    ]
    sig_table = Table(sig_data, colWidths=[35 * mm, 133 * mm])
    sig_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#4a5568")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(sig_table)

    doc.build(story)
    return output_path


if __name__ == "__main__":
    p = make_realistic_pdf(Path("."))
    print(f"Generated: {p}")
