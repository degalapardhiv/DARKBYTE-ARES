from __future__ import annotations

import asyncio
import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from backend.core.config import get_settings
from backend.models.models import Assessment, Finding, Report, Target, User

REPORTING_DIR = Path(__file__).resolve().parents[2] / "reporting"
CONTENT_FONT = "Helvetica"
BOLD_FONT = "Helvetica-Bold"
MONO_FONT = "Courier"
for candidate, candidate_bold in [
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("/usr/share/fonts/dejavu/DejaVuSans.ttf", "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf"),
]:
    if Path(candidate).exists() and Path(candidate_bold).exists():
        pdfmetrics.registerFont(TTFont("AresSans", candidate))
        pdfmetrics.registerFont(TTFont("AresSans-Bold", candidate_bold))
        CONTENT_FONT = "AresSans"
        BOLD_FONT = "AresSans-Bold"
        break
for mono in [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
]:
    if Path(mono).exists():
        pdfmetrics.registerFont(TTFont("AresMono", mono))
        MONO_FONT = "AresMono"
        break

METHODOLOGY = {
    "recon": "Scoped public DNS queries, WHOIS metadata, certificate inspection and a bounded subdomain inventory. No zone transfer, brute-force or exploitation is performed.",
    "network": "A scoped TCP connect inventory with a hard host/port cap and conservative timeouts. Risky services are prioritized for review.",
    "web": "Non-destructive OWASP-aligned checks covering security headers, TLS, cookie flags and limited sensitive-file probes. Injection probes are lab-gated.",
    "vulnerability": "CVE identification using the NVD API with a bundled, clearly-labelled real-data snapshot for offline resilience. Scores use CVSS v3 base metrics.",
    "osint": "Passive public-source collection from DNS, WHOIS, certificate transparency and authorized public documents. Evidence hashes are retained without source files.",
    "password": "Local in-memory strength scoring and a bounded offline dictionary audit. Plaintext and hashes are omitted from persistence; no credential store is contacted.",
    "active_directory": "Read-only analysis of an operator-supplied AD configuration snapshot. No LDAP connection or authentication attempt is made.",
    "cloud": "Read-only review of an exported AWS/Azure/GCP configuration snapshot. The platform does not use or persist cloud credentials.",
    "api_security": "Safe GET/OPTIONS probes, security header review, anonymous exposure checks and limited CORS/rate-limit observations. No authorization bypass is attempted.",
    "red_team": "Tabletop attack-chain planning and detection-engineering exercises only. No malware, exploitation, credential theft or live adversary traffic is generated.",
}


def _safe_filename(value: str, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")[:80]
    return cleaned or fallback


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1
    return counts


def build_executive_summary(assessment: Assessment, target: Target, findings: list[Finding]) -> str:
    counts = severity_counts(findings)
    top = sorted(
        findings,
        key=lambda item: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(item.severity, 0),
        reverse=True,
    )[:3]
    lead = (
        f"DARKBYTE ARES completed a {assessment.module.replace('_', ' ')} assessment of "
        f"{target.name} ({target.value}) with an overall risk score of {assessment.risk_score:.1f}/100. "
        f"The assessment recorded {len(findings)} finding(s): {counts['critical']} critical, "
        f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low and {counts['info']} informational."
    )
    if top:
        lead += " Priority items: " + "; ".join(f"{item.title} ({item.severity})" for item in top) + "."
    if assessment.is_demo:
        lead = "Demonstration data only. " + lead
    lead += (
        " Remediate critical and high findings first, preserve the evidence trail, and schedule a scoped retest "
        "after controls are applied. This report does not assert exploitability beyond the evidence recorded."
    )
    return lead


def _assessment_payload(assessment: Assessment, target: Target, user: User | None) -> dict[str, Any]:
    return {
        "name": assessment.name,
        "module": assessment.module,
        "target_name": target.name,
        "target_value": target.value,
        "target_type": target.target_type,
        "environment": target.environment,
        "authorization_ref": target.authorization_ref,
        "authorized_by": target.authorized_by,
        "authorization_expires": (
            target.authorization_expires.isoformat() if target.authorization_expires else None
        ),
        "action": (target.allowed_actions or [""])[0] if target.allowed_actions else "scoped",
        "risk_score": assessment.risk_score,
        "status": assessment.status,
        "is_demo": assessment.is_demo,
        "created_by": user.name if user else "ARES system",
    }


def _finding_payload(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "cve_id": finding.cve_id,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "references": finding.references,
        "technique_ids": finding.technique_ids,
        "status": finding.status,
        "module": finding.module,
    }


def _write_html(payload: dict[str, Any], path: Path) -> None:
    env = Environment(
        loader=FileSystemLoader(str(REPORTING_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["tojson"] = lambda value, indent=None: json.dumps(value, indent=indent, default=str)
    template = env.get_template("template.html")
    html = template.render(**payload)
    path.write_text(html, encoding="utf-8")


def _pdf_styles():
    return {
        "brand": ParagraphStyle("brand", fontName=BOLD_FONT, fontSize=20, leading=24, textColor=colors.HexColor("#FFFFFF"), spaceAfter=6, tracking=4),
        "eyebrow": ParagraphStyle("eyebrow", fontName=MONO_FONT, fontSize=8, leading=11, textColor=colors.HexColor("#00E5FF"), spaceAfter=18, tracking=2),
        "title": ParagraphStyle("title", fontName=BOLD_FONT, fontSize=30, leading=35, textColor=colors.HexColor("#FFFFFF"), spaceAfter=14),
        "subtitle": ParagraphStyle("subtitle", fontName=CONTENT_FONT, fontSize=11, leading=17, textColor=colors.HexColor("#94A3B8"), spaceAfter=20),
        "h1": ParagraphStyle("h1", fontName=BOLD_FONT, fontSize=17, leading=22, textColor=colors.HexColor("#FFFFFF"), spaceBefore=18, spaceAfter=10),
        "h2": ParagraphStyle("h2", fontName=BOLD_FONT, fontSize=12, leading=16, textColor=colors.HexColor("#00E5FF"), spaceBefore=14, spaceAfter=7),
        "body": ParagraphStyle("body", fontName=CONTENT_FONT, fontSize=9.3, leading=14, textColor=colors.HexColor("#CBD5E1"), alignment=TA_LEFT, spaceAfter=7),
        "small": ParagraphStyle("small", fontName=CONTENT_FONT, fontSize=8, leading=11, textColor=colors.HexColor("#94A3B8"), spaceAfter=5),
        "code": ParagraphStyle("code", fontName=MONO_FONT, fontSize=7.4, leading=10.5, textColor=colors.HexColor("#94A3B8"), backColor=colors.HexColor("#070B11"), borderColor=colors.HexColor("#152131"), borderWidth=0.5, borderPadding=6, spaceBefore=5, spaceAfter=8),
        "severity": ParagraphStyle("severity", fontName=MONO_FONT, fontSize=8, leading=10, textColor=colors.HexColor("#00FF88")),
        "footer": ParagraphStyle("footer", fontName=MONO_FONT, fontSize=7, leading=9, textColor=colors.HexColor("#64748B")),
    }


def _draw_dark_page(canvas, doc):
    width, height = A4
    canvas.saveState()
    canvas.setFillColor(colors.HexColor("#080B12"))
    canvas.rect(0, 0, width, height, fill=1, stroke=0)
    canvas.setStrokeColor(colors.HexColor("#162334"))
    canvas.setLineWidth(0.5)
    canvas.line(22 * mm, 16 * mm, width - 22 * mm, 16 * mm)
    canvas.setFont(MONO_FONT, 6.5)
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.drawString(22 * mm, 11 * mm, "DARKBYTE ARES · AUTHORIZED ASSESSMENT")
    canvas.drawRightString(width - 22 * mm, 11 * mm, f"PAGE {doc.page}")
    canvas.setFillColor(colors.HexColor("#00E5FF"))
    canvas.rect(22 * mm, height - 12 * mm, 22 * mm, 1.2 * mm, fill=1, stroke=0)
    canvas.restoreState()


def _write_pdf(
    assessment_payload: dict[str, Any],
    report_meta: dict[str, Any],
    findings: list[dict[str, Any]],
    counts: dict[str, int],
    executive_summary: str,
    path: Path,
) -> None:
    styles = _pdf_styles()
    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=22 * mm,
        bottomMargin=22 * mm,
        title=report_meta["title"],
        author="DarkByteHunter",
        subject="DARKBYTE ARES security assessment",
    )
    story: list[Any] = []
    story.append(Paragraph("DARKBYTE ARES", styles["brand"]))
    story.append(Paragraph("ONE FRAMEWORK. COMPLETE RED TEAM OPERATIONS.", styles["eyebrow"]))
    if assessment_payload["is_demo"]:
        story.append(Paragraph("DEMONSTRATION DATASET — NOT A LIVE ASSESSMENT", styles["severity"]))
        story.append(Spacer(1, 8))
    story.append(Paragraph(escape(report_meta["title"]), styles["title"]))
    story.append(
        Paragraph(
            f"{escape(assessment_payload['target_name'])} · {escape(assessment_payload['target_value'])}<br/>"
            f"Module: {escape(assessment_payload['module'])} · Environment: {escape(assessment_payload['environment'])}",
            styles["subtitle"],
        )
    )
    meta_rows = [
        ["Risk score", f"{assessment_payload['risk_score']:.1f} / 100", "Findings", str(sum(counts.values()))],
        ["Authorization", assessment_payload["authorization_ref"], "Authorized by", assessment_payload["authorized_by"]],
        ["Generated", report_meta["generated_at"], "Prepared by", assessment_payload["created_by"]],
    ]
    meta_table = Table(meta_rows, colWidths=[30 * mm, 60 * mm, 30 * mm, 50 * mm])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0D1420")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#CBD5E1")),
                ("FONTNAME", (0, 0), (-1, -1), CONTENT_FONT),
                ("FONTNAME", (0, 0), (0, -1), MONO_FONT),
                ("FONTNAME", (2, 0), (2, -1), MONO_FONT),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#64748B")),
                ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor("#64748B")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#1B2B3D")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(Spacer(1, 10))
    story.append(meta_table)
    story.append(Spacer(1, 16))
    severity_table = Table(
        [[f"{level.upper()}\n{counts[level]}" for level in ("critical", "high", "medium", "low", "info")]],
        colWidths=[34 * mm] * 5,
    )
    severity_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0D1420")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#00E5FF")),
                ("FONTNAME", (0, 0), (-1, -1), MONO_FONT),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#1B2B3D")),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#1B2B3D")),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.append(severity_table)
    story.append(PageBreak())

    story.append(Paragraph("Executive summary", styles["h1"]))
    story.append(Paragraph(escape(executive_summary), styles["body"]))
    story.append(Paragraph("Authorization &amp; scope", styles["h1"]))
    expiry = assessment_payload.get("authorization_expires") or "no expiry recorded"
    story.append(
        Paragraph(
            f"Authorized by <b>{escape(assessment_payload['authorized_by'])}</b> under reference "
            f"<b>{escape(assessment_payload['authorization_ref'])}</b>. Scope action: "
            f"{escape(assessment_payload['action'])}. Authorization expiry: {escape(str(expiry))}. "
            "All checks were constrained by ARES scope validation, rate limits, timeouts and conservative concurrency.",
            styles["body"],
        )
    )
    story.append(Paragraph("Severity overview", styles["h1"]))
    story.append(
        Paragraph(
            " ".join(f"<b>{level.upper()}</b>: {counts[level]}" for level in counts),
            styles["body"],
        )
    )
    story.append(Paragraph("Methodology", styles["h1"]))
    story.append(Paragraph(escape(report_meta.get("methodology", "")), styles["body"]))
    story.append(PageBreak())

    story.append(Paragraph("Findings", styles["h1"]))
    if not findings:
        story.append(Paragraph("No findings were recorded for this assessment.", styles["body"]))
    for index, finding in enumerate(findings, start=1):
        story.append(
            Paragraph(
                f"{index}. {escape(finding['title'])} "
                f"<font color='#00FF88'>[{finding['severity'].upper()}]</font>",
                styles["h2"],
            )
        )
        story.append(
            Paragraph(
                f"CVSS: {finding.get('cvss_score') or 0:.1f} · CVE: {escape(finding.get('cve_id') or '—')} · "
                f"Status: {escape(finding['status'])} · Module: {escape(finding['module'])}",
                styles["small"],
            )
        )
        story.append(Paragraph(escape(finding["description"]), styles["body"]))
        evidence_json = json.dumps(finding.get("evidence", {}), indent=2, default=str)[:3500]
        story.append(Paragraph(escape(evidence_json).replace("\n", "<br/>"), styles["code"]))
        story.append(Paragraph(f"<b>Remediation:</b> {escape(finding['remediation'])}", styles["body"]))
        references = finding.get("references") or []
        if references:
            story.append(
                Paragraph(
                    "<b>References:</b> "
                    + " · ".join(
                        f"<link href='{escape(ref)}' color='#00E5FF'>{escape(ref[:120])}</link>"
                        for ref in references[:5]
                    ),
                    styles["small"],
                )
            )
        story.append(Spacer(1, 10))

    story.append(PageBreak())
    story.append(Paragraph("Handling &amp; next steps", styles["h1"]))
    story.append(
        Paragraph(
            "Treat this report as confidential to the target owner and authorized stakeholders. Prioritise critical and "
            "high findings, preserve evidence, and record compensating controls where full remediation is delayed. "
            "Schedule a re-test only after remediating changes have been validated in the target environment. "
            "ARES does not authorise testing outside the recorded target scope.",
            styles["body"],
        )
    )
    story.append(Paragraph("DARKBYTE ARES by DarkByteHunter", styles["h2"]))
    story.append(Paragraph("One framework. Complete red team operations.", styles["small"]))
    doc.build(story, onFirstPage=_draw_dark_page, onLaterPages=_draw_dark_page)


async def generate_report(
    db,
    *,
    assessment: Assessment,
    target: Target,
    findings: list[Finding],
    user: User | None,
    fmt: str,
    title: str | None = None,
) -> Report:
    settings = get_settings()
    reports_dir = Path(settings.reports_dir).resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_id = uuid.uuid4().hex
    safe_title = _safe_filename(title or f"{assessment.name}-{assessment.module}", "ares-report")
    filename = f"{safe_title}-{report_id[:8]}.{fmt}"
    path = (reports_dir / filename).resolve()
    if reports_dir not in path.parents:
        raise ValueError("Report path escaped the reports directory.")
    counts = severity_counts(findings)
    executive_summary = build_executive_summary(assessment, target, findings)
    generated_at = datetime.now(UTC).isoformat()
    report_title = title or f"{assessment.name} — {assessment.module.replace('_', ' ').title()} Assessment"
    assessment_payload = _assessment_payload(assessment, target, user)
    findings_payload = [_finding_payload(finding) for finding in findings]
    report_meta = {
        "id": report_id,
        "title": report_title,
        "format": fmt,
        "generated_at": generated_at,
        "generated_by": user.name if user else "ARES system",
        "executive_summary": executive_summary,
        "counts": counts,
        "methodology": METHODOLOGY.get(assessment.module, "Scoped, non-destructive assessment."),
        "is_demo": assessment.is_demo,
    }
    if fmt == "html":
        payload = {
            "report": report_meta,
            "assessment": assessment_payload,
            "findings": findings_payload,
            "counts": counts,
            "methodology": report_meta["methodology"],
        }
        await asyncio.to_thread(_write_html, payload, path)
    elif fmt == "json":
        payload = {
            "report": report_meta,
            "assessment": assessment_payload,
            "findings": findings_payload,
            "severity_counts": counts,
            "notice": "Authorized security assessment. Demo data is labelled is_demo=true.",
        }
        await asyncio.to_thread(path.write_text, json.dumps(payload, indent=2, default=str), "utf-8")
    elif fmt == "pdf":
        await asyncio.to_thread(
            _write_pdf,
            assessment_payload,
            report_meta,
            findings_payload,
            counts,
            executive_summary,
            path,
        )
    else:
        raise ValueError("Unsupported report format.")
    os.chmod(path, 0o640)
    report = Report(
        id=report_id,
        assessment_id=assessment.id,
        title=report_title,
        format=fmt,
        file_path=str(path),
        size_bytes=path.stat().st_size,
        status="ready",
        executive_summary=executive_summary,
        meta={
            "severity_counts": counts,
            "target": target.name,
            "target_value": target.value,
            "module": assessment.module,
            "risk_score": assessment.risk_score,
            "methodology": report_meta["methodology"],
            "generated_by": user.name if user else "ARES system",
            "authorization_ref": target.authorization_ref,
            "is_demo": assessment.is_demo,
        },
        is_demo=assessment.is_demo,
        created_by=user.id if user else assessment.created_by,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return report
