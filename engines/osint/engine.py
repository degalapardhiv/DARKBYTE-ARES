from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx
from PIL import ExifTags, Image
from pypdf import PdfReader

from backend.core.config import get_settings
from backend.services.cache import cache
from engines.base import EngineResult, FindingDraft, RunContext
from engines.common import SafeFetchError, read_bytes, sha256_hex
from engines.reconnaissance.engine import (
    analyze_email_security,
    dns_inventory,
    whois_lookup,
)

EXIF_LABELS = {v: k for k, v in ExifTags.TAGS.items()}


def _jsonable(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return value[:80].hex()
    if isinstance(value, (int, float, str, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in list(value.items())[:50]}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value[:50]]
    try:
        return str(value)[:500]
    except Exception:
        return None


def analyze_document_metadata(data: bytes, filename: str = "", content_type: str = "") -> dict[str, Any]:
    """Extract public document metadata without retaining the source bytes."""
    digest = sha256_hex(data)
    result: dict[str, Any] = {
        "filename": filename[:200],
        "content_type": content_type[:120],
        "sha256": digest,
        "size_bytes": len(data),
        "metadata": {},
        "privacy_flags": [],
        "parser": None,
    }
    lower = filename.lower()
    try:
        if content_type.startswith("image/") or lower.endswith((".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp")):
            image = Image.open(io.BytesIO(data))
            exif = image.getexif()
            metadata: dict[str, Any] = {"format": image.format, "width": image.width, "height": image.height}
            for tag_id, value in list(exif.items())[:80]:
                label = ExifTags.TAGS.get(tag_id, f"Tag{tag_id}")
                metadata[label] = _jsonable(value)
            gps = exif.get(34853)
            if gps:
                metadata["GPSInfo"] = _jsonable(gps)
                result["privacy_flags"].append("GPS coordinates present")
            for sensitive in ("Artist", "Copyright", "Software", "Make", "Model", "DateTimeOriginal", "UserComment"):
                if metadata.get(sensitive) not in (None, "", 0):
                    result["privacy_flags"].append(f"{sensitive} metadata present")
            result["metadata"] = metadata
            result["parser"] = "Pillow/EXIF"
        elif content_type == "application/pdf" or lower.endswith(".pdf"):
            reader = PdfReader(io.BytesIO(data))
            info = reader.metadata or {}
            metadata = {}
            for key, value in list(info.items())[:50]:
                metadata[str(key).lstrip("/")] = _jsonable(value)
            metadata["pages"] = len(reader.pages)
            result["metadata"] = metadata
            result["parser"] = "pypdf"
            for key in ("Author", "Creator", "Producer", "CreationDate", "ModDate"):
                if metadata.get(key):
                    result["privacy_flags"].append(f"{key} metadata present")
        elif lower.endswith((".docx", ".xlsx", ".pptx")):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if "docProps/core.xml" in archive.namelist():
                    raw = archive.read("docProps/core.xml")[:100_000]
                    text = raw.decode(errors="replace")
                    result["metadata"]["ooxml_core"] = text[:4000]
                    result["parser"] = "OOXML core properties"
                    for key in ("creator", "lastModifiedBy", "created", "modified"):
                        if f"<{key}" in text.lower():
                            result["privacy_flags"].append(f"{key} metadata present")
        else:
            result["metadata"] = {"note": "Unsupported document type; SHA-256 evidence recorded."}
            result["parser"] = "hash-only"
    except Exception as exc:
        result["error"] = f"Metadata extraction failed: {type(exc).__name__}"
    result["privacy_flags"] = sorted(set(result["privacy_flags"]))
    return result


async def crtsh_lookup(domain: str, timeout: float) -> dict[str, Any]:
    settings = get_settings()
    key = f"crtsh:{domain}"
    cached = await cache.get(key)
    if cached is not None:
        return {**cached, "cached": True}
    url = f"{settings.crtsh_url.rstrip('/')}/?q={quote('%25.' + domain)}&output=json"
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": "DARKBYTE-ARES/1.0 osint-evidence"},
        ) as client:
            response = await client.get(url)
            if response.status_code >= 400:
                return {"available": False, "error": f"HTTP {response.status_code}", "names": [], "certificates": 0}
            data = response.json()
    except Exception as exc:
        return {"available": False, "error": type(exc).__name__, "names": [], "certificates": 0}
    names: set[str] = set()
    for row in data if isinstance(data, list) else []:
        for name in str(row.get("name_value", "")).splitlines():
            clean = name.strip().lower().lstrip("*.").rstrip(".")
            if clean.endswith("." + domain) or clean == domain:
                names.add(clean)
    result = {
        "available": True,
        "names": sorted(names)[:300],
        "unique_names": len(names),
        "certificates": len(data) if isinstance(data, list) else 0,
        "source": "crt.sh certificate transparency",
    }
    await cache.set(key, result, ttl=6 * 3600)
    return result


def _evidence_hash(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


async def run(context: RunContext, config: dict[str, Any]) -> EngineResult:
    target = context.target
    domain = str(target["value"]).lower().rstrip(".")
    timeout = float(config.get("timeout", 10.0))
    result = EngineResult()
    evidence: list[dict[str, Any]] = []

    dns_result: dict[str, Any] = {"records": {}, "errors": {}}
    if config.get("include_dns", True):
        dns_result = await dns_inventory(domain, timeout)
        records = dns_result["records"]
        try:
            import dns.asyncresolver

            resolver = dns.asyncresolver.Resolver(configure=True)
            answer = await resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=timeout)
            records["_DMARC_TXT"] = ["".join(str(part) for part in item.strings) for item in answer]
        except Exception:
            records["_DMARC_TXT"] = []
        result.findings.extend(analyze_email_security(records))
        evidence.append(
            {
                "type": "dns_inventory",
                "source": "authoritative DNS via system resolver",
                "collected_at": datetime.now(UTC).isoformat(),
                "sha256": _evidence_hash(records),
                "summary": {key: len(value) for key, value in records.items()},
            }
        )

    whois_result: dict[str, Any] = {}
    if config.get("include_whois", True):
        whois_result = await whois_lookup(domain, timeout)
        if whois_result.get("available"):
            evidence.append(
                {
                    "type": "whois_registration",
                    "source": "public WHOIS",
                    "collected_at": datetime.now(UTC).isoformat(),
                    "sha256": _evidence_hash(whois_result),
                    "summary": {
                        "registrar": whois_result.get("registrar"),
                        "creation_date": whois_result.get("creation_date"),
                        "expiration_date": whois_result.get("expiration_date"),
                    },
                }
            )

    ct: dict[str, Any] = {"available": False, "names": [], "unique_names": 0, "certificates": 0}
    if config.get("include_crtsh", True):
        ct = await crtsh_lookup(domain, timeout)
        if ct.get("available"):
            evidence.append(
                {
                    "type": "certificate_transparency",
                    "source": "crt.sh",
                    "collected_at": datetime.now(UTC).isoformat(),
                    "sha256": _evidence_hash(ct.get("names", [])),
                    "summary": {"certificates": ct["certificates"], "names": ct["unique_names"]},
                }
            )
            if ct.get("unique_names", 0) > 0:
                result.findings.append(
                    FindingDraft(
                        title="Public certificate transparency expands asset inventory",
                        description=(
                            f"{ct['unique_names']} unique DNS names were observed in certificate transparency logs. "
                            "Certificate transparency is public by design; review the inventory for forgotten or "
                            "unauthorized assets."
                        ),
                        severity="info",
                        evidence={"sample": ct["names"][:25], "certificates": ct["certificates"], "source": "crt.sh"},
                        remediation="Reconcile discovered names with the approved asset inventory and decommission stale services.",
                        references=["https://certificate.transparency.dev/"],
                        technique_ids=["T1596", "T1590"],
                    )
                )

    metadata_result: dict[str, Any] = {}
    if config.get("document_url"):
        url = config["document_url"]
        try:
            data, meta = await read_bytes(url, context, max_bytes=5_000_000, timeout=timeout)
            metadata_result = analyze_document_metadata(data, url.split("/")[-1][:200], meta.get("content_type", ""))
            metadata_result["source_url"] = url
            evidence.append(
                {
                    "type": "document_metadata",
                    "source": url,
                    "collected_at": datetime.now(UTC).isoformat(),
                    "sha256": metadata_result.get("sha256"),
                    "summary": {"size_bytes": len(data), "content_type": meta.get("content_type", "")},
                }
            )
            if metadata_result.get("privacy_flags"):
                severity = "medium" if any("GPS" in flag for flag in metadata_result["privacy_flags"]) else "low"
                result.findings.append(
                    FindingDraft(
                        title="Public document exposes descriptive metadata",
                        description=(
                            "The authorized public document includes metadata such as authorship, software, timestamps "
                            "or geolocation. This can aid reconnaissance and reveal internal identifiers."
                        ),
                        severity=severity,
                        cvss_score=4.3 if severity == "medium" else 3.1,
                        evidence={
                            "source_url": url,
                            "sha256": metadata_result.get("sha256"),
                            "flags": metadata_result.get("privacy_flags", []),
                        },
                        remediation="Strip metadata before publishing documents and enforce a publication sanitisation workflow.",
                        references=["https://owasp.org/www-community/attacks/Information_exposure_through_query_strings_in_url"],
                        technique_ids=["T1592"],
                    )
                )
        except (SafeFetchError, ValueError) as exc:
            metadata_result = {"error": str(exc)}
        except Exception as exc:
            metadata_result = {"error": f"Metadata fetch failed: {type(exc).__name__}"}

    if not result.findings:
        result.findings.append(
            FindingDraft(
                title="OSINT collection completed without notable exposure",
                description="Public-source checks completed. No email authentication or metadata issues met the reporting threshold.",
                severity="info",
                evidence={"sources": ["DNS", "WHOIS", "crt.sh"]},
                remediation="Continue periodic external asset discovery and compare results to the approved inventory.",
            )
        )

    result.summary = {
        "domain": domain,
        "dns": dns_result,
        "whois": whois_result,
        "certificate_transparency": ct,
        "metadata": metadata_result,
        "evidence": evidence,
        "evidence_count": len(evidence),
        "sources": ["public DNS", "public WHOIS", "certificate transparency", "authorized public document"],
        "notice": "Passive/public sources only. Evidence hashes are recorded without retaining source document bytes.",
    }
    return result.finalize("osint")
