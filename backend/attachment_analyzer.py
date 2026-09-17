"""NETRA-Mail static attachment analyzer.

Never executes attachment content. Performs bounded metadata, filename,
magic-byte, hashing, archive and embedded-URL inspection.
"""
from __future__ import annotations

import hashlib
import io
import math
import os
import re
import zipfile
from typing import Any, Dict, List


class AttachmentAnalyzer:
    CRITICAL_EXTENSIONS = {
        ".exe", ".scr", ".pif", ".com", ".dll", ".sys", ".cpl",
        ".msi", ".msp", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
        ".bat", ".cmd", ".ps1", ".psm1", ".hta", ".lnk", ".jar", ".reg",
    }
    HIGH_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".html", ".htm", ".svg"}
    ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}
    SUSPICIOUS_NAME_TERMS = {
        "invoice", "payment", "refund", "receipt", "salary", "payroll", "password",
        "verify", "verification", "update", "security", "urgent", "document", "scan",
    }
    EXECUTABLE_MAGICS = (
        (b"MZ", "PE executable"),
        (b"\x7fELF", "ELF executable"),
        (b"\xca\xfe\xba\xbe", "Mach-O executable"),
        (b"\xcf\xfa\xed\xfe", "Mach-O executable"),
        (b"\xfe\xed\xfa\xcf", "Mach-O executable"),
    )

    @staticmethod
    def _ext(filename: str) -> str:
        return os.path.splitext((filename or "").lower().strip())[1]

    @staticmethod
    def _double_extension(filename: str) -> bool:
        base = os.path.basename(filename or "").lower()
        parts = base.split(".")
        if len(parts) < 3:
            return False
        return ("." + parts[-1]) in (AttachmentAnalyzer.CRITICAL_EXTENSIONS | AttachmentAnalyzer.HIGH_EXTENSIONS)

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in counts if c)

    @classmethod
    def _magic(cls, data: bytes) -> str | None:
        for magic, label in cls.EXECUTABLE_MAGICS:
            if data.startswith(magic):
                return label
        if data.startswith(b"PK\x03\x04"):
            return "ZIP/OOXML archive"
        if data.startswith(b"%PDF-"):
            return "PDF document"
        if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return "OLE compound document"
        if data.startswith((b"<!DOCTYPE html", b"<html", b"<HTML")):
            return "HTML document"
        return None

    @classmethod
    def _archive(cls, data: bytes, max_members: int = 500) -> tuple[List[Dict[str, Any]], List[str], bool, List[str]]:
        members: List[Dict[str, Any]] = []
        reasons: List[str] = []
        urls: List[str] = []
        encrypted = False
        remaining_bytes = 2 * 1024 * 1024
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                infos = zf.infolist()
                if len(infos) > max_members:
                    reasons.append(f"Archive contains more than {max_members} members; nested inspection truncated.")
                    infos = infos[:max_members]
                for info in infos:
                    name = info.filename[:1024]
                    is_enc = bool(info.flag_bits & 0x1)
                    encrypted = encrypted or is_enc
                    ext = cls._ext(name)
                    item = {"filename": name, "size_bytes": int(info.file_size), "is_directory": info.is_dir(), "encrypted": is_enc}
                    if ext in cls.CRITICAL_EXTENSIONS:
                        reasons.append(f"Archive contains executable/script member: {name}")
                    elif ext in cls.HIGH_EXTENSIONS:
                        reasons.append(f"Archive contains high-risk document/web member: {name}")
                    members.append(item)
                    oversized = info.file_size > remaining_bytes or info.file_size > 512 * 1024
                    high_ratio = info.file_size > max(info.compress_size, 1) * 100
                    if oversized or high_ratio:
                        reasons.append("Archive content inspection limited by decompression size or compression-ratio budget.")
                    if not info.is_dir() and not is_enc and not oversized and not high_ratio:
                        try:
                            with zf.open(info) as member:
                                content = member.read(min(remaining_bytes, 512 * 1024) + 1)
                            remaining_bytes -= len(content)
                            if len(content) > 512 * 1024 or remaining_bytes < 0:
                                reasons.append("Archive content exceeded the decompression budget.")
                                continue
                            urls.extend(re.findall(r"https?://[^\s<>\"']+", content.decode("utf-8", errors="ignore"))[:20])
                        except Exception:
                            pass
                if encrypted:
                    reasons.append("Password-protected/encrypted archive member detected; content cannot be fully inspected safely.")
        except (zipfile.BadZipFile, OSError, ValueError):
            pass
        return members, sorted(set(urls))[:100], encrypted, reasons

    @classmethod
    def _analyze_one(cls, item: Dict[str, Any]) -> Dict[str, Any]:
        filename = str(item.get("filename") or item.get("name") or "inline-resource")
        content_type = str(item.get("content_type") or item.get("mime_type") or "application/octet-stream").lower()
        size = int(item.get("size_bytes") or item.get("size") or 0)
        data = item.get("content") or item.get("payload") or b""
        if isinstance(data, str):
            data = data.encode("utf-8", errors="ignore")
        if not isinstance(data, bytes):
            data = b""

        ext = cls._ext(filename)
        reasons: List[str] = []
        severity = "LOW"
        score = 0
        magic = cls._magic(data) or str(item.get("magic_signature") or "") or None
        double_ext = cls._double_extension(filename)
        hidden_ext = filename.startswith(".") and "." in filename[1:]

        if ext in cls.CRITICAL_EXTENSIONS:
            score += 80; severity = "CRITICAL"
            reasons.append(f"Dangerous executable/script attachment extension: {ext}")
        elif ext in cls.HIGH_EXTENSIONS:
            score += 55; severity = "HIGH"
            if ext in {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam"}:
                reasons.append("Macro-enabled Office document detected; macros can execute code when enabled.")
            else:
                reasons.append(f"High-risk attachment type: {ext}")
        elif ext in cls.ARCHIVE_EXTENSIONS:
            score += 25; severity = "MEDIUM"
            reasons.append(f"Archive attachment detected: {ext}")

        if double_ext:
            score += 25
            severity = "CRITICAL" if severity in {"LOW", "MEDIUM", "HIGH"} else severity
            reasons.append("Double-extension filename may disguise a dangerous file type.")
        if hidden_ext:
            score += 10
            reasons.append("Hidden/dot-prefixed attachment filename detected.")

        name_lower = filename.lower()
        matched_terms = [t for t in cls.SUSPICIOUS_NAME_TERMS if t in name_lower]
        if matched_terms and ext in cls.CRITICAL_EXTENSIONS | cls.HIGH_EXTENSIONS:
            score += 10
            reasons.append("Filename contains contextually suspicious delivery terms: " + ", ".join(sorted(matched_terms)))

        if magic:
            if "executable" in magic:
                score = max(score, 90); severity = "CRITICAL"
                reasons.append(f"File signature indicates {magic}.")
            elif magic == "OLE compound document" and ext in {".doc", ".xls", ".ppt"}:
                score += 10
                reasons.append("Legacy Office OLE document detected; embedded active content is possible.")

        declared_vs_magic = False
        if magic == "PE executable" and ext not in {".exe", ".scr", ".dll", ".sys", ".cpl", ".ocx"}:
            declared_vs_magic = True; score = max(score, 90); severity = "CRITICAL"
            reasons.append("MIME/filename does not match executable file signature.")
        elif magic == "PDF document" and ext not in {".pdf"}:
            declared_vs_magic = True; score = max(score, 70); severity = "HIGH"
            reasons.append("Filename extension does not match PDF file signature.")
        elif magic == "PE executable" and ext == ".pdf":
            declared_vs_magic = True; score = max(score, 90); severity = "CRITICAL"
            reasons.append("Attachment is declared as PDF but its file signature is a Windows executable.")
        elif magic == "HTML document" and ext not in {".html", ".htm", ".svg"}:
            declared_vs_magic = True; score = max(score, 60); severity = "HIGH"
            reasons.append("Filename extension does not match HTML content signature.")

        archive_members: List[Dict[str, Any]] = []
        embedded_urls: List[str] = []
        encrypted = False
        if ext in cls.ARCHIVE_EXTENSIONS or content_type in {"application/zip", "application/x-7z-compressed", "application/x-rar-compressed"} or data.startswith(b"PK\x03\x04") or magic == "ZIP/OOXML archive":
            archive_members, embedded_urls, encrypted, archive_reasons = cls._archive(data)
            reasons.extend(archive_reasons)
            if any(cls._ext(x.get("filename", "")) in cls.CRITICAL_EXTENSIONS for x in archive_members):
                score = max(score, 90); severity = "CRITICAL"
            elif archive_members:
                score = max(score, 40); severity = "MEDIUM" if score < 50 else severity
            elif magic == "ZIP/OOXML archive" or ext in cls.ARCHIVE_EXTENSIONS:
                score = max(score, 40); severity = "MEDIUM" if score < 50 else severity
                reasons.append("Archive container detected; static member inspection was unavailable or the archive structure could not be parsed.")

        if not data and item.get("analysis_skipped"):
            reasons.append(str(item.get("skip_reason") or "Attachment content was not available for static inspection."))
        image_analysis = item.get("image_analysis") or {}
        qr_payloads = image_analysis.get("qr_payloads", [])[:20]
        if qr_payloads:
            reasons.append("Image contains a QR code; decoded targets were inspected as URLs when applicable.")
            score = max(score, 25)
            severity = "MEDIUM" if severity == "LOW" else severity

        sha256 = item.get("sha256") or (hashlib.sha256(data).hexdigest() if data else None)
        entropy = cls._entropy(data[:2 * 1024 * 1024]) if data else 0.0
        if entropy >= 7.5 and size >= 4096 and ext in cls.CRITICAL_EXTENSIONS:
            reasons.append("High-entropy executable/script content detected.")
            score = max(score, 90); severity = "CRITICAL"

        if encrypted and severity == "LOW":
            severity = "MEDIUM"

        return {
            "filename": filename,
            "extension": ext,
            "content_type": content_type,
            "declared_mime_type": str(item.get("declared_mime_type") or content_type),
            "size_bytes": size,
            "sha256": sha256,
            "magic_signature": magic,
            "mime_mismatch": declared_vs_magic,
            "double_extension": double_ext,
            "hidden_extension": hidden_ext,
            "entropy": round(entropy, 4),
            "archive": bool(archive_members or ext in cls.ARCHIVE_EXTENSIONS),
            "encrypted_archive": encrypted,
            "archive_members": archive_members,
            "embedded_urls": embedded_urls,
            "image_analysis": {"available": bool(image_analysis.get("available")), "qr_payloads": qr_payloads,
                "ocr_text_present": bool(image_analysis.get("ocr_text")), "ocr_available": bool(image_analysis.get("ocr_available")),
                "limitations": image_analysis.get("limitations", [])},
            "reasons": list(dict.fromkeys(reasons)),
            "score": min(100, score),
            "risk_level": severity,
            "suspicious": score >= 35,
            "analysis_skipped": bool(item.get("analysis_skipped", False)),
        }

    @classmethod
    def analyze(cls, attachments: List[Dict[str, Any]] | None) -> Dict[str, Any]:
        attachments = attachments or []
        findings = []
        for item in attachments:
            item = item if isinstance(item, dict) else {}
            # Parsed attachments already carry worker output; do not inspect twice.
            if isinstance(item.get("static_analysis"), dict):
                findings.append(item["static_analysis"])
                continue
            data = item.get("content") or item.get("payload")
            if data:
                from backend.inspection_client import inspect_attachment
                if isinstance(data, str):
                    data = data.encode("utf-8", errors="ignore")
                inspected = inspect_attachment(data, item.get("filename", item.get("name", "")),
                    item.get("content_type", item.get("mime_type", "application/octet-stream")))
                if inspected.get("available") and isinstance(inspected.get("static_analysis"), dict):
                    findings.append(inspected["static_analysis"])
                    continue
                item = {k: v for k, v in item.items() if k not in {"content", "payload"}}
                item.update(analysis_skipped=True, skip_reason=inspected.get("error", "inspection_unavailable"))
            # Metadata-only fallback preserves filename/magic findings and marks
            # missing content inspection explicitly; it never decodes a file.
            findings.append(cls._analyze_one(item))
        from backend.attachment_reputation import apply_reputation
        findings = [apply_reputation(dict(x)) for x in findings]
        highest = max((x["score"] for x in findings), default=0)
        suspicious = sum(1 for x in findings if x["suspicious"])
        reasons = []
        for x in findings:
            reasons.extend(x["reasons"])
        if highest >= 75:
            risk = "CRITICAL"
        elif highest >= 50:
            risk = "HIGH"
        elif highest >= 25:
            risk = "MEDIUM"
        else:
            risk = "LOW"
        return {
            "attachments": findings,
            "attachment_count": len(findings),
            "suspicious_attachment_count": suspicious,
            "score": highest,
            "risk_level": risk,
            "findings": list(dict.fromkeys(reasons)),
            "static_only": True,
            "execution_performed": False,
        }
