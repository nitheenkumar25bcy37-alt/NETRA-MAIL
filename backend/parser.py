from __future__ import annotations

import hashlib
import io
import ipaddress
import os
import re
import time
import zipfile
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any, Dict, List
from urllib.parse import urljoin


class _SafeHTMLExtractor(HTMLParser):
    """Collect HTML metadata without rendering or executing the document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible_parts: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.hidden_elements: List[Dict[str, str]] = []
        self.links: List[Dict[str, str]] = []
        self.inline_images: List[Dict[str, str]] = []
        self._form: Dict[str, Any] | None = None
        self._form_text: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()

        if tag == "form":
            self._form = {
                "action": attributes.get("action", ""),
                "method": attributes.get("method", "get"),
                "fields": [],
            }
            self._form_text = []

        elif tag in {"input", "button", "select", "textarea"} and self._form is not None:
            field = {
                key: attributes.get(key, "")
                for key in ("name", "type", "value", "id")
                if attributes.get(key, "")
            }
            self._form["fields"].append(field)

        if attributes.get("type", "").lower() == "hidden" or "hidden" in attributes:
            self.hidden_elements.append(
                {
                    "tag": tag,
                    "name": attributes.get("name", ""),
                    "id": attributes.get("id", ""),
                    "value": attributes.get("value", ""),
                }
            )

        if tag == "a" and attributes.get("href"):
            self.links.append({"href": attributes["href"], "visible_text": ""})

        if tag == "img" and attributes.get("src"):
            self.inline_images.append(
                {
                    "src": attributes["src"],
                    "alt": attributes.get("alt", ""),
                    "content_id": attributes.get("cid", ""),
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form is not None:
            self._form["visible_text"] = " ".join(self._form_text).strip()
            self.forms.append(self._form)
            self._form = None
            self._form_text = []

    def handle_data(self, data: str) -> None:
        text = " ".join(data.split())
        if not text:
            return

        self.visible_parts.append(text)

        if self._form is not None:
            self._form_text.append(text)

        if self.links:
            self.links[-1]["visible_text"] = (
                self.links[-1]["visible_text"] + " " + text
            ).strip()


class ForensicEmailParser:
    URL_REGEX = re.compile(r"""(?:https?://|www\.)[^\s<>"']+""", re.I)
    IP_REGEX = re.compile(
        r"(?<![A-Za-z0-9_])(?:(?:\d{1,3}\.){3}\d{1,3}|\[?[0-9A-Fa-f:]{2,}\]?)(?![A-Za-z0-9_])"
    )

    # Defensive upper bounds remain in effect even if an environment variable
    # is accidentally configured to an unsafe value.
    MAX_EMAIL_SIZE_BYTES = max(
        1,
        min(int(os.getenv("NETRA_MAX_EMAIL_SIZE_MB", "10")), 50) * 1024 * 1024,
    )
    MAX_TEXT_SIZE_BYTES = max(
        1,
        min(int(os.getenv("NETRA_MAX_TEXT_SIZE_KB", "512")), 5120) * 1024,
    )
    MAX_MIME_PARTS = max(
        1, min(int(os.getenv("NETRA_MAX_MIME_PARTS", "200")), 2000)
    )
    MAX_URLS = max(1, min(int(os.getenv("NETRA_MAX_URLS", "100")), 2000))
    MAX_HEADERS = max(1, min(int(os.getenv("NETRA_MAX_HEADERS", "200")), 2000))
    MAX_ARCHIVE_MEMBERS = max(
        1, min(int(os.getenv("NETRA_MAX_ARCHIVE_MEMBERS", "500")), 5000)
    )
    MAX_ATTACHMENT_SIZE_BYTES = max(
        1,
        min(
            int(
                os.getenv(
                    "NETRA_MAX_ATTACHMENT_SIZE_MB",
                    os.getenv("NETRA_MAX_EMAIL_SIZE_MB", "10"),
                )
            ),
            50,
        )
        * 1024
        * 1024,
    )

    def parse_eml_bytes(self, raw_bytes: bytes) -> Dict[str, Any]:
        if not raw_bytes:
            raise ValueError("Empty email file")

        if not isinstance(raw_bytes, bytes):
            raise ValueError("Email input must be raw bytes")

        if len(raw_bytes) > self.MAX_EMAIL_SIZE_BYTES:
            raise ValueError("Email exceeds the maximum allowed size")

        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

        # Materialize the MIME walk once. This avoids repeated traversal of
        # attacker-controlled MIME trees.
        parts = list(msg.walk())

        if len(parts) > self.MAX_MIME_PARTS:
            raise ValueError("Email contains too many MIME parts")

        header_items = list(msg.items())
        if len(header_items) > self.MAX_HEADERS:
            raise ValueError("Email contains too many headers")

        plain, html = self._extract_bodies(msg)
        html_details = self._extract_html_details(html)

        header_text = "\n".join(
            f"{key}: {value}" for key, value in header_items
        )
        combined_for_urls = "\n".join([plain, html, header_text])
        urls = self._extract_urls(combined_for_urls)

        # Add hrefs that are not present in visible/plain text, while keeping
        # the global URL cap.
        for link in html_details["links"]:
            href = link.get("href", "")
            if not href or href.lower().startswith(("javascript:", "data:")):
                continue

            if len(href) > 4096:
                continue

            try:
                normalized = urljoin("http://placeholder.invalid", href)
            except Exception:
                continue

            if normalized not in urls and normalized != href:
                urls.append(normalized)

            if len(urls) >= self.MAX_URLS:
                break

        metadata = {
            "message_id": str(msg.get("Message-ID", "")).strip(),
            "date": str(msg.get("Date", "")).strip(),
            "subject": str(msg.get("Subject", "")).strip(),
            "from": str(msg.get("From", "")).strip(),
            "to": str(msg.get("To", "")).strip(),
            "cc": str(msg.get("Cc", "")).strip(),
            "bcc": str(msg.get("Bcc", "")).strip(),
            "reply_to": str(msg.get("Reply-To", "")).strip(),
            "return_path": str(msg.get("Return-Path", "")).strip(),
            "sender": str(msg.get("Sender", "")).strip(),
        }

        auth_headers = {
            "authentication_results": self._all_headers(
                msg, "Authentication-Results"
            ),
            "arc_authentication_results": self._all_headers(
                msg, "ARC-Authentication-Results"
            ),
            "received_spf": self._all_headers(msg, "Received-SPF"),
            "dkim_signature": self._all_headers(msg, "DKIM-Signature"),
            "spf": self._all_headers(msg, "Received-SPF"),
            "dmarc": self._all_headers(msg, "DMARC-Results"),
        }

        return {
            "metadata": metadata,
            "authentication_headers": auth_headers,
            "received_headers": [
                str(value) for value in msg.get_all("Received", [])
            ],
            "network_chain": self._parse_received_chain(
                msg.get_all("Received", [])
            ),
            "body": {
                "plain": plain,
                "html": html,
                "visible_text": html_details["visible_text"],
                "html_forms": html_details["forms"],
                "hidden_elements": html_details["hidden_elements"],
            },
            "html_analysis": {
                "links": html_details["links"],
                "inline_images": html_details["inline_images"],
            },
            "urls": urls[: self.MAX_URLS],
            "url_references": self._url_references(
                urls[: self.MAX_URLS], html_details["links"]
            ),
            "attachments": self._extract_attachments(msg),
            "mime_structure": self._mime_structure(msg),
            "raw_bytes": raw_bytes,
            "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "byte_size": len(raw_bytes),
        }

    @staticmethod
    def _all_headers(msg: Any, name: str) -> List[str]:
        return [str(value).strip() for value in msg.get_all(name, [])]

    @classmethod
    def _extract_urls(cls, text: str) -> List[str]:
        urls: List[str] = []

        # Bound regex input so an enormous text field cannot create an
        # unbounded URL-scanning workload.
        bounded_text = str(text or "")[: cls.MAX_TEXT_SIZE_BYTES]

        for value in cls.URL_REGEX.findall(bounded_text):
            value = value.rstrip(".,;:!?)]}>" + "\"'")
            if len(value) > 4096:
                continue

            if value.lower().startswith("www."):
                value = "http://" + value

            if value not in urls:
                urls.append(value)

            if len(urls) >= cls.MAX_URLS:
                break

        return urls

    @staticmethod
    def _url_references(
        urls: List[str], links: List[Dict[str, str]]
    ) -> List[Dict[str, str]]:
        references: List[Dict[str, str]] = []

        for link in links[:2000]:
            href = link.get("href", "")
            if (
                href
                and not href.lower().startswith(("javascript:", "data:"))
                and len(href) <= 4096
            ):
                references.append(
                    {
                        "visible_text": link.get("visible_text", ""),
                        "href": href,
                        "normalized": href,
                    }
                )

        known = {item["normalized"] for item in references}

        for url in urls:
            if url not in known:
                references.append(
                    {
                        "visible_text": "",
                        "href": url,
                        "normalized": url,
                    }
                )

        return references[: ForensicEmailParser.MAX_URLS]

    @classmethod
    def _extract_html_details(cls, html: str) -> Dict[str, Any]:
        extractor = _SafeHTMLExtractor()

        try:
            bounded_html = str(html or "")[: cls.MAX_TEXT_SIZE_BYTES]
            extractor.feed(bounded_html)
            extractor.close()
        except Exception:
            # HTML parsing is enrichment. A malformed HTML body must not make
            # the entire email analysis fail.
            pass

        return {
            "visible_text": " ".join(extractor.visible_parts)[
                : cls.MAX_TEXT_SIZE_BYTES
            ],
            "forms": extractor.forms[: cls.MAX_MIME_PARTS],
            "hidden_elements": extractor.hidden_elements[: cls.MAX_MIME_PARTS],
            "links": extractor.links[: cls.MAX_URLS],
            "inline_images": extractor.inline_images[: cls.MAX_URLS],
        }

    @classmethod
    def _parse_received_chain(
        cls, received_list: List[str]
    ) -> List[Dict[str, Any]]:
        hops: List[Dict[str, Any]] = []

        for header_index, header in enumerate(received_list[: cls.MAX_HEADERS]):
            raw = str(header).strip()

            # Avoid spending excessive work on pathological individual
            # Received headers.
            raw = raw[:8192]

            ips: List[str] = []

            for candidate in cls.IP_REGEX.findall(raw):
                candidate = candidate.strip("[]")

                try:
                    ipaddress.ip_address(candidate)
                except ValueError:
                    continue

                if candidate not in ips:
                    ips.append(candidate)

                if len(ips) >= 32:
                    break

            timestamp = None
            timestamp_anomaly = False
            timestamp_text = (
                raw.rsplit(";", 1)[-1].strip() if ";" in raw else ""
            )

            if timestamp_text:
                try:
                    timestamp = parsedate_to_datetime(timestamp_text).isoformat()
                except (TypeError, ValueError, IndexError, OverflowError):
                    timestamp_anomaly = True
            else:
                timestamp_anomaly = True

            hostnames = re.findall(
                r"\b(?:from|by)\s+([^\s(;)]+)",
                raw,
                flags=re.I,
            )[:32]

            malformed = not re.search(r"\bfrom\b", raw, flags=re.I) or not re.search(
                r"\bby\b", raw, flags=re.I
            )

            from_match = re.search(
                r"\bfrom\s+([^\s(;)]+)(?:\s+\(([^)]*)\))?",
                raw,
                flags=re.I,
            )
            by_match = re.search(
                r"\bby\s+([^\s(;)]+)",
                raw,
                flags=re.I,
            )

            source_hostname = from_match.group(1) if from_match else None
            destination_hostname = by_match.group(1) if by_match else None
            source_ip = ips[0] if ips else None
            destination_ip = ips[1] if len(ips) > 1 else None

            hops.append(
                {
                    "hop_index": header_index + 1,
                    "header_order": header_index,
                    "raw_header": raw,
                    "hostnames": hostnames,
                    "source_hostname": source_hostname,
                    "destination_hostname": destination_hostname,
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "extracted_ips": ips,
                    "ip_classifications": [
                        cls._classify_ip(ip) for ip in ips
                    ],
                    "timestamp": timestamp,
                    "timestamp_anomaly": timestamp_anomaly,
                    "malformed": malformed,
                    "originating_ip": source_ip,
                }
            )

        return hops

    @staticmethod
    def _classify_ip(value: str) -> str:
        try:
            address = ipaddress.ip_address(value)

            documentation_ranges = (
                ipaddress.ip_network("192.0.2.0/24"),
                ipaddress.ip_network("198.51.100.0/24"),
                ipaddress.ip_network("203.0.113.0/24"),
                ipaddress.ip_network("2001:db8::/32"),
            )

            if any(address in network for network in documentation_ranges):
                return "documentation"
            if address.is_loopback:
                return "loopback"
            if address.is_private:
                return "private"
            if address.is_reserved:
                return "reserved"
            if address.is_global:
                return "public"

            return "special"

        except ValueError:
            return "invalid"

    def _extract_bodies(self, msg: Any) -> tuple[str, str]:
        plain_parts: List[str] = []
        html_parts: List[str] = []
        plain_size = 0
        html_size = 0

        for part in msg.walk():
            if part.is_multipart():
                continue

            disposition = str(
                part.get("Content-Disposition", "")
            ).lower()

            if disposition.startswith("attachment"):
                continue

            # Once both body budgets are exhausted, no further body extraction
            # is necessary.
            if (
                plain_size >= self.MAX_TEXT_SIZE_BYTES
                and html_size >= self.MAX_TEXT_SIZE_BYTES
            ):
                break

            try:
                content = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                content = payload.decode(charset, errors="replace")

            content = str(content)

            if part.get_content_type() == "text/plain":
                remaining = self.MAX_TEXT_SIZE_BYTES - plain_size
                if remaining > 0:
                    piece = content[:remaining]
                    plain_parts.append(piece)
                    plain_size += len(piece)

            elif part.get_content_type() == "text/html":
                remaining = self.MAX_TEXT_SIZE_BYTES - html_size
                if remaining > 0:
                    piece = content[:remaining]
                    html_parts.append(piece)
                    html_size += len(piece)

        return "\n".join(plain_parts), "\n".join(html_parts)

    @staticmethod
    def _detect_magic(data: bytes) -> str | None:
        if not data:
            return None
        if data.startswith(b"MZ"):
            return "PE executable"
        if data.startswith(b"\x7fELF"):
            return "ELF executable"
        if data.startswith((b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")):
            return "Mach-O executable"
        if data.startswith(b"PK\x03\x04"):
            return "ZIP/OOXML archive"
        if data.startswith(b"%PDF-"):
            return "PDF document"
        if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return "OLE compound document"
        if data.lstrip().lower().startswith((b"<!doctype html", b"<html")):
            return "HTML document"
        return None

    def _extract_attachments(self, msg: Any) -> List[Dict[str, Any]]:
        attachments: List[Dict[str, Any]] = []
        inspection_deadline = time.monotonic() + 60
        inspections = 0

        for part in msg.walk():
            if part.is_multipart():
                continue

            filename = part.get_filename()
            disposition = str(
                part.get("Content-Disposition", "")
            ).lower()
            content_id = str(part.get("Content-ID", "")).strip("<>")

            if (
                not filename
                and "attachment" not in disposition
                and not content_id
            ):
                continue

            payload = part.get_payload(decode=True) or b""
            declared_size = len(payload)

            # The attachment's decoded bytes are already materialized by the
            # email package. Do not perform expensive ZIP/text inspection when
            # the attachment exceeds the configured inspection budget.
            if declared_size > self.MAX_ATTACHMENT_SIZE_BYTES:
                attachments.append(
                    {
                        "filename": filename or "inline-resource",
                        "content_type": part.get_content_type(),
                        "declared_mime_type": part.get_content_type(),
                        "content_disposition": disposition,
                        "content_id": content_id,
                        "size_bytes": declared_size,
                        "sha256": None,
                        "magic_signature": self._detect_magic(payload[:32]),
                        "content_prefix_hex": payload[:32].hex(),
                        "embedded_urls": [],
                        "archive_members": [],
                        "analysis_skipped": True,
                        "skip_reason": "attachment exceeds inspection size limit",
                    }
                )

                if len(attachments) >= self.MAX_MIME_PARTS:
                    break

                continue

            from backend.inspection_client import inspect_attachment
            remaining = inspection_deadline - time.monotonic()
            if inspections >= 4 or remaining < 1:
                inspection = {"available": False, "error": "message_inspection_budget_exhausted"}
            else:
                inspections += 1
                inspection = inspect_attachment(payload, filename or "inline-resource", part.get_content_type(), timeout=remaining)
            archive_members = inspection.get("archive_members", [])
            embedded_urls = inspection.get("embedded_urls", [])
            image_analysis = inspection.get("image_analysis", {})

            attachments.append(
                {
                    "filename": filename or "inline-resource",
                    "content_type": part.get_content_type(),
                    "declared_mime_type": part.get_content_type(),
                    "content_disposition": disposition,
                    "content_id": content_id,
                    "size_bytes": declared_size,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "magic_signature": self._detect_magic(payload[:32]),
                    "content_prefix_hex": payload[:32].hex(),
                    "embedded_urls": embedded_urls,
                    "archive_members": archive_members,
                    "analysis_skipped": not inspection.get("available", False),
                    "image_analysis": image_analysis,
                    "static_analysis": inspection.get("static_analysis"),
                    "inspection_status": "complete" if inspection.get("available") else "unavailable",
                    "skip_reason": inspection.get("error", ""),
                }
            )

            if len(attachments) >= self.MAX_MIME_PARTS:
                break

        return attachments

    def _mime_structure(self, msg: Any) -> Dict[str, Any]:
        """Build a bounded MIME tree without recursive Python calls."""

        root = {
            "part": "0",
            "content_type": msg.get_content_type(),
            "content_disposition": str(msg.get("Content-Disposition", "")),
            "filename": msg.get_filename() or "",
            "is_multipart": msg.is_multipart(),
            "children": [],
        }

        stack: List[tuple[Any, Dict[str, Any], str]] = [(msg, root, "0")]
        seen = 1

        while stack and seen < self.MAX_MIME_PARTS:
            part, node, index = stack.pop()

            try:
                children = list(part.iter_parts())
            except Exception:
                children = []

            for child_index, child in reversed(list(enumerate(children))):
                if seen >= self.MAX_MIME_PARTS:
                    break

                child_path = f"{index}.{child_index}"

                child_node = {
                    "part": child_path,
                    "content_type": child.get_content_type(),
                    "content_disposition": str(
                        child.get("Content-Disposition", "")
                    ),
                    "filename": child.get_filename() or "",
                    "is_multipart": child.is_multipart(),
                    "children": [],
                }

                node["children"].insert(0, child_node)
                stack.append((child, child_node, child_path))
                seen += 1

        return root
