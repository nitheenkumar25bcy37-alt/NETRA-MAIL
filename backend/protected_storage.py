"""Authenticated evidence encryption with a deployment-managed AES-256 keyring.

Keys are never written here. Preserve old keys while their objects exist.
Encryption protects new objects; historical plaintext is not rewritten.
"""
import base64
import hashlib
import json
import os
import re
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class StorageIntegrityError(ValueError):
    pass


class StorageKeyUnavailable(OSError):
    pass


class ProtectedStorage:
    MAGIC = b"NETRA-AESGCM-1\n"

    def __init__(self, db, root, keys=None, active_key=None):
        self.db = db
        self.root = Path(root).resolve()
        supplied = keys if keys is not None else json.loads(os.getenv("NETRA_EVIDENCE_KEYS_JSON", "{}"))
        if not isinstance(supplied, dict):
            raise ValueError("Evidence keyring must be a JSON object")
        self.keys = {}
        for identifier, encoded in supplied.items():
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identifier):
                raise ValueError("Invalid evidence key identifier")
            value = base64.b64decode(encoded, validate=True)
            if len(value) != 32:
                raise ValueError("Evidence encryption requires a 32-byte AES key")
            self.keys[identifier] = value
        self.active_key = active_key if active_key is not None else os.getenv("NETRA_EVIDENCE_ACTIVE_KEY", "")
        if self.active_key and self.active_key not in self.keys:
            raise ValueError("Active evidence encryption key is unavailable")
        required = os.getenv("NETRA_REQUIRE_EVIDENCE_ENCRYPTION", "false").lower() in {"true", "1", "yes"}
        if required and not self.active_key:
            raise ValueError("Evidence encryption is required but no active key is configured")

    def path(self, reference):
        path = (self.root / reference).resolve()
        if not path.is_relative_to(self.root) or path == self.root:
            raise ValueError("Storage reference escapes the evidence directory")
        return path

    def write(self, reference, raw):
        reference = str(reference).replace("\\", "/")
        destination = self.path(reference)
        destination.parent.mkdir(parents=True, exist_ok=True)
        nonce = os.urandom(12)
        encoded = raw
        if self.active_key:
            encoded = self.MAGIC + nonce + AESGCM(self.keys[self.active_key]).encrypt(nonce, raw, reference.encode("utf-8"))
        # Exclusive creation ensures evidence versions cannot overwrite originals.
        with destination.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        self.db.record_storage_blob(reference, self.active_key or None, hashlib.sha256(raw).hexdigest(), len(raw))
        return reference

    def read(self, reference, maximum_bytes):
        reference = str(reference).replace("\\", "/")
        path = self.path(reference)
        metadata = self.db.get_storage_blob(reference)
        if path.stat().st_size > maximum_bytes + len(self.MAGIC) + 28:
            raise StorageIntegrityError("Stored object exceeds its size limit")
        with path.open("rb") as stream:
            encoded = stream.read(maximum_bytes + len(self.MAGIC) + 29)
        if len(encoded) > maximum_bytes + len(self.MAGIC) + 28:
            raise StorageIntegrityError("Stored object exceeds its size limit")
        key_id = metadata.get("key_id") if metadata else None
        if metadata is None and encoded.startswith(self.MAGIC):
            raise StorageIntegrityError("Encrypted object metadata is unavailable")
        raw = encoded
        if key_id:
            key = self.keys.get(key_id)
            if key is None:
                raise StorageKeyUnavailable("Required evidence decryption key is unavailable")
            if not encoded.startswith(self.MAGIC):
                raise StorageIntegrityError("Encrypted object header is invalid")
            offset = len(self.MAGIC)
            try:
                raw = AESGCM(key).decrypt(encoded[offset:offset + 12], encoded[offset + 12:], reference.encode("utf-8"))
            except (InvalidTag, ValueError) as exc:
                raise StorageIntegrityError("Stored object authentication failed") from exc
        if len(raw) > maximum_bytes:
            raise StorageIntegrityError("Plaintext exceeds its size limit")
        if metadata and hashlib.sha256(raw).hexdigest() != metadata["sha256"]:
            raise StorageIntegrityError("Stored object hash mismatch")
        return raw
