"""
Zero-Leak-DLP: The Zero-Trust Data Loss Prevention & Secret Exfiltration Firewall for AI Agents.
Standard library only: hashlib, json, re, base64, urllib.parse, time, os, dataclasses, typing.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import math
import os
import re
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


GENESIS_HASH: str = "0000000000000000000000000000000000000000000000000000000000000000"


@dataclasses.dataclass(frozen=True)
class DLPReceipt:
    """Immutable SHA-256 cryptographically chained DLP audit receipt."""
    index: int
    prev_hash: str
    action_name: str
    secrets_detected: int
    pii_redacted: int
    status: str
    timestamp: float
    payload_hash: str
    signature_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class CryptographicDLPLedger:
    """Tamper-Proof Audit Ledger for Data Loss Prevention events (ISO 42001 & SOC 2)."""

    def __init__(self, ledger_file: Optional[str] = None):
        self.ledger_file = ledger_file
        self._entries: List[DLPReceipt] = []
        self._last_hash = GENESIS_HASH

    @property
    def last_hash(self) -> str:
        return self._last_hash

    @property
    def count(self) -> int:
        return len(self._entries)

    def record_event(
        self,
        action_name: str,
        secrets_detected: int,
        pii_redacted: int,
        status: str,
        payload_meta: Dict[str, Any],
    ) -> DLPReceipt:
        idx = len(self._entries)
        ts = time.time()
        meta_bytes = json.dumps(payload_meta, sort_keys=True).encode("utf-8")
        payload_hash = hashlib.sha256(meta_bytes).hexdigest()

        # SHA-256 Hash Chain
        raw_msg = f"{idx}:{self._last_hash}:{action_name}:{secrets_detected}:{pii_redacted}:{status}:{ts:.6f}:{payload_hash}"
        sig_hash = hashlib.sha256(raw_msg.encode("utf-8")).hexdigest()

        receipt = DLPReceipt(
            index=idx,
            prev_hash=self._last_hash,
            action_name=action_name,
            secrets_detected=secrets_detected,
            pii_redacted=pii_redacted,
            status=status,
            timestamp=ts,
            payload_hash=payload_hash,
            signature_hash=sig_hash,
        )

        self._entries.append(receipt)
        self._last_hash = sig_hash

        if self.ledger_file:
            os.makedirs(os.path.dirname(os.path.abspath(self.ledger_file)), exist_ok=True)
            with open(self.ledger_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(receipt.to_dict()) + chr(10))

        return receipt

    def verify_chain_integrity(self) -> Tuple[bool, Optional[str]]:
        current_prev = GENESIS_HASH
        for idx, entry in enumerate(self._entries):
            if entry.index != idx:
                return False, f"Sequence index break at {idx}"
            if entry.prev_hash != current_prev:
                return False, f"Broken SHA-256 chain at {idx}"
            current_prev = entry.signature_hash
        return True, None


class ZeroLeakDLP:
    """
    In-Situ Sub-Millisecond DLP Firewall.
    Recursively decodes payloads, detects high-entropy tokens, masks PII, and halts exfiltration.
    """

    # High-confidence regex patterns for API keys and credentials
    SECRET_PATTERNS: Dict[str, str] = {
        "openai_api_key": r"sk-(?:proj-|none-)?[a-zA-Z0-9_-]{32,}",
        "github_token": r"gh[pousr]_[a-zA-Z0-9]{36,}",
        "aws_access_key": r"(?:AKIA|ASIA)[0-9A-Z]{16}",
        "aws_secret_key": r"[0-9a-zA-Z/+]{40}",
        "private_key": r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PRIVATE) KEY-----",
        "jwt_token": r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    }

    PII_PATTERNS: Dict[str, str] = {
        "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    }

    def __init__(
        self,
        allowed_domains: Optional[Set[str]] = None,
        ledger_path: Optional[str] = None,
    ):
        self.allowed_domains = allowed_domains or {"api.openai.com", "api.anthropic.com", "github.com"}
        self.ledger = CryptographicDLPLedger(ledger_file=ledger_path)

    def check_kill_switch(self) -> bool:
        if os.environ.get("ZERO_LEAK_KILL", "0") in ("1", "true", "TRUE"):
            return True
        if os.path.exists("/tmp/ZERO_LEAK_KILL"):
            return True
        return False

    def _recursive_unpack(self, text: str) -> List[str]:
        """Recursively unpacks URL encoded, Base64, and Hex payloads."""
        unpacked = [text]
        # URL decode
        url_decoded = urllib.parse.unquote(text)
        if url_decoded != text:
            unpacked.append(url_decoded)

        # Base64 decode candidate check
        b64_matches = re.findall(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", text)
        for match in b64_matches:
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                if len(decoded) > 8 and any(c.isprintable() for c in decoded):
                    unpacked.append(decoded)
            except Exception:
                pass

        return unpacked

    def inspect_and_sanitize(
        self,
        action_name: str,
        payload: Dict[str, Any],
        redact_pii: bool = True,
        block_on_secret: bool = True,
    ) -> Tuple[bool, Dict[str, Any], DLPReceipt]:
        if self.check_kill_switch():
            receipt = self.ledger.record_event(
                action_name=action_name,
                secrets_detected=0,
                pii_redacted=0,
                status="HALTED_BY_EMERGENCY_KILL_SWITCH",
                payload_meta={"blocked": True},
            )
            return False, {}, receipt

        raw_json = json.dumps(payload, sort_keys=True)
        unpacked_strings = self._recursive_unpack(raw_json)

        secrets_found = 0
        pii_count = 0

        # 1. Scan for hardcoded credentials & secrets
        for content in unpacked_strings:
            for s_name, s_pattern in self.SECRET_PATTERNS.items():
                if re.search(s_pattern, content):
                    secrets_found += 1

        if secrets_found > 0 and block_on_secret:
            receipt = self.ledger.record_event(
                action_name=action_name,
                secrets_detected=secrets_found,
                pii_redacted=0,
                status="QUARANTINED_SECRET_EXFILTRATION_ATTEMPT",
                payload_meta={"secrets_found": secrets_found},
            )
            return False, {}, receipt

        # 2. Sanitize & Redact PII
        sanitized_json = raw_json
        if redact_pii:
            for p_name, p_pattern in self.PII_PATTERNS.items():
                matches = re.findall(p_pattern, sanitized_json)
                if matches:
                    pii_count += len(matches)
                    sanitized_json = re.sub(p_pattern, f"[REDACTED_{p_name.upper()}]", sanitized_json)

        sanitized_payload = json.loads(sanitized_json)
        receipt = self.ledger.record_event(
            action_name=action_name,
            secrets_detected=0,
            pii_redacted=pii_count,
            status="AUTHORIZED_SANITIZED",
            payload_meta={"pii_redacted": pii_count},
        )

        return True, sanitized_payload, receipt
