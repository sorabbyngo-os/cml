"""
CML — Audit Ledger (SUID version) — PATCHED
Added record() alias so cml_service.py doesn't crash.
Hash-chained, append-only, SUID entry IDs.
"""

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("cml.ledger")

LEDGER_PATH    = os.environ.get("CML_LEDGER_PATH",
                                os.path.expanduser("~/.sorabbyngo/cml/audit.jsonl"))
DEFAULT_REGION = os.environ.get("HOSPITAL_REGION", "KE047")

try:
    from suid.generator import SUID
    from suid.registry.prefixes import PREFIX
    SUID_AVAILABLE = True
except ImportError:
    SUID_AVAILABLE = False
    log.warning("[CMLLedger] SUID package not found — using fallback IDs")


def _make_audit_id() -> str:
    if SUID_AVAILABLE:
        return SUID.generate(PREFIX.AUDIT, DEFAULT_REGION)
    import secrets, string
    chars  = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(chars) for _ in range(6))
    date   = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"AUD-{date}-{DEFAULT_REGION}-{suffix}-XX"


def _hash_entry(entry: dict, prev_hash: str) -> str:
    content = json.dumps(entry, sort_keys=True) + prev_hash
    return hashlib.sha256(content.encode()).hexdigest()


class AuditLedger:
    """
    Append-only, hash-chained audit ledger.
    Every entry has a SUID and is linked to the previous entry.
    """

    def __init__(self, path: str = LEDGER_PATH):
        self.path       = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self.path.exists():
            return "GENESIS"
        try:
            lines = self.path.read_text().strip().splitlines()
            if lines:
                return json.loads(lines[-1]).get("hash", "GENESIS")
        except Exception:
            pass
        return "GENESIS"

    def append(
        self,
        action:     str,
        entity_id:  str,
        actor_id:   Optional[str] = None,
        related_id: Optional[str] = None,
        metadata:   Optional[dict] = None,
        ip_address: Optional[str] = None,
        safe:       bool = True,
        region:     str = DEFAULT_REGION,
    ) -> dict:
        """Append an immutable audit entry."""
        audit_id = _make_audit_id()
        seq      = self._current_seq() + 1

        entry = {
            "audit_id":   audit_id,
            "seq":        seq,
            "action":     action.upper(),
            "entity_id":  entity_id,
            "actor_id":   actor_id,
            "related_id": related_id,
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "ip_address": ip_address,
            "region":     region,
            "safe":       safe,
            "metadata":   metadata or {},
            "prev_hash":  self._prev_hash,
        }
        entry["hash"] = _hash_entry(
            {k: v for k, v in entry.items() if k != "hash"},
            self._prev_hash,
        )
        self._write(entry)
        self._prev_hash = entry["hash"]
        log.info("[CMLLedger] %s | %s | seq=%d", action, entity_id, seq)
        return entry

    def record(self, data: dict) -> dict:
        """
        Alias called by cml_service.py.
        Maps legacy record() dict interface to append().
        """
        return self.append(
            action     = data.get("action", "FILTER"),
            entity_id  = data.get("source", "unknown"),
            actor_id   = data.get("component"),
            metadata   = {
                "input":    data.get("input", "")[:200],   # Truncate for storage
                "output":   data.get("output", "")[:200],
                "blocked":  data.get("blocked", False),
                "scrubbed": data.get("scrubbed", False),
                "reason":   data.get("reason", ""),
            },
            safe       = data.get("safe", True),
        )

    def _current_seq(self) -> int:
        if not self.path.exists():
            return 0
        try:
            lines = self.path.read_text().strip().splitlines()
            if lines:
                return json.loads(lines[-1]).get("seq", 0)
        except Exception:
            pass
        return 0

    def _write(self, entry: dict):
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def verify_chain(self) -> dict:
        if not self.path.exists():
            return {"valid": True, "entries": 0, "broken": []}
        lines  = self.path.read_text().strip().splitlines()
        broken = []
        prev   = "GENESIS"
        for i, line in enumerate(lines):
            try:
                entry    = json.loads(line)
                stored   = entry.get("hash", "")
                expected = _hash_entry(
                    {k: v for k, v in entry.items() if k != "hash"},
                    entry.get("prev_hash", "GENESIS"),
                )
                if stored != expected:
                    broken.append({"seq": entry.get("seq", i), "reason": "hash_mismatch"})
                if entry.get("prev_hash") != prev:
                    broken.append({"seq": entry.get("seq", i), "reason": "chain_break"})
                prev = stored
            except Exception as e:
                broken.append({"seq": i, "reason": f"parse_error: {e}"})
        return {
            "valid":       len(broken) == 0,
            "entries":     len(lines),
            "broken":      broken,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    def query(
        self,
        entity_id: Optional[str] = None,
        actor_id:  Optional[str] = None,
        action:    Optional[str] = None,
        date_from: Optional[str] = None,
        date_to:   Optional[str] = None,
    ) -> list:
        if not self.path.exists():
            return []
        results = []
        for line in self.path.read_text().strip().splitlines():
            try:
                entry = json.loads(line)
                if entity_id and entry.get("entity_id") != entity_id \
                             and entry.get("related_id") != entity_id:
                    continue
                if actor_id  and entry.get("actor_id")  != actor_id:  continue
                if action    and entry.get("action")     != action.upper(): continue
                if date_from and entry.get("timestamp",  "") < date_from:   continue
                if date_to   and entry.get("timestamp",  "") > date_to:     continue
                results.append(entry)
            except Exception:
                continue
        return results

    def forensic_export(self, entity_id: str) -> dict:
        entries = self.query(entity_id=entity_id)
        return {
            "entity_id":    entity_id,
            "total_events": len(entries),
            "chain_valid":  self.verify_chain()["valid"],
            "events":       entries,
            "exported_at":  datetime.now(timezone.utc).isoformat(),
            "exported_by":  "CML Audit Ledger — Sorabbyngo OS",
        }


_ledger = None

def get_ledger() -> AuditLedger:
    global _ledger
    if _ledger is None:
        _ledger = AuditLedger()
    return _ledger
