"""
CML — Audit Ledger (SUID version)
Hash-chained audit log where every entry has a SUID.
Entries are immutable — any tampering breaks the chain AND the checksum.

Entry format:
{
  "audit_id":   "AUD-20260421-KE047-A3X9KM-7F",  ← SUID
  "seq":        1,
  "action":     "CREATE",
  "entity_id":  "PAT-20260421-KE045-B7X2QR-3K",  ← SUID
  "actor_id":   "DOC-20260421-KE045-C4M8NP-9W",  ← SUID
  "timestamp":  "2026-04-21T08:00:00Z",
  "hash":       "sha256 of this entry + prev hash",
  "prev_hash":  "sha256 of previous entry",
}
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

# Try to import SUID — fall back to timestamp-based ID if not available
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
    from datetime import datetime, timezone
    import secrets, string
    chars = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(chars) for _ in range(6))
    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"AUD-{date}-{DEFAULT_REGION}-{suffix}-XX"


def _hash_entry(entry: dict, prev_hash: str) -> str:
    """SHA-256 of entry content + previous hash."""
    content = json.dumps(entry, sort_keys=True) + prev_hash
    return hashlib.sha256(content.encode()).hexdigest()


class AuditLedger:
    """
    Append-only, hash-chained audit ledger.
    Every entry has a SUID audit_id and is linked to the previous entry.
    Tampering with any entry breaks the chain.
    """

    def __init__(self, path: str = LEDGER_PATH):
        self.path      = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        """Load hash of the last entry for chain continuity."""
        if not self.path.exists():
            return "GENESIS"
        try:
            lines = self.path.read_text().strip().splitlines()
            if lines:
                last = json.loads(lines[-1])
                return last.get("hash", "GENESIS")
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
        """
        Append an immutable audit entry to the ledger.

        Args:
            action:     Action type (CREATE, READ, ALERT, etc.)
            entity_id:  SUID of entity being acted on
            actor_id:   SUID of actor (doctor, nurse, system)
            related_id: SUID of related entity
            metadata:   Additional context
            ip_address: Network address for forensics
            safe:       Whether CML safety filter approved this action
            region:     Region where action occurred

        Returns:
            The complete audit entry with hash
        """
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

        log.info("[CMLLedger] %s | %s | %s | seq=%d",
                 action, entity_id, audit_id, seq)
        return entry

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
        """
        Verify the entire audit chain integrity.
        Returns report of any broken links or tampered entries.
        Used by IT department for forensic verification.
        """
        if not self.path.exists():
            return {"valid": True, "entries": 0, "broken": []}

        lines   = self.path.read_text().strip().splitlines()
        broken  = []
        prev    = "GENESIS"

        for i, line in enumerate(lines):
            try:
                entry    = json.loads(line)
                stored   = entry.get("hash", "")
                expected = _hash_entry(
                    {k: v for k, v in entry.items() if k != "hash"},
                    entry.get("prev_hash", "GENESIS"),
                )
                if stored != expected:
                    broken.append({
                        "seq":      entry.get("seq", i),
                        "audit_id": entry.get("audit_id"),
                        "reason":   "hash_mismatch",
                    })
                if entry.get("prev_hash") != prev:
                    broken.append({
                        "seq":      entry.get("seq", i),
                        "audit_id": entry.get("audit_id"),
                        "reason":   "chain_break",
                    })
                prev = stored
            except Exception as e:
                broken.append({"seq": i, "reason": f"parse_error: {e}"})

        return {
            "valid":      len(broken) == 0,
            "entries":    len(lines),
            "broken":     broken,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    def query(
        self,
        entity_id:  Optional[str] = None,
        actor_id:   Optional[str] = None,
        action:     Optional[str] = None,
        date_from:  Optional[str] = None,
        date_to:    Optional[str] = None,
    ) -> list:
        """
        Query audit entries. Used by IT for law enforcement requests.

        Returns list of matching entries in chronological order.
        """
        if not self.path.exists():
            return []

        results = []
        for line in self.path.read_text().strip().splitlines():
            try:
                entry = json.loads(line)
                if entity_id and entry.get("entity_id") != entity_id \
                             and entry.get("related_id") != entity_id:
                    continue
                if actor_id  and entry.get("actor_id")  != actor_id:
                    continue
                if action    and entry.get("action")     != action.upper():
                    continue
                if date_from and entry.get("timestamp", "") < date_from:
                    continue
                if date_to   and entry.get("timestamp", "") > date_to:
                    continue
                results.append(entry)
            except Exception:
                continue

        return results

    def forensic_export(self, entity_id: str) -> dict:
        """
        Export full forensic record for a single entity.
        Used for law enforcement requests — returns everything
        related to this SUID from the audit chain.
        """
        entries = self.query(entity_id=entity_id)
        return {
            "entity_id":    entity_id,
            "total_events": len(entries),
            "chain_valid":  self.verify_chain()["valid"],
            "events":       entries,
            "exported_at":  datetime.now(timezone.utc).isoformat(),
            "exported_by":  "CML Audit Ledger — Sorabbyngo OS",
        }


# Module-level singleton
_ledger = None

def get_ledger() -> AuditLedger:
    global _ledger
    if _ledger is None:
        _ledger = AuditLedger()
    return _ledger
