#!/usr/bin/env python3
"""
audit/ledger.py — CML Immutable Audit Ledger
Append-only, hash-chained log of every CML decision.
Every entry references the previous hash — tamper-evident.
"""

import os
import json
import hashlib
import threading
import logging
from datetime import datetime

log = logging.getLogger("cml.audit")

LEDGER_PATH = os.environ.get(
    "CML_LEDGER_PATH",
    os.path.expanduser("~/.sorabbyngo/cml/audit.jsonl")
)


class AuditLedger:
    def __init__(self):
        self._prev_hash = self._load_last_hash()
        self._lock      = threading.Lock()
        os.makedirs(os.path.dirname(LEDGER_PATH), exist_ok=True)
        log.info(f"CML Audit Ledger ready at {LEDGER_PATH}")
        log.info(f"Last hash: {self._prev_hash[:16]}...")

    def _load_last_hash(self) -> str:
        try:
            with open(LEDGER_PATH, "rb") as f:
                lines = f.read().splitlines()
                if lines:
                    last = json.loads(lines[-1])
                    return last.get("hash", "0" * 64)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        return "0" * 64

    def record(self, event: dict) -> str:
        """
        Append a CML decision to the ledger.
        Returns the hash of this entry.
        """
        with self._lock:
            entry = {
                "timestamp":   datetime.utcnow().isoformat(),
                "prev_hash":   self._prev_hash,
                "source":      event.get("source", "unknown"),
                "action":      event.get("action", ""),
                "safe":        event.get("safe", True),
                "scrubbed":    event.get("scrubbed", False),
                "blocked":     event.get("blocked", False),
                "reason":      event.get("reason", ""),
                "input_hash":  self._hash(event.get("input", "")),
                "output_hash": self._hash(event.get("output", "")),
                "component":   event.get("component", ""),
            }
            entry_str       = json.dumps(entry, sort_keys=True)
            entry_hash      = hashlib.sha256(entry_str.encode()).hexdigest()
            entry["hash"]   = entry_hash
            self._prev_hash = entry_hash

            with open(LEDGER_PATH, "a") as f:
                f.write(json.dumps(entry) + "\n")

            return entry_hash

    def verify_chain(self) -> dict:
        """Verify the entire audit chain is intact"""
        try:
            with open(LEDGER_PATH) as f:
                lines = f.readlines()

            prev = "0" * 64
            for i, line in enumerate(lines):
                entry = json.loads(line)
                if entry.get("prev_hash") != prev:
                    return {"valid": False, "broken_at": i, "reason": "hash chain broken"}
                prev = entry.get("hash", "")

            return {"valid": True, "entries": len(lines)}
        except FileNotFoundError:
            return {"valid": True, "entries": 0}
        except Exception as e:
            return {"valid": False, "reason": str(e)}

    def _hash(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:16]
