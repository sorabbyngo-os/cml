# Audit Logger
# Immutable audit trail of all CML decisions

import logging
import json
from datetime import datetime, timezone
log = logging.getLogger(__name__)

class AuditLogger:
    def __init__(self, log_path: str = "/var/log/sorabbyngo/cml_audit.jsonl"):
        self.log_path = log_path

    def log(self, agent: str, input_hash: str, output: dict, decision: str):
        """Write immutable audit entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": agent,
            "input_hash": input_hash,
            "decision": decision,
            "risk_level": output.get("safety", {}).get("risk_level", "UNKNOWN"),
            "human_review": output.get("safety", {}).get("human_review_required", False),
        }
        log.info(f"AUDIT: {json.dumps(entry)}")
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "
")
        except Exception as e:
            log.error(f"Audit log write failed: {e}")
