# Safety Filter
# Constitutional AI filtering on all Byngox agent outputs

import logging
log = logging.getLogger(__name__)

HIGH_RISK_KEYWORDS = [
    "diagnosis", "prescribe", "dosage", "surgery", "emergency",
    "critical", "lethal", "overdose",
]

class SafetyFilter:
    def __init__(self):
        self.blocked_count = 0
        self.flagged_count = 0

    def filter(self, output: dict) -> dict:
        """Filter agent output for safety. Returns filtered output with safety metadata."""
        reasoning = output.get("reasoning", "")
        risk_level = self._assess_risk(reasoning)

        output["safety"] = {
            "risk_level": risk_level,
            "human_review_required": risk_level == "HIGH",
            "filtered_by": "CML-SafetyFilter-v1",
        }

        if risk_level == "HIGH":
            self.flagged_count += 1
            log.warning(f"HIGH risk output flagged for human review: {reasoning[:100]}")
            output["reasoning"] = output["reasoning"] + " [REQUIRES HUMAN REVIEW]"

        return output

    def _assess_risk(self, text: str) -> str:
        text_lower = text.lower()
        if any(kw in text_lower for kw in HIGH_RISK_KEYWORDS):
            return "HIGH"
        return "LOW"
