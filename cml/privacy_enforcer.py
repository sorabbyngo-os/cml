# Privacy Enforcer
# Kenya DPA 2019 compliance + HEALTH data classification

import logging
log = logging.getLogger(__name__)

DATA_CLASSES = {
    "HEALTH": ["diagnosis", "medication", "vitals", "symptoms", "patient"],
    "IDENTITY": ["name", "id", "phone", "email", "location"],
    "FINANCIAL": ["payment", "insurance", "billing"],
}

class PrivacyEnforcer:
    def classify(self, data: dict) -> str:
        """Classify data sensitivity level per Kenya DPA 2019."""
        data_str = str(data).lower()
        for cls, keywords in DATA_CLASSES.items():
            if any(kw in data_str for kw in keywords):
                return cls
        return "GENERAL"

    def enforce(self, data: dict, user_consent: bool = False) -> dict:
        """Enforce privacy rules. Strips sensitive fields if no consent."""
        classification = self.classify(data)
        if classification == "HEALTH" and not user_consent:
            log.warning("HEALTH data access without explicit consent — stripping PII")
            data = {k: v for k, v in data.items() if k not in ["name", "id", "phone"]}
        data["_privacy_class"] = classification
        return data
