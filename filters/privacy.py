#!/usr/bin/env python3
"""
filters/privacy.py — CML Privacy Enforcer
Scrubs PII from any data before it leaves the device.
Applies to all Tier 3 external API calls across the OS.
"""

import re
import logging

log = logging.getLogger("cml.privacy")

PII_RULES = [
    (re.compile(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b'),                          "[NAME]"),
    (re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),                        "[PHONE]"),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),  "[EMAIL]"),
    (re.compile(r'\b\d{6,13}\b'),                                          "[ID_NUMBER]"),
    (re.compile(r'(?i)national.?id[:\s]+\S+'),                             "[NATIONAL_ID]"),
    (re.compile(r'(?i)patient.?id[:\s]+\S+'),                              "[PATIENT_ID]"),
    (re.compile(r'(?i)dob[:\s]+[\d/.-]+'),                                 "[DOB]"),
    (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),              "[IP_ADDRESS]"),
    (re.compile(r'[0-9a-f]{32,}', re.IGNORECASE),                         "[HASH]"),
    (re.compile(r'(?i)/home/\S+'),                                         "[PATH]"),
    (re.compile(r'(?i)/proc/sorabbyngo/\S+'),                              "[KERNEL_PATH]"),
    (re.compile(r'(?i)/opt/sorabbyngo/\S+'),                               "[OS_PATH]"),
]


class PrivacyEnforcer:
    def scrub(self, text: str) -> dict:
        """
        Scrub PII from text.
        Returns: {text: scrubbed_text, scrubbed: bool, count: int}
        """
        if not text:
            return {"text": text, "scrubbed": False, "count": 0}

        original = text
        count    = 0

        for pattern, replacement in PII_RULES:
            new_text, n = pattern.subn(replacement, text)
            if n > 0:
                count += n
                text   = new_text

        if count > 0:
            log.info(f"Privacy: scrubbed {count} PII instances")

        return {
            "text":     text,
            "scrubbed": count > 0,
            "count":    count
        }

    def scrub_dict(self, data: dict) -> dict:
        """Recursively scrub PII from a dict"""
        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.scrub(value)["text"]
            elif isinstance(value, dict):
                result[key] = self.scrub_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    self.scrub(v)["text"] if isinstance(v, str) else v
                    for v in value
                ]
            else:
                result[key] = value
        return result
