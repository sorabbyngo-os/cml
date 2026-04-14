#!/usr/bin/env python3
"""
filters/safety.py — CML Safety Filter
Blocks harmful content before any external API call.
Used by Chameha, Novela, Byngox — any component calling Claude.
"""

import re
import logging

log = logging.getLogger("cml.safety")

BLOCKED_PATTERNS = [
    (re.compile(r'(?i)(how to|steps to).{0,30}(make|synthesize|manufacture).{0,30}(drug|weapon|explosive|poison)'), "weapons/drugs"),
    (re.compile(r'(?i)suicide.{0,20}(method|way|how)'), "self-harm"),
    (re.compile(r'(?i)self.harm.{0,20}(instruction|method|how)'), "self-harm"),
    (re.compile(r'(?i)(hack|exploit|bypass).{0,30}(sorabbyngo|sentinel|kernel)'), "system-attack"),
    (re.compile(r'(?i)child.{0,10}(abuse|exploitation|pornography)'), "child-safety"),
    (re.compile(r'(?i)(bomb|explosive).{0,20}(make|build|construct|detonate)'), "weapons"),
]

WARN_PATTERNS = [
    (re.compile(r'(?i)(password|credentials|api.key|secret)'), "credentials"),
    (re.compile(r'(?i)(root access|sudo|privilege escalation)'), "privilege"),
]


class SafetyFilter:
    def check(self, text: str) -> dict:
        """
        Returns: {safe: bool, reason: str, category: str}
        """
        if not text:
            return {"safe": True, "reason": "", "category": ""}

        for pattern, category in BLOCKED_PATTERNS:
            if pattern.search(text):
                log.warning(f"Safety block [{category}]: {text[:50]}")
                return {
                    "safe":     False,
                    "reason":   f"Content blocked by CML safety filter [{category}]",
                    "category": category
                }

        warnings = []
        for pattern, category in WARN_PATTERNS:
            if pattern.search(text):
                warnings.append(category)

        if warnings:
            log.info(f"Safety warning {warnings}: {text[:50]}")

        return {"safe": True, "reason": "", "category": "", "warnings": warnings}
