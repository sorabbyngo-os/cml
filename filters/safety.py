#!/usr/bin/env python3
"""
filters/safety.py — CML Safety Filter (Enhanced)
Blocks harmful content before any AI decision reaches a user.
Two layers:
  1. General harm rules (weapons, self-harm, system attacks)
  2. Clinical safety rules (diagnosis, prescribing, dosage)

Clinical rules are critical — wrong medical AI output can kill people.
"""

import re
import logging

log = logging.getLogger("cml.safety")


# ── General harm rules ───────────────────────────────────────────────────────
BLOCKED_PATTERNS = [
    (re.compile(r'(?i)(how to|steps to).{0,30}(make|synthesize|manufacture).{0,30}(drug|weapon|explosive|poison)'),
     "weapons/drugs"),
    (re.compile(r'(?i)suicide.{0,20}(method|way|how)'),
     "self-harm"),
    (re.compile(r'(?i)self.harm.{0,20}(instruction|method|how)'),
     "self-harm"),
    (re.compile(r'(?i)(hack|exploit|bypass).{0,30}(sorabbyngo|sentinel|kernel|byngox|cml)'),
     "system-attack"),
    (re.compile(r'(?i)child.{0,10}(abuse|exploitation|pornography)'),
     "child-safety"),
    (re.compile(r'(?i)(bomb|explosive).{0,20}(make|build|construct|detonate)'),
     "weapons"),
    (re.compile(r'(?i)ignore.{0,20}(previous|above|prior).{0,20}(instructions|prompt|rules)'),
     "prompt-injection"),
    (re.compile(r'(?i)(jailbreak|DAN mode|ignore your training)'),
     "jailbreak-attempt"),
]

WARN_PATTERNS = [
    (re.compile(r'(?i)(password|credentials|api.key|secret)'), "credentials"),
    (re.compile(r'(?i)(root access|sudo|privilege escalation)'), "privilege"),
]


# ── Clinical safety rules ────────────────────────────────────────────────────
# These don't BLOCK but flag for human review.
# CML never prevents clinical support — it flags high-risk decisions.

CLINICAL_WARN_PATTERNS = [
    (re.compile(r'(?i)(you have|you are diagnosed with|you suffer from).{0,50}(cancer|hiv|diabetes|heart|tumor)'),
     "direct-diagnosis"),
    (re.compile(r'(?i)(take|prescribe|administer).{0,30}(mg|ml|dose|tablet).{0,30}(daily|twice|three times)'),
     "dosage-instruction"),
    (re.compile(r'(?i)(stop taking|do not take|discontinue).{0,30}(medication|drug|pill|tablet)'),
     "medication-change"),
    (re.compile(r'(?i)(you (do not|don\'t) need).{0,30}(doctor|hospital|medical|treatment)'),
     "avoid-care"),
    (re.compile(r'(?i)(home remedy|natural cure).{0,40}(instead of|replace).{0,20}(medicine|treatment)'),
     "alternative-medicine-replacement"),
    (re.compile(r'(?i)(lethal dose|LD50|overdose).{0,30}(of|for).{0,30}(medication|drug)'),
     "lethal-dose-info"),
]

# Clinical outputs that MUST trigger human review
CLINICAL_BLOCK_PATTERNS = [
    (re.compile(r'(?i)(inject|intravenous|IV).{0,30}(yourself|at home|without)'),
     "dangerous-self-injection"),
    (re.compile(r'(?i)(this (is|confirms) (a )?diagnosis)'),
     "ai-diagnosis-claim"),
    (re.compile(r'(?i)(I (diagnose|confirm|determine) (that )?you)'),
     "ai-diagnosis-claim"),
]


class SafetyFilter:

    def check(self, text: str, context: str = "general") -> dict:
        """
        Check text for safety violations.

        Args:
            text:    The text to check
            context: "general" | "clinical" — clinical applies stricter rules

        Returns:
            {
              safe: bool,
              reason: str,
              category: str,
              warnings: list,
              clinical_flags: list,
              human_review_required: bool,
            }
        """
        if not text:
            return {
                "safe": True, "reason": "", "category": "",
                "warnings": [], "clinical_flags": [],
                "human_review_required": False,
            }

        # ── Hard blocks ──────────────────────────────────────────────────
        for pattern, category in BLOCKED_PATTERNS:
            if pattern.search(text):
                log.warning("[Safety] BLOCKED [%s]: %s...", category, text[:60])
                return {
                    "safe":                   False,
                    "reason":                 f"Content blocked by CML safety filter [{category}]",
                    "category":               category,
                    "warnings":               [],
                    "clinical_flags":         [],
                    "human_review_required":  True,
                }

        # ── Clinical hard blocks (context-aware) ─────────────────────────
        if context == "clinical":
            for pattern, category in CLINICAL_BLOCK_PATTERNS:
                if pattern.search(text):
                    log.warning("[Safety] CLINICAL BLOCK [%s]: %s...", category, text[:60])
                    return {
                        "safe":                   False,
                        "reason":                 f"Clinical safety block [{category}] — AI must not make direct diagnoses",
                        "category":               category,
                        "warnings":               [],
                        "clinical_flags":         [category],
                        "human_review_required":  True,
                    }

        # ── Warnings ─────────────────────────────────────────────────────
        warnings       = []
        clinical_flags = []
        human_review   = False

        for pattern, category in WARN_PATTERNS:
            if pattern.search(text):
                warnings.append(category)

        if context == "clinical":
            for pattern, category in CLINICAL_WARN_PATTERNS:
                if pattern.search(text):
                    clinical_flags.append(category)
                    human_review = True
                    log.info("[Safety] Clinical flag [%s]", category)

        if warnings:
            log.info("[Safety] Warnings %s", warnings)

        return {
            "safe":                   True,
            "reason":                 "",
            "category":               "",
            "warnings":               warnings,
            "clinical_flags":         clinical_flags,
            "human_review_required":  human_review,
        }

    def check_clinical(self, text: str) -> dict:
        """Shorthand for clinical context check."""
        return self.check(text, context="clinical")
