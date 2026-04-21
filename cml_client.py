"""
CML Client Library
Used by Byngox, Novela, Chameha, and any other Sorabbyngo component
to route content through the Cognitive Mediation Layer before use.

Usage:
    from cml_client import cml_filter, cml_filter_clinical

    # Before using any AI output
    result = await cml_filter(text="AI response here", component="byngox.health_agent")
    if not result["allowed"]:
        # CML blocked it — use fallback
        return safe_fallback_response()

    safe_text = result["text"]   # PII-scrubbed, safety-checked

    # For clinical contexts (stricter rules)
    result = await cml_filter_clinical(text=ai_output, component="novela.counterfeit")
"""

import asyncio
import json
import logging
import os
import time
import uuid
from typing import Optional

log = logging.getLogger("cml.client")

NATS_URL      = os.environ.get("NATS_URL", "nats://localhost:4222")
CML_TIMEOUT   = float(os.environ.get("CML_TIMEOUT_S", "5.0"))

# Subjects
FILTER_REQUEST  = "sorabbyngo.cml.filter.request"
FILTER_RESPONSE = "sorabbyngo.cml.filter.response"

# If CML service is unreachable — fail open or fail closed
CML_FAIL_OPEN = os.environ.get("CML_FAIL_OPEN", "true").lower() == "true"


class CMLClient:
    """
    Async CML client using NATS request/reply.
    Singleton — one connection shared across the process.
    """

    def __init__(self):
        self._nc   = None
        self._lock = asyncio.Lock()

    async def _ensure_connected(self):
        if self._nc and not self._nc.is_closed:
            return
        async with self._lock:
            if self._nc and not self._nc.is_closed:
                return
            try:
                import nats
                self._nc = await nats.connect(
                    NATS_URL,
                    max_reconnect_attempts=3,
                    reconnect_time_wait=1,
                )
                log.info("[CMLClient] Connected to NATS")
            except Exception as e:
                log.warning("[CMLClient] Cannot connect to NATS: %s", e)
                self._nc = None

    async def filter(
        self,
        text:       str,
        component:  str = "unknown",
        context:    str = "general",
        action:     str = "filter",
        entity_id:  Optional[str] = None,
        actor_id:   Optional[str] = None,
    ) -> dict:
        """
        Send text through CML safety + privacy filter.

        Args:
            text:       Text to filter (AI output or user input)
            component:  Which component is calling (for audit trail)
            context:    "general" | "clinical" (clinical = stricter rules)
            action:     What's being done (filter, audit, verify)
            entity_id:  SUID of related entity for audit trail
            actor_id:   SUID of actor for audit trail

        Returns:
            {
              allowed:    bool,   # False = CML blocked content
              text:       str,    # Filtered/scrubbed text (empty if blocked)
              scrubbed:   bool,   # True if PII was removed
              reason:     str,    # Why blocked (if blocked)
              warnings:   list,   # Non-blocking warnings
              clinical_flags: list,  # Clinical safety flags
              human_review_required: bool,
            }
        """
        await self._ensure_connected()

        if self._nc is None:
            return self._fallback(text, component)

        request_id = str(uuid.uuid4())[:8]
        payload    = json.dumps({
            "request_id": request_id,
            "text":       text,
            "component":  component,
            "context":    context,
            "action":     action,
            "entity_id":  entity_id,
            "actor_id":   actor_id,
            "timestamp":  time.time(),
        }).encode()

        reply_subject = f"{FILTER_RESPONSE}.{request_id}"

        try:
            reply = await asyncio.wait_for(
                self._nc.request(FILTER_REQUEST, payload, timeout=CML_TIMEOUT),
                timeout=CML_TIMEOUT + 0.5,
            )
            result = json.loads(reply.data.decode())
            log.info("[CMLClient] %s → allowed=%s scrubbed=%s",
                     component, result.get("allowed"), result.get("scrubbed"))
            return result
        except asyncio.TimeoutError:
            log.warning("[CMLClient] CML timeout — %s",
                        "allowing (fail-open)" if CML_FAIL_OPEN else "blocking (fail-closed)")
            return self._fallback(text, component)
        except Exception as e:
            log.error("[CMLClient] Filter error: %s", e)
            return self._fallback(text, component)

    def _fallback(self, text: str, component: str) -> dict:
        """
        Fallback when CML service is unreachable.
        Controlled by CML_FAIL_OPEN env var.
        Default: fail-open (allow but log warning).
        """
        if CML_FAIL_OPEN:
            log.warning("[CMLClient] CML unreachable — FAIL OPEN for %s", component)
            return {
                "allowed":              True,
                "text":                 text,
                "scrubbed":             False,
                "reason":               "",
                "warnings":             ["cml_unreachable"],
                "clinical_flags":       [],
                "human_review_required": False,
                "cml_bypassed":         True,
            }
        else:
            log.error("[CMLClient] CML unreachable — FAIL CLOSED for %s", component)
            return {
                "allowed":              False,
                "text":                 "",
                "scrubbed":             False,
                "reason":               "CML service unreachable — fail closed",
                "warnings":             ["cml_unreachable"],
                "clinical_flags":       [],
                "human_review_required": True,
                "cml_bypassed":         False,
            }


# ── Module-level singleton ────────────────────────────────────────────────────

_client: Optional[CMLClient] = None

def get_client() -> CMLClient:
    global _client
    if _client is None:
        _client = CMLClient()
    return _client


# ── Convenience functions ─────────────────────────────────────────────────────

async def cml_filter(
    text:      str,
    component: str = "unknown",
    **kwargs,
) -> dict:
    """Filter text through CML. General context."""
    return await get_client().filter(text, component, context="general", **kwargs)


async def cml_filter_clinical(
    text:      str,
    component: str = "unknown",
    **kwargs,
) -> dict:
    """Filter text through CML. Clinical context — stricter rules."""
    return await get_client().filter(text, component, context="clinical", **kwargs)


# ── Sync wrapper for non-async code ──────────────────────────────────────────

def cml_filter_sync(
    text:      str,
    component: str = "unknown",
    context:   str = "general",
    **kwargs,
) -> dict:
    """
    Synchronous wrapper for environments without async (Django views, etc.)
    Creates a new event loop if none exists.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # We're inside an async context — can't use run()
            # Return a simple local filter without NATS
            return _local_filter(text, component, context)
        return loop.run_until_complete(
            get_client().filter(text, component, context=context, **kwargs)
        )
    except RuntimeError:
        return asyncio.run(
            get_client().filter(text, component, context=context, **kwargs)
        )


def _local_filter(text: str, component: str, context: str) -> dict:
    """
    Lightweight local filter when async NATS call isn't possible.
    Runs safety + privacy check inline without the CML service.
    """
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    try:
        from filters.safety  import SafetyFilter
        from filters.privacy import PrivacyEnforcer
        safety  = SafetyFilter()
        privacy = PrivacyEnforcer()

        safety_result  = safety.check(text, context=context)
        if not safety_result["safe"]:
            return {
                "allowed":              False,
                "text":                 "",
                "scrubbed":             False,
                "reason":               safety_result["reason"],
                "warnings":             [],
                "clinical_flags":       safety_result.get("clinical_flags", []),
                "human_review_required": True,
                "cml_bypassed":         False,
                "local_filter":         True,
            }

        privacy_result = privacy.scrub(text)
        return {
            "allowed":              True,
            "text":                 privacy_result["text"],
            "scrubbed":             privacy_result["scrubbed"],
            "reason":               "",
            "warnings":             safety_result.get("warnings", []),
            "clinical_flags":       safety_result.get("clinical_flags", []),
            "human_review_required": safety_result.get("human_review_required", False),
            "cml_bypassed":         False,
            "local_filter":         True,
        }
    except Exception as e:
        log.error("[CMLClient] Local filter failed: %s", e)
        return {
            "allowed":  True, "text": text, "scrubbed": False,
            "reason":   "", "warnings": ["local_filter_error"],
            "clinical_flags": [], "human_review_required": False,
            "cml_bypassed": True, "local_filter": True,
        }
