#!/usr/bin/env python3
"""
cml_service.py — Sorabbyngo CML Service
Cognitive Mediation Layer — standalone NATS service

Any OS component sends data here before external API calls.
CML filters it and returns a safe version.

NATS interface:
  Subscribe: sorabbyngo.cml.filter.request
  Publish:   sorabbyngo.cml.filter.response.<request_id>
  Subscribe: sorabbyngo.cml.audit.verify
  Publish:   sorabbyngo.cml.audit.result
"""

import os
import sys
import json
import time
import socket
import threading
import logging

sys.path.insert(0, os.path.dirname(__file__))

from filters.safety  import SafetyFilter
from filters.privacy import PrivacyEnforcer
from audit.ledger    import AuditLedger

logging.basicConfig(
    level=logging.INFO,
    format="[CML] %(asctime)s %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("cml")

NATS_HOST = "127.0.0.1"
NATS_PORT = 4222


class CMLService:
    def __init__(self):
        self.safety  = SafetyFilter()
        self.privacy = PrivacyEnforcer()
        self.ledger  = AuditLedger()
        self._sock   = None
        self._lock   = threading.Lock()
        self._buf    = ""
        self._stats  = {"requests": 0, "blocked": 0, "scrubbed": 0}

    def start(self):
        log.info("Sorabbyngo CML Service starting...")
        log.info("Safety filter    : active")
        log.info("Privacy enforcer : active")
        log.info("Audit ledger     : active")
        self._connect()
        self._subscribe()
        log.info("CML Service ready — listening on sorabbyngo.cml.*")
        self._listen()

    def _connect(self):
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((NATS_HOST, NATS_PORT))
                s.recv(1024)
                s.sendall(b'CONNECT {"verbose":false}\r\n')
                s.settimeout(None)
                self._sock = s
                log.info("Connected to NATS")
                return
            except Exception as e:
                log.warning(f"NATS unavailable: {e} — retrying in 3s")
                time.sleep(3)

    def _subscribe(self):
        self._sock.sendall(b"SUB sorabbyngo.cml.filter.request 1\r\n")
        self._sock.sendall(b"SUB sorabbyngo.cml.audit.verify 2\r\n")
        log.info("Subscribed: sorabbyngo.cml.filter.request")
        log.info("Subscribed: sorabbyngo.cml.audit.verify")

    def _publish(self, subject: str, payload: dict):
        msg  = json.dumps(payload)
        data = f"PUB {subject} {len(msg)}\r\n{msg}\r\n".encode()
        with self._lock:
            try:
                self._sock.sendall(data)
            except Exception:
                self._connect()
                self._sock.sendall(data)

    def _on_filter_request(self, data: dict):
        self._stats["requests"] += 1
        request_id = data.get("request_id", str(time.time()))
        text       = data.get("text", "")
        component  = data.get("component", "unknown")
        action     = data.get("action", "filter")

        # Step 1 — Safety check
        safety_result = self.safety.check(text)

        if not safety_result["safe"]:
            self._stats["blocked"] += 1
            self.ledger.record({
                "source":    component,
                "action":    action,
                "safe":      False,
                "blocked":   True,
                "reason":    safety_result["reason"],
                "input":     text,
                "output":    "",
                "component": component,
            })
            response = {
                "request_id": request_id,
                "allowed":    False,
                "text":       "",
                "reason":     safety_result["reason"],
                "scrubbed":   False,
            }
            self._publish(f"sorabbyngo.cml.filter.response.{request_id}", response)
            log.warning(f"BLOCKED [{component}]: {safety_result['reason']}")
            return

        # Step 2 — Privacy scrub
        privacy_result = self.privacy.scrub(text)
        clean_text     = privacy_result["text"]

        if privacy_result["scrubbed"]:
            self._stats["scrubbed"] += 1

        # Step 3 — Audit
        self.ledger.record({
            "source":    component,
            "action":    action,
            "safe":      True,
            "blocked":   False,
            "scrubbed":  privacy_result["scrubbed"],
            "reason":    "",
            "input":     text,
            "output":    clean_text,
            "component": component,
        })

        response = {
            "request_id": request_id,
            "allowed":    True,
            "text":       clean_text,
            "scrubbed":   privacy_result["scrubbed"],
            "scrub_count": privacy_result["count"],
            "warnings":   safety_result.get("warnings", []),
        }
        self._publish(f"sorabbyngo.cml.filter.response.{request_id}", response)
        log.info(f"ALLOWED [{component}] scrubbed={privacy_result['scrubbed']} count={privacy_result['count']}")

    def _on_audit_verify(self, data: dict):
        result = self.ledger.verify_chain()
        self._publish("sorabbyngo.cml.audit.result", result)
        log.info(f"Audit chain verify: {result}")

    def _listen(self):
        while True:
            try:
                chunk = self._sock.recv(4096).decode("utf-8", errors="ignore")
                if not chunk:
                    self._connect()
                    self._subscribe()
                    continue
                self._buf += chunk
                self._buf  = self._process(self._buf)
            except Exception:
                self._connect()
                self._subscribe()

    def _process(self, buf: str) -> str:
        while "\r\n" in buf:
            line, buf = buf.split("\r\n", 1)
            if line.startswith("MSG "):
                parts = line.split()
                if len(parts) >= 4:
                    subject = parts[1]
                    nbytes  = int(parts[3])
                    if len(buf) >= nbytes:
                        payload = buf[:nbytes]
                        buf     = buf[nbytes:].lstrip("\r\n")
                        try:
                            data = json.loads(payload)
                            if subject == "sorabbyngo.cml.filter.request":
                                threading.Thread(
                                    target=self._on_filter_request,
                                    args=(data,), daemon=True
                                ).start()
                            elif subject == "sorabbyngo.cml.audit.verify":
                                self._on_audit_verify(data)
                        except json.JSONDecodeError:
                            pass
        return buf


if __name__ == "__main__":
    CMLService().start()
