"""Krynox Captcha — official server-side SDK (Python).

    from krynox_captcha import KrynoxCaptcha
    krynox = KrynoxCaptcha(secret=os.environ["KRYNOX_SECRET"])
    result = krynox.verify(token, remoteip=request.remote_addr)
    if not result.success:
        abort(400)
    if result.risk == "high" or "tor-exit" in result.reasons:
        ...  # extra friction
"""

from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

__all__ = [
    "KrynoxCaptcha",
    "KrynoxResult",
    "KrynoxAgent",
    "KrynoxHuman",
    "KrynoxFeedback",
    "KrynoxClassification",
    "ErrorCode",
    "verify",
]

DEFAULT_ENDPOINT = "https://api.krynox.net/siteverify"


@dataclass
class KrynoxAgent:
    """A cryptographically verified AI agent (Web Bot Auth), when forwarded."""

    verified: bool
    name: Optional[str] = None
    allowlisted: bool = False


@dataclass
class KrynoxHuman:
    """A device-attested real human (Private Access Token), when forwarded."""

    attested: bool
    method: Optional[str] = None
    issuer: Optional[str] = None


@dataclass
class KrynoxResult:
    success: bool
    score: Optional[float] = None
    risk: Optional[str] = None  # "low" | "medium" | "high"
    hostname: Optional[str] = None
    challenge_ts: Optional[str] = None
    action: Optional[str] = None
    cdata: Optional[str] = None
    error_codes: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)  # stable reason codes explaining the score
    agent: Optional[KrynoxAgent] = None
    human: Optional[KrynoxHuman] = None


@dataclass
class KrynoxFeedback:
    ok: bool
    corrected: bool = False


@dataclass
class KrynoxClassification:
    ok: bool
    score: Optional[float] = None
    classification: Optional[str] = None  # "GOOD" | "NEUTRAL" | "BAD"
    reasons: list[str] = field(default_factory=list)
    blocked: bool = False
    error_codes: list[str] = field(default_factory=list)


class ErrorCode:
    """Machine-readable error codes returned by the API + SDK transport."""

    MISSING_RESPONSE = "missing-input-response"
    INVALID_RESPONSE = "invalid-input-response"
    INVALID_SECRET = "invalid-input-secret"
    RATE_LIMITED = "rate-limited"
    TIMEOUT = "timeout"
    REQUEST_FAILED = "request-failed"


class KrynoxCaptcha:
    def __init__(
        self,
        secret: str,
        *,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: float = 5.0,
        retries: int = 2,
    ) -> None:
        if not secret:
            raise ValueError("KrynoxCaptcha: secret key is required")
        self._secret = secret
        self._endpoint = endpoint
        self._timeout = timeout
        self._retries = retries

    def _derive(self, path: str) -> str:
        e = self._endpoint
        return (e[: -len("/siteverify")] + path) if e.endswith("/siteverify") else e

    def _post(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        """POST JSON, retrying transient failures (network / 429 / 5xx). Raises on final failure."""
        body = json.dumps(payload).encode()
        last: Optional[Exception] = None
        for attempt in range(self._retries + 1):
            req = urllib.request.Request(
                url, data=body, headers={"content-type": "application/json"}, method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                # A 4xx (other than 429) carries a JSON error body — return it, don't retry.
                if e.code != 429 and e.code < 500:
                    try:
                        return json.loads(e.read().decode())
                    except Exception:
                        raise
                last = e
            except (urllib.error.URLError, TimeoutError, ValueError) as e:
                last = e
            if attempt < self._retries:
                time.sleep(min(1.0, 0.1 * (2**attempt)))
        raise last if last else RuntimeError("request-failed")

    def verify(
        self,
        response: str,
        remoteip: Optional[str] = None,
        *,
        idempotency_key: Optional[str] = None,
    ) -> KrynoxResult:
        if not response:
            return KrynoxResult(success=False, error_codes=[ErrorCode.MISSING_RESPONSE])
        # A token is single-use, so a retried verify carries an idempotency key — the server
        # returns the first outcome instead of failing the now-consumed token.
        key = idempotency_key or (secrets.token_hex(16) if self._retries > 0 else None)
        payload = {"secret": self._secret, "response": response, "remoteip": remoteip, "idempotency_key": key}
        try:
            data = self._post(self._endpoint, payload)
        except Exception:
            return KrynoxResult(success=False, error_codes=[ErrorCode.REQUEST_FAILED])
        agent = data.get("agent")
        human = data.get("human")
        return KrynoxResult(
            success=data.get("success") is True,
            score=data.get("score"),
            risk=data.get("risk"),
            hostname=data.get("hostname"),
            challenge_ts=data.get("challenge_ts"),
            action=data.get("action"),
            cdata=data.get("cdata"),
            error_codes=list(data.get("error-codes", []) or []),
            reasons=list(data.get("reasons", []) or []),
            agent=KrynoxAgent(
                verified=agent.get("verified") is True,
                name=agent.get("name"),
                allowlisted=agent.get("allowlisted") is True,
            )
            if isinstance(agent, dict)
            else None,
            human=KrynoxHuman(
                attested=human.get("attested") is True,
                method=human.get("method"),
                issuer=human.get("issuer"),
            )
            if isinstance(human, dict)
            else None,
        )

    def feedback(
        self, label: str, *, ip: Optional[str] = None, note: Optional[str] = None
    ) -> KrynoxFeedback:
        """Report detection-quality feedback ("human" | "bot").

        Flagging an auto-blocked IP as "human" un-blocks it server-side (false-positive correction).
        """
        try:
            data = self._post(
                self._derive("/feedback"), {"secret": self._secret, "label": label, "ip": ip, "note": note}
            )
        except Exception:
            return KrynoxFeedback(ok=False)
        return KrynoxFeedback(ok=data.get("ok") is True, corrected=data.get("corrected") is True)

    def classify(
        self,
        *,
        text: Optional[str] = None,
        fields: Optional[dict[str, Any]] = None,
        ip: Optional[str] = None,
    ) -> KrynoxClassification:
        """Score submitted content (a ``text`` string or a ``fields`` dict) for spam/abuse."""
        try:
            data = self._post(
                self._derive("/classify"),
                {"secret": self._secret, "text": text, "fields": fields, "ip": ip},
            )
        except Exception:
            return KrynoxClassification(ok=False, error_codes=[ErrorCode.REQUEST_FAILED])
        return KrynoxClassification(
            ok=data.get("ok") is True,
            score=data.get("score"),
            classification=data.get("classification"),
            reasons=list(data.get("reasons", []) or []),
            blocked=data.get("blocked") is True,
            error_codes=list(data.get("error-codes", []) or []),
        )


def verify(
    secret: str, response: str, *, endpoint: str = DEFAULT_ENDPOINT, timeout: float = 5.0
) -> KrynoxResult:
    """Functional shorthand for a one-off verification."""
    return KrynoxCaptcha(secret, endpoint=endpoint, timeout=timeout).verify(response)
