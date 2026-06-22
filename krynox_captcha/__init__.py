"""Krynox Captcha — official server-side verification SDK (Python).

    from krynox_captcha import KrynoxCaptcha
    krynox = KrynoxCaptcha(secret=os.environ["KRYNOX_SECRET"])
    result = krynox.verify(token, remoteip=request.remote_addr)
    if not result.success:
        abort(400)
    if result.risk == "high":
        ...  # extra friction
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

__all__ = ["KrynoxCaptcha", "KrynoxResult", "KrynoxFeedback", "verify"]

DEFAULT_ENDPOINT = "https://api.krynox.id/siteverify"


@dataclass
class KrynoxResult:
    success: bool
    score: Optional[float] = None
    risk: Optional[str] = None  # "low" | "medium" | "high"
    hostname: Optional[str] = None
    challenge_ts: Optional[str] = None
    error_codes: list[str] = field(default_factory=list)


@dataclass
class KrynoxFeedback:
    ok: bool
    corrected: bool = False


class KrynoxCaptcha:
    def __init__(self, secret: str, *, endpoint: str = DEFAULT_ENDPOINT, timeout: float = 5.0) -> None:
        if not secret:
            raise ValueError("KrynoxCaptcha: secret key is required")
        self._secret = secret
        self._endpoint = endpoint
        self._timeout = timeout

    def verify(self, response: str, remoteip: Optional[str] = None) -> KrynoxResult:
        if not response:
            return KrynoxResult(success=False, error_codes=["missing-input-response"])
        body = json.dumps({"secret": self._secret, "response": response, "remoteip": remoteip}).encode()
        req = urllib.request.Request(
            self._endpoint, data=body, headers={"content-type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.URLError:
            return KrynoxResult(success=False, error_codes=["request-failed"])
        except (ValueError, TimeoutError):
            return KrynoxResult(success=False, error_codes=["request-failed"])
        return KrynoxResult(
            success=data.get("success") is True,
            score=data.get("score"),
            risk=data.get("risk"),
            hostname=data.get("hostname"),
            challenge_ts=data.get("challenge_ts"),
            error_codes=list(data.get("error-codes", []) or []),
        )

    def feedback(
        self, label: str, *, ip: Optional[str] = None, note: Optional[str] = None
    ) -> KrynoxFeedback:
        """Report detection-quality feedback ("human" | "bot").

        Flagging an auto-blocked IP as "human" un-blocks it server-side
        (false-positive correction).
        """
        endpoint = self._endpoint
        if endpoint.endswith("/siteverify"):
            endpoint = endpoint[: -len("/siteverify")] + "/feedback"
        body = json.dumps({"secret": self._secret, "label": label, "ip": ip, "note": note}).encode()
        req = urllib.request.Request(
            endpoint, data=body, headers={"content-type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode())
        except (urllib.error.URLError, ValueError, TimeoutError):
            return KrynoxFeedback(ok=False)
        return KrynoxFeedback(ok=data.get("ok") is True, corrected=data.get("corrected") is True)


def verify(secret: str, response: str, *, endpoint: str = DEFAULT_ENDPOINT, timeout: float = 5.0) -> KrynoxResult:
    """Functional shorthand for a one-off verification."""
    return KrynoxCaptcha(secret, endpoint=endpoint, timeout=timeout).verify(response)
