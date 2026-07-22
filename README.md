# krynox-captcha (Python)

Official server-side verification SDK for **Krynox Captcha**. Zero dependencies (stdlib only).

```bash
pip install krynox-captcha
```

```python
import os
from krynox_captcha import KrynoxCaptcha

krynox = KrynoxCaptcha(secret=os.environ["KRYNOX_SECRET"])

# in your view / handler
result = krynox.verify(form["krynox-captcha"], remoteip=request.remote_addr)
if not result.success:
    return ("captcha failed", 400)
if result.risk == "high" or "tor-exit" in result.reasons:
    ...  # add friction
```

### Reasons, agents & attested humans

- `result.reasons` — stable codes explaining the score (`"tor-exit"`, `"elevated-request-rate"`, …).
- `result.agent` — set when a **verified AI agent** (Web Bot Auth) was forwarded:
  `.verified`, `.name`, `.allowlisted`. Allowlist good bots instead of blocking them.
- `result.human` — set when a **device-attested human** (Private Access Token) was forwarded:
  `.attested`, `.method`, `.issuer`.

```python
if result.agent and result.agent.verified and result.agent.allowlisted:
    ...  # trusted crawler
if result.human and result.human.attested:
    ...  # proven human, skip friction
```

### Content classification (spam/abuse)

```python
c = krynox.classify(text=comment, ip=request.remote_addr)  # or fields={...}
if c.blocked or c.classification == "BAD":
    return ("rejected", 400)
```

### Reliability

Transient failures (network, `429`, `5xx`) are retried automatically (default **2**, exponential
backoff; tune with `retries=`). A retried `verify()` carries an **idempotency key** so it never fails
the single-use token — the server replays the first outcome.

### Feedback (false-positive correction)

Report detection quality back to Krynox. Flagging an auto-blocked IP as `human`
immediately un-blocks it server-side — a closed feedback loop that tunes detection.

```python
# a real user got blocked by mistake → un-block their IP
fb = krynox.feedback("human", ip=request.remote_addr, note="support ticket #1234")
print(fb.ok, fb.corrected)

# confirm a bot you let through
krynox.feedback("bot", ip=suspicious_ip)
```

### API
- `KrynoxCaptcha(secret, *, endpoint=..., timeout=5.0, retries=2)`
- `.verify(response, remoteip=None, *, idempotency_key=None) -> KrynoxResult`
- `.classify(*, text=None, fields=None, ip=None) -> KrynoxClassification`
- `.feedback(label, *, ip=None, note=None) -> KrynoxFeedback` — `label` is `"human"` or `"bot"`
- `verify(secret, response, *, endpoint=..., timeout=5.0)` — shorthand
- `ErrorCode` — constants for `error_codes` (e.g. `ErrorCode.RATE_LIMITED`)

`KrynoxResult`: `success, score, risk, hostname, challenge_ts, action, cdata, error_codes, reasons, agent, human`.
`KrynoxClassification`: `ok, score, classification, reasons, blocked, error_codes`.
`KrynoxFeedback`: `ok, corrected`.

Self-hosting? Pass `endpoint="https://captcha.your-domain/siteverify"`.
