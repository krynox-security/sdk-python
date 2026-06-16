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
if result.risk == "high":
    ...  # add friction
```

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
- `KrynoxCaptcha(secret, *, endpoint=..., timeout=5.0)`
- `.verify(response, remoteip=None) -> KrynoxResult`
- `.feedback(label, *, ip=None, note=None) -> KrynoxFeedback` — `label` is `"human"` or `"bot"`
- `verify(secret, response, *, endpoint=..., timeout=5.0)` — shorthand

`KrynoxResult`: `success, score, risk, hostname, challenge_ts, error_codes`.
`KrynoxFeedback`: `ok, corrected`.

Self-hosting? Pass `endpoint="https://captcha.your-domain/siteverify"`.
