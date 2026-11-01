"""Breach + Safe alerts for VAJRA.

Two channels:
  - BROWSER: pushed to the live SSE stream so the dashboard shows a toast
    (and plays a sound). Always on, no setup.
  - PHONE: Twilio voice call for a breach, Twilio SMS for a block.
    ElevenLabs synthesises the voice. Both no-op silently if the env keys
    are not set, so the demo works even without creds.

Nothing here reaches real email or payment systems. The only external
destination is the user's OWN verified phone number (ALERT_TO).

Called from the attack verdict path (api/main.py) and the campaign scripts.
"""
from __future__ import annotations

import os
import logging
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

log = logging.getLogger("vajra.alerts")

Severity = Literal["safe", "breach"]


@dataclass
class AlertEvent:
    severity: Severity          # "breach" | "safe"
    goal: str                    # redirect_payment | leak_canary | ...
    family: str                  # indirect_email | social_engineering | ...
    attack_id: str
    layer: str | None            # which guardian layer caught it (safe only)
    summary: str                 # one-line human description

    def phone_script(self) -> str:
        if self.severity == "breach":
            return (
                f"Security alert. VAJRA detected a successful attack "
                f"targeting {self.goal.replace('_',' ')}. "
                f"The attacker used a {self.family.replace('_',' ')} technique. "
                f"Please check the dashboard immediately."
            )
        return (
            f"VAJRA notification. An attack was attempted against "
            f"{self.goal.replace('_',' ')} but was blocked by the "
            f"{self.layer or 'guardian'} layer. You are safe."
        )

    def sms_body(self) -> str:
        tag = "BREACH" if self.severity == "breach" else "BLOCKED"
        return f"[VAJRA {tag}] {self.goal} / {self.family} / id={self.attack_id}"

    def web_payload(self) -> dict:
        return {
            "stage": "alert",
            "severity": self.severity,
            "goal": self.goal,
            "family": self.family,
            "attack_id": self.attack_id,
            "layer": self.layer,
            "summary": self.summary,
        }


# ---------------------------------------------------------------
# ElevenLabs TTS — synth to a temp wav, return the path
# ---------------------------------------------------------------
def _synthesize_voice(text: str) -> str | None:
    key = os.getenv("ELEVENLABS_KEY")
    if not key:
        return None
    try:
        from elevenlabs.client import ElevenLabs
        client = ElevenLabs(api_key=key)
        voice = os.getenv("ELEVENLABS_VOICE", "Rachel")
        audio = client.text_to_speech.convert(
            voice_id=voice, text=text, model_id="eleven_turbo_v2_5",
            output_format="mp3_44100_128",
        )
        path = Path(tempfile.gettempdir()) / f"vajra_alert_{os.getpid()}.mp3"
        with open(path, "wb") as f:
            for chunk in audio:
                f.write(chunk)
        return str(path)
    except Exception as e:
        log.warning("ElevenLabs TTS failed: %s", e)
        return None


# ---------------------------------------------------------------
# Twilio — call or SMS
# ---------------------------------------------------------------
def _twilio_client():
    sid = os.getenv("TWILIO_SID"); tok = os.getenv("TWILIO_TOKEN")
    if not (sid and tok):
        return None
    try:
        from twilio.rest import Client
        return Client(sid, tok)
    except Exception as e:
        log.warning("Twilio init failed: %s", e)
        return None


def _twilio_call(text: str) -> bool:
    client = _twilio_client()
    frm, to = os.getenv("TWILIO_FROM"), os.getenv("ALERT_TO")
    if not (client and frm and to):
        return False
    # TwiML inline: Twilio will speak the text with its own voice if we
    # don't host the ElevenLabs mp3. Hosting mp3 requires a public URL;
    # for the demo we use <Say> (Twilio's TTS) with the same script.
    twiml = (
        f'<Response><Say voice="Polly.Aditi">{text}</Say>'
        f'<Pause length="1"/><Hangup/></Response>'
    )
    try:
        call = client.calls.create(to=to, from_=frm, twiml=twiml)
        log.info("Twilio call placed sid=%s", call.sid)
        return True
    except Exception as e:
        log.warning("Twilio call failed: %s", e)
        return False


def _twilio_sms(body: str) -> bool:
    client = _twilio_client()
    frm, to = os.getenv("TWILIO_FROM"), os.getenv("ALERT_TO")
    if not (client and frm and to):
        return False
    try:
        msg = client.messages.create(to=to, from_=frm, body=body)
        log.info("Twilio SMS sent sid=%s", msg.sid)
        return True
    except Exception as e:
        log.warning("Twilio SMS failed: %s", e)
        return False


# ---------------------------------------------------------------
# Public API
# ---------------------------------------------------------------
def dispatch(evt: AlertEvent, web_queue=None) -> dict:
    """Fan out the alert on every available channel.

    `web_queue` is an optional Queue (per Live Flow SSE run). If given,
    an alert event is pushed to it so the browser gets a toast/sound.
    Returns a dict describing which channels fired, for logs.
    """
    status = {"web": False, "sms": False, "call": False, "tts_file": None}

    # 1. Browser — push into SSE queue if present
    if web_queue is not None:
        try:
            web_queue.put(evt.web_payload())
            status["web"] = True
        except Exception as e:
            log.warning("web queue push failed: %s", e)

    # 2. Phone channels run on a thread so they don't block the attack flow
    def _phone():
        if evt.severity == "breach":
            # Try ElevenLabs for logs/history, then voice call via Twilio.
            status["tts_file"] = _synthesize_voice(evt.phone_script())
            status["call"] = _twilio_call(evt.phone_script())
        else:
            status["sms"] = _twilio_sms(evt.sms_body())

    t = threading.Thread(target=_phone, daemon=True)
    t.start()
    # Give it a short head start but don't block the request longer than ~2s.
    t.join(timeout=2.0)

    log.info("alert dispatched: %s %s", evt.severity, status)
    return status


def is_configured() -> dict[str, bool]:
    return {
        "twilio": bool(os.getenv("TWILIO_SID") and os.getenv("TWILIO_TOKEN")
                       and os.getenv("TWILIO_FROM") and os.getenv("ALERT_TO")),
        "elevenlabs": bool(os.getenv("ELEVENLABS_KEY")),
    }
