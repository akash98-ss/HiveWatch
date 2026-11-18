"""
alerts.py - optional Discord / Telegram alerts (stdlib only).

Set environment variables to enable (leave unset = alerts off):
  DISCORD_WEBHOOK_URL   https://discord.com/api/webhooks/...
  TELEGRAM_BOT_TOKEN    123456:ABC...
  TELEGRAM_CHAT_ID      your chat id
"""
import json, os, threading, time, urllib.parse, urllib.request

_last = 0.0
_lock = threading.Lock()
MIN_INTERVAL = 5  # seconds between alerts, so a noisy bot can't spam you


def _clean(text):
    # keep it short and break mention/markdown tricks from attacker-controlled text
    return text.replace("`", "'").replace("@", "@\u200b")[:300]


def _send(text):
    hook = os.environ.get("DISCORD_WEBHOOK_URL", "")
    if hook.startswith(("https://discord.com/api/webhooks/", "https://discordapp.com/api/webhooks/")):
        body = json.dumps({"content": text, "allowed_mentions": {"parse": []}}).encode()
        req = urllib.request.Request(hook, body, {"Content-Type": "application/json",
                                                  "User-Agent": "ssh-honeypot-alert"})
        urllib.request.urlopen(req, timeout=10).read()
    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if token and chat:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
        urllib.request.urlopen(url, data, timeout=10).read()


def enabled():
    return bool(os.environ.get("DISCORD_WEBHOOK_URL") or
                (os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID")))


def notify(text):
    """Fire-and-forget; never raises, never blocks the honeypot."""
    global _last
    if not enabled():
        return
    with _lock:
        if time.time() - _last < MIN_INTERVAL:
            return
        _last = time.time()

    def run():
        try:
            _send(_clean(text))
        except Exception:
            pass
    threading.Thread(target=run, daemon=True).start()
