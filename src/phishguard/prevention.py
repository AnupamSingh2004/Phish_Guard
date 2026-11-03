"""Prevention layer: allow/block lists, policy engine, link neutralisation, defanging, user guidance."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .config import BLOCK_AT, DATA_DIR, WARN_AT
from .logger import audit, get_logger
from .url_features import parse_url, split_host

log = get_logger("phishguard.prevent")


class ListStore:
    """Domain allow/block lists persisted as one-domain-per-line text files (comments with #)."""

    def __init__(self, allow: Path | None = None, block: Path | None = None):
        self.allow_path = allow or DATA_DIR / "allowlist.txt"
        self.block_path = block or DATA_DIR / "blocklist.txt"
        self.allow, self.block = self._load(self.allow_path), self._load(self.block_path)

    @staticmethod
    def _load(path: Path) -> set[str]:
        if not path.exists():
            return set()
        return {l.split("#")[0].strip().lower() for l in path.read_text().splitlines() if l.split("#")[0].strip()}

    @staticmethod
    def _domain(url: str) -> str:
        return split_host(parse_url(url)[2])[3]

    def status(self, url: str) -> str | None:
        d = self._domain(url)
        if d in self.block:
            return "block"
        if d in self.allow:
            return "allow"
        return None

    def add_block(self, url: str, persist: bool = True) -> bool:
        d = self._domain(url)
        if d in self.block:
            return False
        self.block.add(d)
        if persist:
            with open(self.block_path, "a") as f:
                f.write(f"{d}  # auto-added by feedback loop\n")
        log.warning("Feedback loop: %s added to blocklist", d)
        audit({"event": "blocklist_add", "domain": d})
        return True


@dataclass
class Decision:
    action: str          # ALLOW | WARN | BLOCK | QUARANTINE
    label: str           # legitimate | suspicious | phishing
    message: str


class PolicyEngine:
    def decide(self, risk: float, kind: str = "url") -> Decision:
        if risk >= BLOCK_AT:
            act = "BLOCK" if kind in ("url", "html") else "QUARANTINE"
            return Decision(act, "phishing", "Delivery/navigation prevented and incident logged." if act == "BLOCK"
                            else "Message moved to quarantine; links disabled; SOC notified.")
        if risk >= WARN_AT:
            return Decision("WARN", "suspicious", "Show a warning banner; require explicit user confirmation.")
        return Decision("ALLOW", "legitimate", "No action required.")


def defang(url: str) -> str:
    """Make an indicator safe to paste in tickets/chat (hxxps://evil[.]com)."""
    return re.sub(r"^http", "hxxp", url, flags=re.I).replace(".", "[.]")


def neutralise_links(text: str, risky: set[str]) -> str:
    """Replace risky URLs in an e-mail body with a defanged, non-clickable marker."""
    for u in sorted(risky, key=len, reverse=True):
        text = text.replace(u, f"[LINK DISABLED: {defang(u)}]")
    return text


WARNING_BANNER = ("*** WARNING: This message was flagged by PhishGuard as a possible phishing attempt. "
                  "Do not click links, open attachments or reply with credentials. ***")

TIPS = {
    "ip_host": "Legitimate sites use domain names, not raw IP addresses.",
    "at_symbol": "Everything before '@' in a URL is ignored by the browser - the real host comes after it.",
    "brand_mismatch": "Check the registered domain (the part just before the TLD), not the brand name in the subdomain.",
    "typosquat": "Look closely: letters may be swapped, or '1'/'0' may replace 'l'/'o'.",
    "punycode": "Characters from other alphabets can imitate Latin letters (homograph attack).",
    "spf_fail": "The sending server is not authorised by the domain owner - the sender is likely forged.",
    "dmarc_fail": "The domain owner's own policy says this message is not authentic.",
    "display_name_spoof": "The visible name can be anything; always inspect the actual sender address.",
    "link_text_mismatch": "Hover over links: the text shown differs from where the link really goes.",
    "dangerous_attachment": "Never run executables or enable macros from unsolicited mail.",
    "credential_request": "Legitimate companies never ask for your password by e-mail.",
    "urgency": "Pressure and deadlines are social-engineering tactics.",
    "exec_freemail": "Executives rarely write from free-mail accounts; verify out-of-band by phone.",
    "financial_lure": "Requests for gift cards or urgent wire transfers are classic BEC fraud.",
    "external_form_action": "This page sends what you type to a different website.",
    "shortener": "Shortened links hide the destination; expand them in a sandbox first.",
}


def tips_for(reason_ids) -> list[str]:
    return [TIPS[r] for r in dict.fromkeys(reason_ids) if r in TIPS][:4]
