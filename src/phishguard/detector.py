"""PhishGuard detector: hybrid ML + explainable rules + lists + policy, for URLs, pages and e-mails."""
from __future__ import annotations

import hashlib
import time

import numpy as np

from .config import ML_WEIGHT
from .email_analyzer import analyze_email
from .html_analyzer import analyze_html
from .logger import audit, get_logger
from .models import load_email_model, load_url_model, stack_vector
from .prevention import ListStore, PolicyEngine, defang, neutralise_links, tips_for, WARNING_BANNER
from .url_features import FEATURE_NAMES, extract_features, rule_score

log = get_logger("phishguard.detector")


class PhishGuard:
    def __init__(self, lists: ListStore | None = None, url_bundle=None, email_bundle=None, audit_log: bool = True,
                 auto_block: bool = False):
        self.url_bundle = url_bundle or load_url_model()
        self.email_bundle = email_bundle
        if self.email_bundle is None:
            try:
                self.email_bundle = load_email_model()
            except FileNotFoundError:
                log.warning("No e-mail model found - run `train` first; e-mail scanning disabled")
        self.lists = lists or ListStore()
        self.policy = PolicyEngine()
        self.audit_log = audit_log
        self.auto_block = auto_block      # feedback loop: add confirmed phishing domains to blocklist
        self.stats = {"url": 0, "email": 0, "html": 0, "BLOCK": 0, "QUARANTINE": 0, "WARN": 0, "ALLOW": 0}

    # ---------------------------------------------------------------- URL scoring
    def score_components(self, urls):
        """Vectorised (ml_prob, rule_score) for many URLs - used by evaluation and e-mail scoring."""
        feats = [extract_features(u) for u in urls]
        X = np.array([[f[k] for k in FEATURE_NAMES] for f in feats]) if feats else np.zeros((0, len(FEATURE_NAMES)))
        p = self.url_bundle["model"].predict_proba(X)[:, 1] if len(X) else np.array([])
        r = np.array([rule_score(f)[0] for f in feats])
        return p, r

    @staticmethod
    def hybrid(p, r):
        return 100.0 * (ML_WEIGHT * p) + (1 - ML_WEIGHT) * r

    def score_many(self, urls):
        p, r = self.score_components(list(urls))
        return list(self.hybrid(p, r))

    def scan_url(self, url: str, log_it: bool = True) -> dict:
        t0 = time.perf_counter()
        f = extract_features(url)
        rs, hits = rule_score(f)
        p = float(self.url_bundle["model"].predict_proba(np.array([[f[k] for k in FEATURE_NAMES]]))[0, 1])
        risk = float(self.hybrid(p, rs))
        reasons = [{"id": i, "weight": w, "text": d} for i, w, d in hits]
        listed = self.lists.status(url)
        if listed == "block":
            risk = 100.0
            reasons.insert(0, {"id": "blocklist", "weight": 100, "text": "Domain is on the organisation blocklist"})
        elif listed == "allow":
            risk = min(risk, 5.0)
            reasons.insert(0, {"id": "allowlist", "weight": -100, "text": "Domain is on the trusted allowlist"})
        d = self.policy.decide(risk, "url")
        out = {"type": "url", "target": url, "defanged": defang(url), "risk": round(risk, 1), "ml_probability": round(p, 4),
               "rule_score": rs, "label": d.label, "action": d.action, "reasons": reasons,
               "advice": tips_for([r["id"] for r in reasons]), "latency_ms": round((time.perf_counter() - t0) * 1000, 2)}
        self._record(out, log_it)
        if self.auto_block and d.action == "BLOCK" and not listed:
            self.lists.add_block(url)
        return out

    # ---------------------------------------------------------------- HTML page
    def scan_html(self, html: str, url: str = "") -> dict:
        score, hits = analyze_html(html, url)
        url_res = self.scan_url(url, log_it=False) if url else None
        risk = score if not url_res else min(100.0, 0.6 * score + 0.6 * url_res["risk"])
        reasons = [{"id": i, "weight": w, "text": d} for i, w, d in hits]
        if url_res:
            reasons += url_res["reasons"]
        d = self.policy.decide(risk, "html")
        out = {"type": "html", "target": url or "<inline>", "risk": round(risk, 1), "html_score": score,
               "label": d.label, "action": d.action, "reasons": reasons, "advice": tips_for([r["id"] for r in reasons])}
        self._record(out)
        return out

    # ---------------------------------------------------------------- e-mail
    def scan_email(self, raw: str, log_it: bool = True) -> dict:
        if not self.email_bundle:
            raise RuntimeError("e-mail model not trained")
        t0 = time.perf_counter()
        a = analyze_email(raw)
        text = a.subject + "\n" + a.body_text
        tp = float(self.email_bundle["text_model"].predict_proba([text])[0, 1])
        url_results = [self.scan_url(u, log_it=False) for u in a.urls]
        umax = max([u["risk"] for u in url_results], default=0.0)
        x = np.array([stack_vector(a.header_score, tp, umax, a.flags["link_mismatch"], a.flags["attachment_risk"], len(a.urls))])
        risk = float(self.email_bundle["stacker"].predict_proba(x)[0, 1] * 100)
        reasons = [{"id": i, "weight": w, "text": d} for i, w, d in a.findings]
        bad = {u["target"] for u in url_results if u["action"] == "BLOCK"}
        for u in url_results:
            if u["action"] != "ALLOW":
                reasons.append({"id": "bad_url", "weight": round(u["risk"]), "text": f"{u['action']} link: {u['defanged']}"})
        if any(u["reasons"] and u["reasons"][0]["id"] == "blocklist" for u in url_results):
            risk = max(risk, 95.0)
        if a.from_domain in self.lists.block:
            risk, _ = 100.0, reasons.insert(0, {"id": "blocklist", "weight": 100, "text": "Sender domain is blocklisted"})
        d = self.policy.decide(risk, "email")
        out = {"type": "email", "subject": a.subject, "from": f"{a.display_name} <{a.from_addr}>",
               "risk": round(risk, 1), "text_probability": round(tp, 4), "header_score": a.header_score,
               "url_max_risk": round(umax, 1), "auth": {k: a.auth[k] for k in ("spf", "dkim", "dmarc")},
               "label": d.label, "action": d.action, "reasons": reasons, "urls": [u["defanged"] for u in url_results],
               "attachments": a.attachments, "advice": tips_for([r["id"] for r in reasons]),
               "sha256": hashlib.sha256(raw.encode()).hexdigest()[:16], "latency_ms": round((time.perf_counter() - t0) * 1000, 2)}
        if d.action != "ALLOW":
            out["sanitised_body"] = WARNING_BANNER + "\n\n" + neutralise_links(a.body_text, bad or set(a.urls))
        self._record(out, log_it)
        if self.auto_block and d.action == "QUARANTINE":
            for u in bad:
                self.lists.add_block(u)
        return out

    def _record(self, out: dict, log_it: bool = True):
        if not log_it:
            return
        self.stats[out["type"]] += 1
        self.stats[out["action"]] += 1
        lvl = {"ALLOW": log.info, "WARN": log.warning, "BLOCK": log.error, "QUARANTINE": log.error}[out["action"]]
        tgt = out.get("defanged") or out.get("subject") or out["target"]
        lvl("%-10s %-10s risk=%5.1f  %s  [%s]", out["action"], out["type"], out["risk"], str(tgt)[:80],
            ", ".join(r["id"] for r in out["reasons"][:4]))
        if self.audit_log:
            audit({"event": "scan", "type": out["type"], "target": str(tgt)[:200], "risk": out["risk"],
                   "action": out["action"], "reasons": [r["id"] for r in out["reasons"]]})
