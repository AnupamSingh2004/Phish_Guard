"""OPTIONAL: natural-language explanation of a verdict using Google Gemini.

Disabled unless GEMINI_API_KEY is set in the environment (the key is never stored in the repo).
Only the already-computed verdict (defanged URLs + rule names) is sent - never the raw e-mail body.
Falls back to a deterministic explanation if the key/network is unavailable.
"""
from __future__ import annotations

import json
import os
import urllib.request

from .logger import get_logger

log = get_logger("phishguard.llm")
MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")


def local_explanation(v: dict) -> str:
    rs = "; ".join(r["text"] for r in v["reasons"][:4]) or "no suspicious indicators"
    return f"Verdict {v['label'].upper()} (risk {v['risk']}/100, action {v['action']}): {rs}."


def explain(verdict: dict, timeout: float = 10.0) -> str:
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        return local_explanation(verdict)
    prompt = ("You are a security analyst. Explain in 2 plain sentences, for a non-technical employee, why this "
              "item was classified as it was and what they should do. Facts: " + json.dumps(
                  {k: verdict.get(k) for k in ("type", "defanged", "label", "risk", "action")} |
                  {"reasons": [r["text"] for r in verdict["reasons"][:6]]}))
    req = urllib.request.Request(
        f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent",
        data=json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode(),
        headers={"Content-Type": "application/json", "x-goog-api-key": key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception as ex:
        log.warning("Gemini unavailable (%s) - using local explanation", type(ex).__name__)
        return local_explanation(verdict)
