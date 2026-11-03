"""End-to-end training + evaluation pipeline that writes reproducible reports."""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score, recall_score,
                             roc_auc_score, roc_curve)
from sklearn.model_selection import train_test_split

from .config import BLOCK_AT, DATA_DIR, REPORT_DIR, SEED, WARN_AT
from .dataset import generate_emails, generate_urls, split_by_group
from .detector import PhishGuard
from .logger import get_logger
from .models import train_email_model, train_url_model
from .prevention import ListStore
from .url_features import FEATURE_NAMES, extract_features, rule_score

log = get_logger("phishguard.eval")


def binary_metrics(y, score, thr=BLOCK_AT):
    y, score = np.asarray(y), np.asarray(score)
    pred = (score >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred, zero_division=0),
            "recall": recall_score(y, pred), "f1": f1_score(y, pred), "roc_auc": roc_auc_score(y, score),
            "false_positive_rate": fp / max(1, fp + tn), "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}


def fmt(m):
    return (f"acc={m['accuracy']:.4f} prec={m['precision']:.4f} rec={m['recall']:.4f} f1={m['f1']:.4f} "
            f"auc={m['roc_auc']:.4f} FPR={m['false_positive_rate']:.4f}")


def _clean_guard(**kw):
    return PhishGuard(lists=ListStore(Path("/nonexistent/a"), Path("/nonexistent/b")), audit_log=False, **kw)


def roc_svg(y, score, path, title):
    fpr, tpr, _ = roc_curve(y, score)
    auc = roc_auc_score(y, score)
    pts = " ".join(f"{40 + 320 * a:.1f},{360 - 320 * b:.1f}" for a, b in zip(fpr, tpr))
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="400" height="420" font-family="sans-serif" font-size="12">
<rect width="400" height="420" fill="white"/><text x="200" y="22" text-anchor="middle" font-size="14" font-weight="bold">{title}</text>
<rect x="40" y="40" width="320" height="320" fill="none" stroke="#999"/><line x1="40" y1="360" x2="360" y2="40" stroke="#bbb" stroke-dasharray="4"/>
<polyline points="{pts}" fill="none" stroke="#c0392b" stroke-width="2.5"/>
<text x="200" y="395" text-anchor="middle">False positive rate</text><text x="14" y="200" transform="rotate(-90 14 200)" text-anchor="middle">True positive rate</text>
<text x="230" y="330" fill="#c0392b">AUC = {auc:.4f}</text></svg>'''
    Path(path).write_text(svg)


def bars_svg(items, path, title):
    items = items[:12]
    mx = max(v for _, v in items) or 1
    rows = "".join(f'<text x="170" y="{52 + i * 24}" text-anchor="end">{k}</text><rect x="178" y="{40 + i * 24}" width="{300 * v / mx:.1f}" height="16" fill="#2c7fb8"/>'
                   f'<text x="{184 + 300 * v / mx:.1f}" y="{53 + i * 24}" font-size="11">{v:.3f}</text>' for i, (k, v) in enumerate(items))
    Path(path).write_text(f'<svg xmlns="http://www.w3.org/2000/svg" width="560" height="{70 + 24 * len(items)}" font-family="sans-serif" font-size="12">'
                          f'<rect width="560" height="{70 + 24 * len(items)}" fill="white"/><text x="280" y="22" text-anchor="middle" font-size="14" font-weight="bold">{title}</text>{rows}</svg>')


def run_pipeline(n_urls=None, n_emails=None):
    REPORT_DIR.mkdir(exist_ok=True)
    DATA_DIR.mkdir(exist_ok=True)
    t0 = time.time()
    kw_u = {"n": n_urls} if n_urls else {}
    kw_e = {"n": n_emails} if n_emails else {}
    urls, emails = generate_urls(**kw_u), generate_emails(**kw_e)
    urls.to_csv(DATA_DIR / "urls.csv", index=False)
    emails.to_json(DATA_DIR / "emails.jsonl", orient="records", lines=True)
    log.info("Generated %d URLs and %d e-mails (seeded, reproducible)", len(urls), len(emails))
    tr, te = split_by_group(urls)
    shared = set(tr.group) & set(te.group)
    log.info("Group split by registered domain: train=%d test=%d  overlapping domains=%d (must be 0)", len(tr), len(te), len(shared))
    assert not shared, "data leakage between train and test"

    # ---------------- URL model
    bundle = train_url_model(tr)
    pg = _clean_guard(url_bundle=bundle, email_bundle={})
    p, r = pg.score_components(te.url.tolist())
    hybrid = pg.hybrid(p, r)
    res = {"test_size": len(te), "train_size": len(tr), "threshold": BLOCK_AT, "systems": {}}
    log.info("=== URL detection - held-out test set (unseen domains) ===")
    for name, score in [("rules_only", r), ("ml_only", p * 100), ("HYBRID (production)", hybrid)]:
        m = binary_metrics(te.label, score)
        res["systems"][name] = m
        log.info("%-20s %s", name, fmt(m))
    Xte = np.array([[extract_features(u)[k] for k in FEATURE_NAMES] for u in te.url])
    for name, est in bundle["members"].items():
        m = binary_metrics(te.label, est.predict_proba(Xte)[:, 1] * 100)
        res["systems"][f"member:{name}"] = m
        log.info("%-20s %s", f"member:{name}", fmt(m))
    te = te.assign(score=hybrid, pred=(hybrid >= BLOCK_AT).astype(int), flagged=(hybrid >= WARN_AT).astype(int))
    fm = binary_metrics(te.label, hybrid, WARN_AT)
    res["systems"]["HYBRID flagged (WARN+BLOCK)"] = fm
    log.info("%-20s %s", "HYBRID flagged>=WARN", fmt(fm))
    tech = {t: {"n": int(len(g)), "detected": float(g.pred.mean()), "flagged": float(g.flagged.mean())}
            for t, g in te[te.label == 1].groupby("technique")}
    res["recall_by_technique"] = tech
    log.info("Recall by attack technique:")
    for t, v in sorted(tech.items(), key=lambda kv: kv[1]["detected"]):
        log.info("   %-18s n=%-4d blocked=%5.1f%%  flagged(warn+block)=%5.1f%%", t, v["n"], 100 * v["detected"], 100 * v["flagged"])
    fp = te[(te.label == 0) & (te.pred == 1)].url.head(8).tolist()
    res["sample_false_positives"] = fp
    res["feature_importances"] = dict(sorted(bundle["importances"].items(), key=lambda kv: -kv[1]))
    m = res["systems"]["HYBRID (production)"]
    cm = f"""Confusion matrix (HYBRID, threshold {BLOCK_AT}) - test n={len(te)}
                    predicted legit   predicted phish
actual legit          {m['tn']:>6}            {m['fp']:>6}
actual phish          {m['fn']:>6}            {m['tp']:>6}
"""
    (REPORT_DIR / "url_confusion_matrix.txt").write_text(cm)
    log.info("\n%s", cm)
    roc_svg(te.label, hybrid, REPORT_DIR / "url_roc.svg", "URL detector ROC (held-out)")
    bars_svg(list(res["feature_importances"].items()), REPORT_DIR / "url_feature_importance.svg", "Top URL features (random forest)")
    t1 = time.perf_counter()
    for u in te.url.head(200):
        pg.scan_url(u, log_it=False)
    res["avg_latency_ms"] = round((time.perf_counter() - t1) / 200 * 1000, 2)
    log.info("Average single-URL latency: %.2f ms", res["avg_latency_ms"])
    (REPORT_DIR / "url_metrics.json").write_text(json.dumps(res, indent=2))

    # ---------------- e-mail model
    etr, ete = train_test_split(emails, test_size=0.25, random_state=SEED, stratify=emails.label)
    etr, ete = etr.reset_index(drop=True), ete.reset_index(drop=True)
    eb = train_email_model(etr, pg.score_many)
    pg_e = _clean_guard(url_bundle=bundle, email_bundle=eb)
    from .email_analyzer import analyze_email
    an = [analyze_email(x) for x in ete.raw]
    text_only = eb["text_model"].predict_proba([a.subject + "\n" + a.body_text for a in an])[:, 1] * 100
    header_only = np.array([a.header_score for a in an], dtype=float)
    full = np.array([pg_e.scan_email(x, log_it=False)["risk"] for x in ete.raw])
    eres = {"train_size": len(etr), "test_size": len(ete), "systems": {}}
    log.info("=== E-mail detection - held-out test set ===")
    for name, s in [("header_rules_only", header_only), ("text_model_only", text_only), ("FULL PIPELINE", full)]:
        m = binary_metrics(ete.label, s)
        eres["systems"][name] = m
        log.info("%-20s %s", name, fmt(m))
    ete = ete.assign(pred=(full >= BLOCK_AT).astype(int))
    eres["recall_by_technique"] = {t: {"n": int(len(g)), "detected": float(g.pred.mean())} for t, g in ete[ete.label == 1].groupby("technique")}
    for t, v in eres["recall_by_technique"].items():
        log.info("   %-14s n=%-4d detected=%.1f%%", t, v["n"], 100 * v["detected"])
    m = eres["systems"]["FULL PIPELINE"]
    (REPORT_DIR / "email_confusion_matrix.txt").write_text(
        f"Confusion matrix (full pipeline) - test n={len(ete)}\n  TN={m['tn']} FP={m['fp']}\n  FN={m['fn']} TP={m['tp']}\n")
    roc_svg(ete.label, full, REPORT_DIR / "email_roc.svg", "E-mail detector ROC (held-out)")
    (REPORT_DIR / "email_metrics.json").write_text(json.dumps(eres, indent=2))
    log.info("Pipeline finished in %.1fs - reports in %s", time.time() - t0, REPORT_DIR)
    return res, eres
