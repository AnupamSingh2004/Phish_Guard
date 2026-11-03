"""Machine-learning layer: URL ensemble, e-mail text classifier and e-mail stacker."""
from __future__ import annotations

import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_predict, cross_val_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .config import MODEL_DIR, SEED
from .logger import get_logger
from .url_features import FEATURE_NAMES, vectorize

log = get_logger("phishguard.models")
URL_MODEL = MODEL_DIR / "url_model.joblib"
EMAIL_MODEL = MODEL_DIR / "email_model.joblib"


# ------------------------------------------------------------------------- URL model
def url_estimators():
    return {
        "logreg": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, C=1.0, random_state=SEED)),
        "random_forest": RandomForestClassifier(n_estimators=300, min_samples_leaf=2, n_jobs=-1, random_state=SEED),
        "grad_boost": GradientBoostingClassifier(n_estimators=200, max_depth=3, random_state=SEED),
    }


def train_url_model(train_df: pd.DataFrame):
    t0 = time.time()
    X = np.array([vectorize(u) for u in train_df.url])
    y = train_df.label.values
    log.info("URL training set: %d samples x %d features (phishing=%.1f%%)", *X.shape, 100 * y.mean())
    cv = StratifiedKFold(5, shuffle=True, random_state=SEED)
    ests = url_estimators()
    for name, est in ests.items():
        sc = cross_val_score(est, X, y, cv=cv, scoring="f1", n_jobs=1)
        log.info("  5-fold CV F1  %-14s %.4f +/- %.4f", name, sc.mean(), sc.std())
    ens = VotingClassifier(list(ests.items()), voting="soft", weights=[1, 2, 2]).fit(X, y)
    rf = ens.named_estimators_["random_forest"]
    bundle = {"model": ens, "feature_names": FEATURE_NAMES, "importances": dict(zip(FEATURE_NAMES, rf.feature_importances_.tolist())),
              "members": {k: v for k, v in ens.named_estimators_.items()}}
    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(bundle, URL_MODEL)
    log.info("URL ensemble trained + saved -> %s (%.1fs)", URL_MODEL.name, time.time() - t0)
    return bundle


def load_url_model():
    b = joblib.load(URL_MODEL)
    for est in b["model"].estimators_:       # single-sample latency: avoid thread-pool overhead
        if hasattr(est, "n_jobs"):
            est.n_jobs = 1
    return b


# ------------------------------------------------------------------ e-mail text + stacker
def email_text_pipeline():
    return make_pipeline(
        TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, stop_words="english"),
        LogisticRegression(max_iter=2000, C=4.0, random_state=SEED))


def stack_vector(header_score, text_prob, url_max, link_mismatch, attach_risk, n_urls):
    return [header_score / 100, text_prob, url_max / 100, link_mismatch, attach_risk, min(n_urls, 5) / 5]


def train_email_model(train_df: pd.DataFrame, score_many):
    """Text model is trained on bodies; stacker is trained on OUT-OF-FOLD text probabilities (no leakage)."""
    from .email_analyzer import analyze_email
    t0 = time.time()
    analyses = [analyze_email(r) for r in train_df.raw]
    texts = [a.subject + "\n" + a.body_text for a in analyses]
    y = train_df.label.values
    cv = StratifiedKFold(5, shuffle=True, random_state=SEED)
    oof = cross_val_predict(email_text_pipeline(), texts, y, cv=cv, method="predict_proba")[:, 1]
    text_model = email_text_pipeline().fit(texts, y)
    rows = []
    all_urls = sorted({u for a in analyses for u in a.urls})
    risk = dict(zip(all_urls, score_many(all_urls)))
    for a, p in zip(analyses, oof):
        umax = max([risk[u] for u in a.urls], default=0.0)
        rows.append(stack_vector(a.header_score, p, umax, a.flags["link_mismatch"], a.flags["attachment_risk"], len(a.urls)))
    stacker = LogisticRegression(C=2.0, max_iter=2000, random_state=SEED).fit(np.array(rows), y)
    names = ["header_score", "text_prob", "url_max_risk", "link_mismatch", "attachment_risk", "n_urls"]
    log.info("E-mail stacker coefficients: %s", {n: round(float(c), 2) for n, c in zip(names, stacker.coef_[0])})
    bundle = {"text_model": text_model, "stacker": stacker, "stack_features": names}
    joblib.dump(bundle, EMAIL_MODEL)
    log.info("E-mail model trained + saved -> %s (%.1fs)", EMAIL_MODEL.name, time.time() - t0)
    return bundle


def load_email_model():
    return joblib.load(EMAIL_MODEL)
