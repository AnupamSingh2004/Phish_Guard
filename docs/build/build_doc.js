const fs = require("fs");
const sharp = require("sharp");
const D = require("docx");
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, HeadingLevel, AlignmentType, WidthType, ShadingType, BorderStyle, LevelFormat, ImageRun, PageBreak, TableOfContents, Footer, PageNumber, Header } = D;
const R = "/home/anupam/code/CyberSecurity/PhishGuard/reports/";
const U = JSON.parse(fs.readFileSync(R + "url_metrics.json")), E = JSON.parse(fs.readFileSync(R + "email_metrics.json"));
const W = 9638, INK = "0E1A2B", TEAL = "0F7F74", ALERT = "C8433C", SOFT = "DDE6EE", LIGHT = "F4F7FA";
const f3 = x => x.toFixed(3), pc = x => (100 * x).toFixed(1) + "%";

const P = (t, o = {}) => new Paragraph({ spacing: { after: 120, line: 276 }, ...o, children: Array.isArray(t) ? t : [new TextRun(t)] });
const B = t => new TextRun({ text: t, bold: true });
const H1 = t => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(t)] });
const H2 = t => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(t)] });
const H3 = t => new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(t)] });
const BL = (items) => items.map(t => new Paragraph({ numbering: { reference: "bul", level: 0 }, spacing: { after: 60 }, children: Array.isArray(t) ? t : [new TextRun(t)] }));
const NL = (items, ref = "num") => items.map(t => new Paragraph({ numbering: { reference: ref, level: 0 }, spacing: { after: 60 }, children: Array.isArray(t) ? t : [new TextRun(t)] }));
const CODE = lines => lines.map((l, i) => new Paragraph({ shading: { type: ShadingType.CLEAR, fill: "EEF2F6" }, spacing: { after: i === lines.length - 1 ? 160 : 0 }, indent: { left: 120, right: 120 }, children: [new TextRun({ text: l || " ", font: "Courier New", size: 18 })] }));
const CAP = t => new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 }, children: [new TextRun({ text: t, italics: true, size: 20, color: "5B6B7F" })] });
const bd = { style: BorderStyle.SINGLE, size: 4, color: "B8C4D0" };
const borders = { top: bd, bottom: bd, left: bd, right: bd };
function table(head, rows, widths, opts = {}) {
  const mk = (t, w, h, i) => new TableCell({ width: { size: w, type: WidthType.DXA }, borders, margins: { top: 60, bottom: 60, left: 100, right: 100 },
    shading: h ? { type: ShadingType.CLEAR, fill: INK } : (opts.hl && opts.hl.includes(i) ? { type: ShadingType.CLEAR, fill: "D7F3EF" } : undefined),
    children: [new Paragraph({ spacing: { after: 0 }, alignment: opts.center && opts.center.includes(widths.indexOf(w)) ? AlignmentType.CENTER : AlignmentType.LEFT, children: [new TextRun({ text: String(t), bold: h, color: h ? "FFFFFF" : undefined, size: opts.size || 19, font: opts.mono && opts.mono.includes(widths.indexOf(w)) && !h ? "Courier New" : undefined })] })] });
  return new Table({ width: { size: W, type: WidthType.DXA }, columnWidths: widths,
    rows: [new TableRow({ tableHeader: true, children: head.map((t, j) => mk(t, widths[j], true)) })].concat(rows.map((r, i) => new TableRow({ cantSplit: true, children: r.map((t, j) => mk(t, widths[j], false, i)) }))) });
}
const sp = () => new Paragraph({ spacing: { after: 120 }, children: [] });
async function img(svgOrPath, w, h, isSvg = true) {
  const buf = await sharp(isSvg ? fs.readFileSync(svgOrPath) : svgOrPath, { density: 220 }).png().toBuffer();
  return new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, keepNext: true, children: [new ImageRun({ type: "png", data: buf, transformation: { width: w, height: h }, altText: { title: "figure", description: "figure", name: "figure" } })] });
}

(async () => {
  const c = [];
  // ---------------- title page
  c.push(new Paragraph({ spacing: { before: 2400, after: 200 }, children: [new TextRun({ text: "PHISHING DETECTION & PREVENTION", size: 28, bold: true, color: TEAL, font: "Arial" })] }));
  c.push(new Paragraph({ spacing: { after: 240 }, children: [new TextRun({ text: "PhishGuard: Complete Technical Report", size: 56, bold: true, color: INK, font: "Cambria" })] }));
  c.push(new Paragraph({ spacing: { after: 600 }, children: [new TextRun({ text: "A hybrid machine-learning and rule-based system that detects phishing in URLs, e-mails and web pages, explains every verdict, and prevents harm through block, warn and quarantine policies.", size: 26, color: "3B4A5C" })] }));
  c.push(table(["Item", "Detail"], [["Course / context", "Cybersecurity project evaluation"], ["Report date", "4 November 2026"], ["Software", "PhishGuard v1.0.0 (Python 3.14, scikit-learn 1.9.1)"], ["Source folder", "CyberSecurity/PhishGuard/"], ["One-command run", "./scripts/run_all.sh"], ["Test status", "75 of 75 tests pass"]], [2600, 7038], { size: 21 }));
  c.push(new Paragraph({ children: [new PageBreak()] }));
  c.push(new Paragraph({ spacing: { after: 200 }, children: [new TextRun({ text: "Contents", bold: true, size: 36, font: "Cambria", color: INK })] }));
  c.push(new TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-2" }));
  c.push(new Paragraph({ children: [new PageBreak()] }));

  // ---------------- 1 intro
  c.push(H1("1. Introduction"));
  c.push(P("Phishing is a social-engineering attack in which an adversary impersonates a trusted party in order to make a victim disclose credentials, authorise payments or execute malware. Because the attack targets human judgement rather than a software flaw, it bypasses many purely technical defences and remains one of the most common ways in which organisations are first compromised."));
  c.push(P("This project, PhishGuard, is a complete detection and prevention toolkit. It accepts three kinds of input (a URL, a raw e-mail message and the HTML of a web page), scores each for phishing risk on a scale of 0 to 100, explains the score with named, human-readable reasons, and then applies a prevention policy such as allowing, warning, blocking or quarantining the item."));
  c.push(H2("1.1 Objectives"));
  c.push(...BL([[B("Detect: "), new TextRun("identify phishing in URLs, e-mails and pages using machine learning combined with explainable rules.")], [B("Explain: "), new TextRun("attach reasons and plain-language advice to every verdict so users learn what to look for.")], [B("Prevent: "), new TextRun("enforce a policy (allow, warn, block, quarantine), neutralise dangerous links and learn from confirmed detections.")], [B("Prove: "), new TextRun("evaluate rigorously on held-out data, run an automated test suite and keep complete logs.")]]));
  c.push(H2("1.2 Scope"));
  c.push(P("All analysis is static and local: PhishGuard never visits the suspicious site and never executes scripts. This keeps scanning fast (about 40 ms per URL), private and safe. The training data is synthetic and generated by the project itself (Section 8); the limitations that follow from this are discussed openly in Section 12."));

  // ---------------- 2 background
  c.push(H1("2. Background: Understanding Phishing"));
  c.push(H2("2.1 Anatomy of an attack"));
  c.push(...NL([[B("Set up. "), new TextRun("The attacker registers a look-alike domain, clones a login page and rents hosting.")], [B("Lure. "), new TextRun("A message (e-mail, SMS, call, QR code) carries a link or attachment and creates urgency or reward.")], [B("Click. "), new TextRun("The victim opens the link and lands on a convincing fake page.")], [B("Harvest. "), new TextRun("Typed credentials are posted to a server controlled by the attacker.")], [B("Exploit. "), new TextRun("Stolen accounts are used for fraud, data theft or lateral movement.")]], "life"));
  c.push(P("Detection and prevention are most valuable in steps 1 to 3, before any credentials are lost. PhishGuard operates at the lure and click stages."));
  c.push(H2("2.2 Types of phishing"));
  c.push(table(["Type", "Description"], [["Email phishing", "Mass campaigns posing as banks, shops or IT departments, linking to a fake login page."], ["Spear phishing", "Targeted messages tailored to one person or team using personal context."], ["Whaling / Business E-mail Compromise (BEC)", "Impersonation of executives to request wire transfers, gift cards or sensitive data; often has no link at all."], ["Smishing", "Phishing by SMS: parcel fees, bank alerts, shortened links."], ["Vishing", "Voice calls pretending to be support staff or a bank."], ["Quishing", "Malicious QR codes that hide the destination URL from mail filters."], ["Clone / pharming", "Duplicated legitimate pages or poisoned DNS that send victims to attacker servers."]], [3000, 6638]));
  c.push(sp());
  c.push(H2("2.3 How attackers disguise URLs"));
  c.push(P("The URL is the single most important artefact in a phishing attack, because the victim must ultimately visit it. The table lists the techniques that PhishGuard detects; each one is also generated by the project's test-data generator."));
  c.push(table(["Technique", "Example", "Why it works"], [["Typosquatting", "paypa1.com", "Swapped, missing or look-alike letters (1 for l, 0 for o)"], ["Combosquatting", "paypal-secure-login.xyz", "A real brand name combined with trust words"], ["Brand in subdomain", "paypal.com.verify-now.top", "The reader stops at the first '.com'; the real domain is verify-now.top"], ["IP address host", "http://185.220.101.7/login", "No domain name to inspect or recognise"], ["'@' trick", "paypal.com@evil.tk/signin", "Browsers ignore everything before '@'; the real host is evil.tk"], ["Homograph (IDN)", "xn--pypal-4ve.com", "Cyrillic characters that look identical to Latin letters"], ["URL shortener", "bit.ly/3xYz9Qa", "Hides the final destination"], ["Free-hosting abuse", "amazon-wallet.pages.dev", "A trusted platform hosting attacker content"], ["Long obfuscated URL", "x7f3k9.click/login.php?id=...&session=...", "Random tokens and parameters to look like a session"], ["Executable download", "x.top/microsoft-update-12.exe", "Disguised software update"]], [2200, 3400, 4038], { mono: [1], size: 18 }));
  c.push(sp());
  c.push(H2("2.4 Why detection is hard"));
  c.push(...BL([[B("Short lifespan: "), new TextRun("phishing sites often live only hours, so blocklists lag behind new domains (zero-day phishing).")], [B("Legitimate appearance: "), new TextRun("HTTPS padlocks, cloned branding and compromised but clean-looking sites defeat naive checks.")], [B("False positives hurt: "), new TextRun("genuine login pages, tracking links and alarming-sounding security notices resemble phishing; wrongly blocking them erodes trust.")], [B("Adversarial adaptation: "), new TextRun("attackers test against filters and change tactics, so static rules decay.")]]));
  c.push(H2("2.5 Detection approaches"));
  c.push(table(["Approach", "How it works", "Strength", "Weakness"], [["Blocklists", "Lookup of known-bad URLs", "Fast, almost no false positives", "Misses new sites"], ["Heuristic rules", "Hand-written URL and page checks", "Explainable, no training", "Brittle, easy to evade"], ["Machine learning", "Classifier on URL or content features", "Generalises to unseen attacks", "Needs data, less transparent"], ["Content / visual", "Page text, logos, screenshots", "Catches clean-looking URLs", "Needs fetching, slower, riskier"], ["E-mail authentication", "SPF, DKIM, DMARC results", "Proves sender identity", "Does not judge content"], ["Hybrid (this project)", "Rules + ML + headers + lists", "Accurate and explainable", "Needs maintenance"]], [2000, 2700, 2500, 2438], { hl: [5] }));
  c.push(sp());
  c.push(H2("2.6 Layers of prevention"));
  c.push(P("No single control stops phishing; defence in depth is required."));
  c.push(...BL([[B("Gateway and filtering: "), new TextRun("e-mail gateways, DNS and web filtering, attachment sandboxing (implemented in PhishGuard).")], [B("Identity: "), new TextRun("SPF, DKIM and DMARC for sender authenticity; multi-factor authentication and passkeys (FIDO2) so that stolen passwords are not enough (consumed as signals).")], [B("Endpoint and browser: "), new TextRun("safe-browsing warnings, endpoint detection, patching.")], [B("People: "), new TextRun("awareness training and a one-click report button (user advice is generated by PhishGuard).")], [B("Response: "), new TextRun("quarantine, blocklist updates, takedown and audit trails (implemented in PhishGuard).")]]));

  // ---------------- 3 overview
  c.push(H1("3. System Overview"));
  c.push(await img("arch.svg", 620, 230));
  c.push(CAP("Figure 1. PhishGuard architecture: inputs, analysis, machine learning and prevention."));
  c.push(P("A scan proceeds as follows. The input is parsed; analysers extract features and fire named rules; learned models turn the evidence into a probability; the result is fused into a single risk score between 0 and 100; allow and block lists may override the score; and the policy engine converts the score into an action. Every decision is written to a human-readable log and to a JSON-lines audit trail."));
  c.push(H2("3.1 Project structure"));
  c.push(table(["Module (src/phishguard)", "Purpose"], [["url_features.py", "Host parsing, 30 features, Damerau-Levenshtein typosquat detection, homoglyph and leetspeak folding, 16 weighted rules"], ["email_analyzer.py", "RFC-822 forensics: SPF/DKIM/DMARC, sender spoofing, BEC, link mismatch, attachments"], ["html_analyzer.py", "Static page analysis: forms, iframes, scripts, redirects, brand misuse"], ["models.py", "URL soft-voting ensemble; e-mail text model and stacker trained on out-of-fold predictions"], ["detector.py", "Orchestrates everything and returns a JSON-serialisable verdict with reasons"], ["prevention.py", "Lists, policy engine, defanging, link neutralisation, advice, feedback loop"], ["api.py", "Standard-library REST server: /scan/url, /scan/email, /scan/html, /health, /stats"], ["llm_explain.py", "Optional Gemini plain-English explanation; falls back to a local explanation"], ["dataset.py", "Deterministic URL and e-mail generators with hard cases"], ["evaluate.py", "Training, evaluation and report/chart generation"], ["logger.py, config.py, cli.py", "Logging and audit trail, central configuration, command-line interface"]], [3000, 6638], { mono: [0], size: 18 }));
  c.push(sp());
  c.push(H2("3.2 Technology"));
  c.push(P("Python 3.14 with scikit-learn (models), pandas and NumPy (data), joblib (model persistence) and the standard library for e-mail parsing, HTML parsing, HTTP serving and testing. No network access is required to scan anything."));

  // ---------------- 4 URL
  c.push(H1("4. URL Analysis Module"));
  c.push(H2("4.1 Parsing"));
  c.push(P("A URL is parsed with the standard library and split into subdomain, label, suffix and registered domain. Because the public-suffix list is not available offline, a built-in table of multi-part suffixes (co.uk, com.au, github.io, pages.dev and others) is used. The registered domain is the part that identifies the real owner (for example evil.top in paypal.com.verify.evil.top), and most attacks rely on the reader not noticing it. User-information tricks are handled correctly: in https://paypal.com@evil.top/ the real host is evil.top."));
  c.push(H2("4.2 The 30 features"));
  const F = [["url_length", "Length", "Total characters in the URL"], ["host_length", "Length", "Characters in the host name"], ["path_length", "Length", "Characters in the decoded path"], ["query_length", "Length", "Characters in the query string"], ["label_len", "Length", "Length of the registered-domain label"], ["num_dots", "Structure", "Number of dots in the host"], ["num_subdomains", "Structure", "Subdomain levels before the registered domain"], ["num_params", "Structure", "Number of query parameters"],
    ["digit_ratio_host", "Characters", "Share of digits in the host"], ["digit_ratio_url", "Characters", "Share of digits in the whole URL"], ["num_hyphens_host", "Characters", "Hyphens in the host"], ["host_entropy", "Characters", "Shannon entropy of the host (random-looking hosts score high)"], ["path_entropy", "Characters", "Shannon entropy of path plus query"], ["num_special_chars", "Characters", "Count of ! $ % * ; = ~ # ^"], ["encoded_chars", "Characters", "Count of %XX escapes (obfuscation)"],
    ["is_https", "Security", "1 if the scheme is https"], ["has_ip_host", "Security", "Host is an IP address (including hex or decimal-encoded)"], ["has_at_symbol", "Security", "'@' present in the authority"], ["has_punycode", "Security", "Host contains xn--"], ["non_ascii_host", "Security", "Host contains non-ASCII characters"], ["nonstandard_port", "Security", "Port other than 80 or 443"], ["double_slash_in_path", "Security", "'//' inside the path (redirect trick)"], ["exec_extension", "Security", "Path ends in .exe, .scr, .bat, .msi, .apk, .jar, ..."], ["embedded_url_in_query", "Security", "Another http(s) URL inside the query (redirect chain)"],
    ["is_shortener", "Lexical", "Registered domain is a known URL shortener"], ["suspicious_tld", "Lexical", "TLD frequently abused (xyz, top, tk, ml, ga, cf, gq, click, ...)"], ["keyword_count", "Lexical", "Occurrences of 22 phishing keywords (login, verify, secure, ...)"], ["keyword_in_host", "Lexical", "Any such keyword inside the host"], ["brand_mismatch", "Lexical", "Brand token on a domain the brand does not own"], ["is_typosquat", "Lexical", "Look-alike of a known brand (see 4.3)"]];
  c.push(table(["Feature", "Group", "Meaning"], F, [2700, 1400, 5538], { mono: [0], size: 18 }));
  c.push(sp());
  c.push(H2("4.3 Brand-impersonation detection"));
  c.push(P("This is the most technically involved part of the URL module. It works in four steps:"));
  c.push(...NL(["Split the host into subdomain, label, suffix and registered domain.", "Fold look-alike characters: 0 to o, 3 to e, 4 to a, 5 to s, 7 to t, rn to m, vv to w, 1 to l or i, and common Cyrillic and Greek homoglyphs to ASCII. Punycode hosts are decoded first.", "Compare the label (and each hyphen-separated token of length 5 or more) with 28 brand names using Damerau-Levenshtein distance, where swapping two adjacent letters counts as one edit. A distance of 1 (or up to 2 for brand names of 8 or more letters) marks a typosquat.", "Flag a brand mismatch when a brand name appears in the subdomain, label or path of a domain that the brand does not own. Ownership is a table: for example paypal maps to {paypal.com}, amazon to {amazon.com, amazon.in, amazon.co.uk, amazonaws.com}."], "alg"));
  c.push(P([B("Worked example. "), new TextRun("For http://paypa1-secure-login.xyz/verify/account the token paypa1 folds to paypal (distance 1: typosquat, +40), the brand is not owned by the domain (mismatch, +35), .xyz is an abused TLD (+15) and credential keywords are used over plain HTTP (+15). The rule score is capped at 100 and the final risk is 99.1, so the action is BLOCK.")]));
  c.push(P("A unit test found a weakness in an earlier version: the swapped-letter typo paypla.com has plain Levenshtein distance 2 and was missed. Switching to Damerau-Levenshtein fixed it."));
  c.push(H2("4.4 Explainable rule engine"));
  c.push(P("Sixteen rules each add a weight when fired. The rule score is the sum of weights capped at 100, and each fired rule is reported to the user with a description."));
  c.push(table(["Rule", "Weight", "Condition"], [["typosquat", "+40", "Look-alike (typo or leetspeak) of a well-known brand"], ["brand_mismatch", "+35", "Brand name used on a domain the brand does not own"], ["ip_host", "+35", "Raw IP address instead of a domain"], ["at_symbol", "+30", "'@' hides the real destination host"], ["exec_download", "+25", "Link points to an executable or installer"], ["punycode", "+25", "Punycode or non-ASCII host (homograph risk)"], ["suspicious_tld", "+15", "TLD frequently abused for phishing"], ["no_https_keywords", "+15", "Credential keywords over plain HTTP"], ["deep_subdomains", "+15", "Four or more subdomain levels"], ["many_keywords", "+15", "Three or more phishing keywords"], ["hyphen_heavy_host", "+15", "Three or more hyphens in the host"], ["shortener", "+10", "URL shortener hides the destination"], ["long_url", "+10", "URL longer than 100 characters"], ["nonstandard_port", "+10", "Non-standard port"], ["open_redirect", "+10", "Another URL embedded in the query"], ["encoded_chars", "+8", "More than five percent-encoded characters"]], [2600, 1000, 6038], { mono: [0], center: [1], size: 18 }));
  c.push(sp());
  c.push(P("Used alone, the rules have perfect precision (no false positives) but only 37.4 % recall, because many phishing URLs trigger no rule. This is the motivation for adding a learned model."));
  c.push(H2("4.5 Machine-learning models and parameters"));
  c.push(P("Three diverse learners are trained on the 30 features and combined by soft voting (averaging predicted probabilities). Random forest and gradient boosting receive double weight because they scored best in cross-validation."));
  c.push(table(["Model", "Parameters", "5-fold CV F1 (train)", "Test F1 alone"], [["Logistic Regression", "StandardScaler; C = 1.0; max_iter = 2000; random_state = 42", "0.966", f3(U.systems["member:logreg"].f1)], ["Random Forest", "n_estimators = 300; min_samples_leaf = 2; n_jobs = -1; random_state = 42", "0.992", f3(U.systems["member:random_forest"].f1)], ["Gradient Boosting", "n_estimators = 200; max_depth = 3; random_state = 42", "0.993", f3(U.systems["member:grad_boost"].f1)], ["Soft-voting ensemble", "weights 1 : 2 : 2 over the three models above", "final model", "see 9.1"]], [2100, 4200, 1700, 1638], { hl: [3], size: 18 }));
  c.push(sp());
  c.push(P("Cross-validation uses stratified 5-fold splitting with seed 42 on the 5,865 training URLs."));
  c.push(H2("4.6 Hybrid risk score"));
  c.push(...CODE(["risk = 0.70 x P(phishing | ensemble) x 100  +  0.30 x rule_score", "", "allow-listed domain  -> risk capped at 5", "block-listed domain  -> risk forced to 100"]));
  c.push(P("The weights are defined in config.py (ML_WEIGHT = 0.70). Rules supply explainable evidence and catch obvious cases; the model generalises to combinations of weak signals that no single rule captures."));
  c.push(H2("4.7 What the model relies on"));
  const fi = Object.entries(U.feature_importances).slice(0, 8);
  c.push(table(["Rank", "Feature", "Random-forest importance"], fi.map((x, i) => [i + 1, x[0], x[1].toFixed(3)]), [1200, 4000, 4438], { mono: [1], center: [0, 2] }));
  c.push(sp());
  c.push(await img(R + "url_feature_importance.svg", 480, 290));
  c.push(CAP("Figure 2. Top URL features by random-forest importance."));

  // ---------------- 5 email
  c.push(H1("5. E-mail Analysis Module"));
  c.push(P("An e-mail is parsed with the standard-library MIME parser. The analyser extracts the sender, authentication results, body text, HTML links with their visible text, URLs and attachment names, and then applies forensic checks. Each check adds a weight to a header score capped at 100."));
  c.push(H2("5.1 Forensic checks"));
  c.push(table(["Group", "Finding", "Weight", "Condition"], [["Authentication", "spf_fail / spf_softfail", "+20 / +12", "Sending server not authorised for the domain"], ["", "dkim_fail / dkim_none", "+15 / +6", "Signature invalid / message not signed"], ["", "dmarc_fail / dmarc_none", "+20 / +5", "Domain's own policy says not authentic / no policy"], ["", "no_auth_results", "+10", "No Authentication-Results header at all"], ["Sender spoofing", "display_name_spoof", "+25", "Display name names a brand but the domain is not the brand's"], ["", "exec_freemail", "+25", "Executive title (CEO, CFO...) on a free-mail address"], ["", "reply_to_mismatch", "+15", "Reply-To domain differs from From domain"], ["", "return_path_mismatch", "+10", "Return-Path domain differs from From domain"], ["", "display_name_email", "+20", "Display name contains a different e-mail address"], ["Content", "credential_request", "+15", "Asks for password, card, bank or identity details"], ["", "urgency", "+12", "Two or more urgency or threat phrases"], ["", "financial_lure", "+12", "Gift cards, wire transfer, fees"], ["", "generic_greeting", "+5", "Dear customer / Dear user"], ["Links", "link_text_mismatch", "+30", "Visible link text shows one domain, href goes to another"], ["Attachments", "dangerous_attachment", "+35", ".exe, .scr, .bat, .cmd, .js, .vbs, .jar, .iso, .lnk, .msi"], ["", "macro / html attachment", "+25", ".docm .xlsm .pptm / .html .htm"], ["", "archive_attachment", "+12", ".zip .rar .7z .gz"], ["", "double_extension", "+15", "For example invoice.pdf.exe"]], [1500, 2400, 1200, 4538], { size: 18 }));
  c.push(sp());
  c.push(H2("5.2 Text classifier"));
  c.push(P("The subject and body are vectorised with TF-IDF using unigrams and bigrams (ngram_range = (1, 2)), a minimum document frequency of 2, sub-linear term frequency and English stop-word removal. A logistic regression with C = 4.0 and random_state = 42 classifies the text. On the held-out e-mails it alone reaches precision 0.997 and recall 0.960."));
  c.push(H2("5.3 Stacking: fusing all signals"));
  c.push(P("A second-level logistic regression (C = 2.0) combines six signals into the final e-mail risk. Importantly, the text probability fed to the stacker during training comes from 5-fold out-of-fold predictions, so the stacker never sees a prediction that the text model made on its own training data (this avoids leakage and over-optimistic fusion)."));
  c.push(table(["Stacker input", "Meaning", "Learned coefficient"], [["header_score", "Forensic header score / 100", "6.85"], ["text_prob", "Text-model probability", "6.26"], ["url_max_risk", "Highest hybrid risk among all embedded links / 100", "2.80"], ["attachment_risk", "1 if any risky attachment", "1.69"], ["link_mismatch", "1 if anchor text and target disagree", "0.70"], ["n_urls", "Number of links (capped at 5) / 5", "-4.72"]], [2600, 4600, 2438], { mono: [0], center: [2] }));
  c.push(sp());
  c.push(P("The negative coefficient for n_urls is an artefact of the synthetic data: business-e-mail-compromise messages have no link at all but are strongly malicious, so link count is partly anti-correlated with phishing in this data set. With real mail this coefficient would be re-learned. It is a good example of why the model must be retrained on real data (Section 12)."));
  c.push(P("The e-mail risk is the stacker's phishing probability multiplied by 100. A block-listed sender or link forces a high risk. Quarantined messages are delivered with links disabled and a warning banner."));

  // ---------------- 6 html
  c.push(H1("6. Web-Page (HTML) Analysis Module"));
  c.push(P("The HTML analyser parses a page without executing scripts or loading resources. Its indicators and weights are listed below. The page score is combined with the URL risk of the page address: risk = min(100, 0.6 x page score + 0.6 x URL risk)."));
  c.push(table(["Indicator", "Weight", "Why it matters"], [["external_form_action", "+40", "A form posts typed data to a different domain than the page"], ["brand_on_foreign_domain", "+25", "Login page mentions a brand but is hosted elsewhere (uses the brand-ownership table)"], ["hidden_iframe", "+25", "Zero-size or display:none iframe (tracking, drive-by)"], ["obfuscated_js", "+20", "eval(), atob(), unescape() or fromCharCode in scripts"], ["password_field", "+15", "Page requests a password"], ["insecure_form", "+15", "Password form submits over plain HTTP"], ["status_bar_spoof", "+15", "onmouseover handler rewriting the status bar"], ["right_click_disabled", "+10", "Context menu blocked to hinder inspection"], ["meta_refresh", "+10", "Automatic redirect via meta refresh"], ["external_links", "+10", "More than 80 % of four or more links lead off-site"], ["empty_form_action", "+5", "Password form with empty action (script-handled submit)"]], [2800, 1000, 5838], { mono: [0], center: [1], size: 18 }));
  c.push(sp());
  c.push(P("In the demo, the sample fake PayPal page (password form posting to collector.evil-host.tk, hidden iframe, eval(atob(...)), disabled right-click, meta refresh and four off-site links) reaches risk 100 and is blocked, while a clean documentation page scores 0.1 and is allowed."));

  // ---------------- 7 prevention
  c.push(H1("7. Prevention Engine"));
  c.push(H2("7.1 Policy"));
  c.push(table(["Risk score", "Label", "URL / page action", "E-mail action"], [["0 to under 30", "legitimate", "ALLOW", "ALLOW"], ["30 to under 50", "suspicious", "WARN (banner, explicit confirmation)", "WARN"], ["50 to 100", "phishing", "BLOCK", "QUARANTINE (links disabled, banner, incident logged)"]], [1800, 1800, 3000, 3038]));
  c.push(P("The thresholds are WARN_AT = 30 and BLOCK_AT = 50 in config.py."));
  c.push(sp());
  c.push(H2("7.2 Mechanisms"));
  c.push(...BL([[B("Allow and block lists. "), new TextRun("data/allowlist.txt and data/blocklist.txt hold registered domains. Matching uses the real registered domain, so good.com@evil.top cannot borrow the trust of good.com, and good.com.evil.org does not match good.com.")], [B("Link neutralisation. "), new TextRun("Risky URLs in quarantined mail are replaced by [LINK DISABLED: hxxp://evil[.]com] and a warning banner is prepended.")], [B("Defanging. "), new TextRun("Indicators are displayed as hxxp and [.] so they cannot be clicked accidentally in logs, tickets or chat.")], [B("Feedback loop. "), new TextRun("With auto_block enabled, domains of confirmed BLOCK verdicts are appended to the blocklist so the next attempt is blocked instantly with reason 'blocklist'.")], [B("User advice. "), new TextRun("Each fired rule maps to a plain-language tip (for example 'Check the registered domain, not the brand name in the subdomain').")], [B("Audit trail. "), new TextRun("Every decision is appended to logs/audit.jsonl with timestamp, type, target, risk, action and reasons.")]]));
  c.push(H2("7.3 REST API"));
  c.push(table(["Endpoint", "Method", "Body", "Result"], [["/scan/url", "POST", "{\"url\": \"...\"}", "URL verdict"], ["/scan/email", "POST", "{\"raw\": \"<RFC-822 text>\"}", "E-mail verdict"], ["/scan/html", "POST", "{\"html\": \"...\", \"url\": \"...\"}", "Page verdict"], ["/health", "GET", "-", "{\"status\": \"ok\"}"], ["/stats", "GET", "-", "Counters of scans and actions"]], [2000, 1100, 3400, 3138], { mono: [0, 2], size: 18 }));
  c.push(P("The server limits request size to 2 MB, validates input (400 for bad requests, 404 for unknown paths) and never returns stack traces to clients (500 with a generic message)."));
  c.push(H2("7.4 Optional LLM explanation"));
  c.push(P("If the environment variable GEMINI_API_KEY is set, a short plain-English explanation of each verdict is requested from Google Gemini. Only the already computed verdict (defanged URL, label, risk, rule names) is sent, never the raw e-mail. The key is read from the environment and is never stored in the project. If no key is present or the network fails, a deterministic local explanation is used. In this build only the offline fallback was exercised."));

  // ---------------- 8 data
  c.push(H1("8. Data and Evaluation Methodology"));
  c.push(H2("8.1 Synthetic data"));
  c.push(P("Real phishing feeds (PhishTank, OpenPhish) require network access and licences and change daily, so the project generates its own deterministic data (random seed 42). The generators reproduce documented attack techniques and also inject hard cases so that the evaluation is not trivially perfect."));
  c.push(table(["Data set", "Size", "Content"], [["URLs", "8,000 requested, 7,882 unique, 50 % phishing", "13 phishing techniques; legitimate URLs from about 120 real-looking domains plus small-business, hosting, tracking-parameter, shortener, redirect and login-page cases"], ["E-mails", "2,400, 50 % phishing", "Credential phishing, BEC, malicious-attachment lures and prize scams; legitimate notices, receipts, newsletters, colleague mail and invoices"]], [1600, 3000, 5038]));
  c.push(sp());
  c.push(P([B("Phishing URL techniques generated: "), new TextRun("brand_subdomain, typosquat, combosquat, ip_host, at_symbol, punycode, long_obfuscated, shortener, free_hosting, deep_subdomain, hard_clean (compromised, clean-looking site), redirect_param and exec_download.")]));
  c.push(P([B("Hard cases. "), new TextRun("Clean-looking compromised sites; legitimate login and security pages containing phishing keywords; legitimate URL shorteners; long tracking parameters; genuine but alarming-sounding service notices (hard negatives); polite, benign-sounding phishing with only the link or headers as evidence (hard positives); and phishing sent with fully passing authentication.")]));
  c.push(H2("8.2 Splitting and leakage control"));
  c.push(...BL(["URLs are split by registered domain using a hash, so no domain appears in both training (5,865 URLs) and test (2,017 URLs). The pipeline asserts that the overlap is zero.", "E-mails use a stratified 75 / 25 split (1,800 train, 600 test).", "The e-mail stacker is trained on out-of-fold text probabilities.", "All thresholds are fixed in advance (risk at least 50 is phishing); nothing is tuned on the test set."]));
  c.push(H2("8.3 Metrics"));
  c.push(P("Precision is the share of blocked items that really were phishing; recall is the share of phishing that was caught; F1 is their harmonic mean; the false-positive rate (FPR) is the share of legitimate items wrongly blocked; ROC-AUC measures ranking quality across all thresholds."));

  // ---------------- 9 results
  c.push(H1("9. Results"));
  c.push(H2("9.1 URL detection (test set: 2,017 URLs)"));
  const rowsU = [["rules_only", "Rules only"], ["ml_only", "ML only"], ["HYBRID (production)", "Hybrid, BLOCK only (production)"], ["HYBRID flagged (WARN+BLOCK)", "Hybrid, WARN or BLOCK"]].map(([k, n]) => { const m = U.systems[k]; return [n, f3(m.accuracy), f3(m.precision), f3(m.recall), f3(m.f1), f3(m.roc_auc), f3(m.false_positive_rate)]; });
  c.push(table(["System", "Accuracy", "Precision", "Recall", "F1", "ROC-AUC", "FPR"], rowsU, [2938, 1100, 1100, 1000, 1000, 1300, 1200], { center: [1, 2, 3, 4, 5, 6], hl: [2], size: 18 }));
  c.push(sp());
  const m = U.systems["HYBRID (production)"];
  c.push(P([B("Confusion matrix (hybrid, BLOCK): "), new TextRun(`TN ${m.tn}, FP ${m.fp}, FN ${m.fn}, TP ${m.tp}. Average single-URL scan latency is ${U.avg_latency_ms} ms.`)]));
  c.push(P([B("Interpretation. "), new TextRun("Rules alone are perfectly precise but miss most attacks (recall 0.374). The learned model has high recall (0.972) but a 7.4 % false-positive rate, mostly legitimate shortened and tracking-heavy URLs. The production hybrid blocks only when confident (precision 0.971, FPR 2.6 %), and sends uncertain items to WARN. Counting WARN as a detection, 99.1 % of phishing URLs are at least flagged. This trade-off protects users from wrongful blocks while still alerting them to doubtful links.")]));
  c.push(await img(R + "url_roc.svg", 330, 346));
  c.push(CAP("Figure 3. ROC curve of the URL detector on the held-out test set (AUC 0.988)."));
  c.push(H2("9.2 Recall by attack technique"));
  const tq = Object.entries(U.recall_by_technique).sort((a, b) => b[1].detected - a[1].detected || b[1].flagged - a[1].flagged);
  c.push(table(["Technique", "Test count", "Blocked", "Flagged (WARN + BLOCK)"], tq.map(([k, v]) => [k, v.n, pc(v.detected), pc(v.flagged)]), [3000, 1800, 2000, 2838], { center: [1, 2, 3], mono: [0], size: 18 }));
  c.push(sp());
  c.push(P("Ten techniques are blocked 100 %. Shorteners are intentionally not blocked (5.2 %) but are flagged 99.3 %, because a shortened link looks identical whether it is benign or malicious and its destination cannot be judged from the text alone. Homograph (76.3 %) and typosquat (91.1 %) domains are the hardest genuine cases."));
  c.push(H2("9.3 E-mail detection (test set: 600 e-mails)"));
  const rowsE = [["header_rules_only", "Header forensics only"], ["text_model_only", "Text model only"], ["FULL PIPELINE", "Full pipeline (stacked)"]].map(([k, n]) => { const x = E.systems[k]; return [n, f3(x.accuracy), f3(x.precision), f3(x.recall), f3(x.f1), f3(x.roc_auc), f3(x.false_positive_rate)]; });
  c.push(table(["System", "Accuracy", "Precision", "Recall", "F1", "ROC-AUC", "FPR"], rowsE, [2938, 1100, 1100, 1000, 1000, 1300, 1200], { center: [1, 2, 3, 4, 5, 6], hl: [2], size: 18 }));
  c.push(sp());
  const x = E.systems["FULL PIPELINE"];
  c.push(P(`Full pipeline confusion matrix: TN ${x.tn}, FP ${x.fp}, FN ${x.fn}, TP ${x.tp}. Recall by family: BEC 100 %, attachment lures 100 %, credential phishing 98.8 %, prize scams 97.3 %. Fusing header, text, link and attachment signals beats each single signal, and this is enforced by an automated test. The near-perfect AUC must be read with care because the e-mails are synthetic (Section 12).`));
  c.push(await img(R + "email_roc.svg", 330, 346));
  c.push(CAP("Figure 4. ROC curve of the full e-mail pipeline on the held-out test set."));

  // ---------------- 10 testing
  c.push(H1("10. Testing"));
  c.push(P("The suite contains 75 tests (run with python3 tests/run_tests.py); all 75 pass in about 2 seconds, with zero failures, errors or skips. Output is stored in logs/tests.log, outputs/02_tests.txt and reports/test_results.json."));
  c.push(table(["Test file", "Tests", "What is verified"], [["test_url_features.py", "22", "Host splitting, multi-part suffixes, Levenshtein and entropy, every rule, '@' trick, leetspeak, homoglyph, transposition typos, official-brand domains not flagged, garbage and malformed input never crashes"], ["test_detector.py", "16", "Legitimate URLs allowed, phishing blocked, shorteners warned, verdict schema and defanging, list overrides, feedback loop, e-mail verdicts, sanitised body, HTML verdicts, junk input, REST API (200, 400, 404)"], ["test_prevention.py", "8", "List matching including userinfo-trick resistance, persistence, policy bands, defang, neutralise, advice"], ["test_email_analyzer.py", "7", "SPF/DKIM/DMARC parsing, Reply-To mismatch, display-name spoof, BEC, double extension, URL punctuation, missing headers, malformed mail"], ["test_model_quality.py", "7", "Quality gates: AUC at least 0.97, precision at least 0.94, FPR at most 5 %, flagged recall at least 0.93, hybrid F1 beats rules by 0.2, e-mail F1 at least 0.95 and FPR at most 2 %, fusion at least as good as single signals, latency under 250 ms"], ["test_html_analyzer.py", "4", "Fake login page triggers eight indicators and scores 100; clean page scores 0; same-domain login stays low; garbage HTML"], ["test_inspector.py", "7", "Interactive tool: every analysis step printed for URL, e-mail, HTML and batch inputs; template e-mail; help, quit and error handling; junk input never crashes"], ["test_dataset.py", "4", "Determinism, class balance, no train/test domain leakage, generated e-mails parse"]], [2500, 800, 6338], { mono: [0], center: [1], size: 18 }));
  c.push(sp());
  c.push(P([B("Bugs found by the tests during development. "), new TextRun("(1) Swapped-letter typos such as paypla.com were missed by plain Levenshtein distance; fixed with Damerau-Levenshtein. (2) The HTML brand check mis-fired on domains that contained the brand name; fixed by using the brand-ownership table. An early e-mail data set also produced a suspicious score of 1.000 for every metric, which revealed that the synthetic text was too easy; hard negatives and hard positives were added.")]));

  // ---------------- 11 run
  c.push(H1("11. How to Run"));
  c.push(...CODE(["cd CyberSecurity/PhishGuard", "pip install -r requirements.txt", "./scripts/run_all.sh                # runs everything, logs everything", "", "export PYTHONPATH=src", "python3 -m phishguard train         # data + models + reports", "python3 tests/run_tests.py          # 75 tests", "python3 -m phishguard demo          # live showcase", "python3 -m phishguard scan-url \"http://paypa1-secure-login.xyz/verify\"", "python3 -m phishguard scan-email samples/phishing_paypal.eml", "python3 -m phishguard scan-html samples/fake_login.html --url http://secure-paypal-login.xyz/signin", "python3 -m phishguard serve --port 8765", "", "./scripts/try_it.sh                  # interactive: type your own URLs / e-mails / pages"]));
  c.push(P("The master script run_all.sh performs six steps: (1) environment check; (2) data generation, training and evaluation; (3) the test suite; (4) the live demo of URLs, e-mails, pages, prevention and the REST API; (5) CLI examples; (6) a summary of all artefacts. The whole run takes about 90 seconds."));
  c.push(table(["Artefact", "Location"], [["Console output of each step", "outputs/01_train_and_evaluate.txt ... 05_cli_scan_email.txt"], ["Combined run log", "logs/run_all.log"], ["Application log", "logs/phishguard.log"], ["Test log", "logs/tests.log"], ["JSON audit trail", "logs/audit.jsonl"], ["Metrics and charts", "reports/url_metrics.json, email_metrics.json, confusion matrices, ROC and importance SVGs, test_results.json"], ["Trained models", "models/url_model.joblib, email_model.joblib"], ["Generated data", "data/urls.csv, data/emails.jsonl"]], [3200, 6438], { size: 19 }));
  c.push(sp());

  // ---------------- 12 limits
  c.push(H1("12. Limitations and Future Work"));
  c.push(H2("12.1 Limitations"));
  c.push(...BL([[B("Synthetic data. "), new TextRun("Accuracy on real traffic will be lower. The generators reproduce documented techniques and include hard cases, but they cannot capture every real-world variation. The pipeline can ingest real feeds (dataset.load_urls_csv) and the quality gates will show whether performance holds.")], [B("Lexical limits. "), new TextRun("Shortened URLs and compromised-but-clean-looking sites cannot be judged from text alone; they are routed to WARN rather than BLOCK.")], [B("Template vocabulary. "), new TextRun("The e-mail text model learns the generator's vocabulary; real mail will weaken text accuracy and the stacker's coefficients (such as n_urls) must be re-learned.")], [B("No dynamic analysis. "), new TextRun("No JavaScript execution, screenshot or logo-similarity analysis is performed.")], [B("Static brand list. "), new TextRun("28 brands are covered; a real deployment should use a large, regularly updated list.")]]));
  c.push(H2("12.2 Future work"));
  c.push(...BL(["Train and evaluate on PhishTank, OpenPhish and a real e-mail corpus.", "Add redirect expansion, domain age and WHOIS, TLS certificate and reputation look-ups.", "Add visual similarity (logo and screenshot comparison) and sandbox detonation of attachments.", "Provide a browser extension and a mail-gateway plug-in using the REST API.", "Learn the hybrid weights and thresholds from labelled operational data, and monitor model drift."]));

  // ---------------- 13 conclusion
  c.push(H1("13. Conclusion"));
  c.push(P("PhishGuard demonstrates that layering fast explainable rules, a learned model and e-mail-protocol evidence yields detection that is both accurate and understandable. On held-out data it blocks URLs with 97.1 % precision and a 2.6 % false-positive rate while flagging 99.1 % of phishing, and its e-mail pipeline reaches F1 0.995 on the synthetic test set. Beyond detection, the prevention engine acts on the verdict by warning, blocking, quarantining, neutralising links, learning from confirmed cases and logging every decision. The complete workflow, with logs, reports and 75 passing tests, can be reproduced with a single command."));

  // ---------------- references
  c.push(H1("References"));
  c.push(...NL(["Sahoo, D., Liu, C., Hoi, S. Malicious URL Detection using Machine Learning: A Survey. arXiv:1701.07179, 2017.", "Kitterman, S. RFC 7208: Sender Policy Framework (SPF). IETF, 2014.", "Crocker, D. et al. RFC 6376: DomainKeys Identified Mail (DKIM) Signatures. IETF, 2011.", "Kucherawy, M., Zwicky, E. RFC 7489: Domain-based Message Authentication, Reporting and Conformance (DMARC). IETF, 2015.", "Anti-Phishing Working Group (APWG). Phishing Activity Trends Reports.", "Breiman, L. Random Forests. Machine Learning 45(1), 2001.", "Friedman, J. Greedy Function Approximation: A Gradient Boosting Machine. Annals of Statistics 29(5), 2001.", "Damerau, F. A technique for computer detection and correction of spelling errors. Communications of the ACM 7(3), 1964.", "Pedregosa, F. et al. Scikit-learn: Machine Learning in Python. Journal of Machine Learning Research 12, 2011.", "PhishTank (phishtank.com) and OpenPhish (openphish.com): community phishing feeds."], "refs"));

  // ---------------- appendix
  c.push(H1("Appendix A. Configuration Parameters"));
  c.push(table(["Parameter", "Value", "Where / effect"], [["SEED", "42", "config.py: all random generators, splits and models"], ["N_URLS / N_EMAILS", "8000 / 2400", "config.py: generated data volume"], ["WARN_AT", "30", "config.py: risk at which WARN begins"], ["BLOCK_AT", "50", "config.py: risk at which BLOCK or QUARANTINE begins"], ["ML_WEIGHT", "0.70", "config.py: share of ML probability in the hybrid URL score"], ["Allow-list cap", "5", "detector.py: risk of allow-listed domains"], ["Voting weights", "1 : 2 : 2", "models.py: LR : RF : GB"], ["RF trees / leaf", "300 / 2", "models.py"], ["GB estimators / depth", "200 / 3", "models.py"], ["LR (URL) C", "1.0", "models.py"], ["TF-IDF n-grams / min_df", "(1, 2) / 2", "models.py"], ["LR (text) C", "4.0", "models.py"], ["Stacker C", "2.0", "models.py"], ["CV folds", "5 (stratified)", "models.py and out-of-fold text probabilities"], ["API request limit", "2,000,000 bytes", "api.py"], ["Group-split test fraction", "0.25", "dataset.split_by_group"]], [3000, 2200, 4438], { mono: [0], size: 18 }));
  c.push(sp());
  c.push(H1("Appendix B. Sample Verdict"));
  c.push(P("Output of: python3 -m phishguard scan-url \"http://paypa1-secure-login.xyz/verify\" (abridged)."));
  c.push(...CODE(["URL   hxxp://paypa1-secure-login[.]xyz/verify", "risk  99.7/100 |###################| -> BLOCK (phishing)", "   - [brand_mismatch] Well-known brand name used on a domain the brand does not own", "   - [typosquat] Domain is a look-alike (typo / leetspeak) of a well-known brand", "   - [suspicious_tld] TLD frequently abused for phishing", "   - [no_https_keywords] Credential-style keywords over plain HTTP", "   * tip: Look closely: letters may be swapped, or '1'/'0' may replace 'l'/'o'."]));

  const doc = new Document({
    creator: "PhishGuard project team", title: "PhishGuard: Phishing Detection and Prevention - Technical Report",
    styles: { default: { document: { run: { font: "Calibri", size: 22 } } },
      paragraphStyles: [
        { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { font: "Cambria", size: 34, bold: true, color: INK }, paragraph: { spacing: { before: 360, after: 160 }, keepNext: true, outlineLevel: 0 } },
        { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { font: "Cambria", size: 27, bold: true, color: TEAL }, paragraph: { spacing: { before: 240, after: 120 }, keepNext: true, outlineLevel: 1 } },
        { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true, run: { font: "Cambria", size: 24, bold: true, color: INK }, paragraph: { spacing: { before: 160, after: 80 }, keepNext: true, outlineLevel: 2 } }] },
    numbering: { config: ["bul", "num", "life", "alg", "refs"].map(r => ({ reference: r, levels: [{ level: 0, format: r === "bul" ? LevelFormat.BULLET : LevelFormat.DECIMAL, text: r === "bul" ? "•" : "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 560, hanging: 360 } } } }] })) },
    sections: [{ properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 } } },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "PhishGuard technical report  |  page ", size: 18, color: "5B6B7F" }), new TextRun({ children: [PageNumber.CURRENT], size: 18, color: "5B6B7F" })] })] }) },
      children: c }]
  });
  fs.writeFileSync("../PhishGuard_Project_Report.docx", await Packer.toBuffer(doc));
  console.log("docx written");
})();
