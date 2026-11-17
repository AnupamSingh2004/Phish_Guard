const fs = require("fs");
const D = require("docx");
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, HeadingLevel, AlignmentType, WidthType, ShadingType, BorderStyle, LevelFormat, PageBreak, TableOfContents, Footer, PageNumber } = D;
const W = 9638, INK = "0E1A2B", TEAL = "0F7F74";

const P = (t, o = {}) => new Paragraph({ spacing: { after: 100, line: 272 }, ...o, children: Array.isArray(t) ? t : [new TextRun(t)] });
const B = t => new TextRun({ text: t, bold: true });
const H1 = t => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(t)] });
const H2 = t => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(t)] });
const BL = items => items.map(t => new Paragraph({ numbering: { reference: "bul", level: 0 }, spacing: { after: 50 }, children: Array.isArray(t) ? t : [new TextRun(t)] }));
const bd = { style: BorderStyle.SINGLE, size: 4, color: "B8C4D0" }, borders = { top: bd, bottom: bd, left: bd, right: bd };
function table(head, rows, widths, o = {}) {
  const mk = (t, w, h, j) => new TableCell({ width: { size: w, type: WidthType.DXA }, borders, margins: { top: 50, bottom: 50, left: 90, right: 90 }, shading: h ? { type: ShadingType.CLEAR, fill: INK } : undefined,
    children: [new Paragraph({ spacing: { after: 0 }, alignment: o.center && o.center.includes(j) ? AlignmentType.CENTER : AlignmentType.LEFT, children: [new TextRun({ text: String(t), bold: h || (o.boldFirst && j === 0), color: h ? "FFFFFF" : undefined, size: o.size || 19 })] })] });
  return new Table({ width: { size: W, type: WidthType.DXA }, columnWidths: widths, rows: [new TableRow({ tableHeader: true, children: head.map((t, j) => mk(t, widths[j], true, j)) })].concat(rows.map(r => new TableRow({ cantSplit: true, children: r.map((t, j) => mk(t, widths[j], false, j)) }))) });
}
const sp = () => new Paragraph({ spacing: { after: 100 }, children: [] });
// question blocks
const Q = (n, q, a) => [new Paragraph({ keepNext: true, spacing: { before: 140, after: 50 }, children: [new TextRun({ text: `Q${n}. `, bold: true, color: TEAL }), new TextRun({ text: q, bold: true })] }), new Paragraph({ spacing: { after: 80, line: 272 }, indent: { left: 360 }, children: [new TextRun(a)] })];
const DQ = (n, q) => [new Paragraph({ pageBreakBefore: n > 1, heading: HeadingLevel.HEADING_2, children: [new TextRun(`D${n}. ${q}`)] })];

const c = [];
c.push(new Paragraph({ spacing: { before: 2200, after: 200 }, children: [new TextRun({ text: "PHISHGUARD  |  PRESENTATION PREPARATION", size: 26, bold: true, color: TEAL })] }));
c.push(new Paragraph({ spacing: { after: 240 }, children: [new TextRun({ text: "Questions and Answers for the Project Evaluation", size: 52, bold: true, color: INK, font: "Cambria" })] }));
c.push(new Paragraph({ spacing: { after: 500 }, children: [new TextRun({ text: "30 short-answer and 10 detailed-answer questions covering every phase of the project: idea and brainstorming, requirements, design, data, implementation, evaluation, testing and the modifications made along the way.", size: 25, color: "3B4A5C" })] }));
c.push(table(["Section", "Content"], [["Part 1", "Project at a glance: key numbers to memorise"], ["Part 2", "Project phases, from idea to delivery"], ["Part 3", "30 short questions (Q1 to Q30)"], ["Part 4", "10 detailed questions (D1 to D10)"], ["Part 5", "Tips for answering and a live-demo checklist"]], [1800, 7838], { size: 21, boldFirst: true }));
c.push(new Paragraph({ children: [new PageBreak()] }));
c.push(new Paragraph({ spacing: { after: 160 }, children: [new TextRun({ text: "Contents", bold: true, size: 34, font: "Cambria", color: INK })] }));
c.push(new TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-2" }));
c.push(new Paragraph({ children: [new PageBreak()] }));

// ---------------- PART 1
c.push(H1("Part 1. Project at a Glance"));
c.push(P("Memorise these numbers. They are all measured and reproducible with ./scripts/run_all.sh."));
c.push(table(["Item", "Value"], [
  ["What it is", "Phishing detection and prevention toolkit for URLs, e-mails (.eml) and web pages (HTML)"],
  ["Approach", "Hybrid: 16 explainable rules + machine-learning ensemble + e-mail header forensics + prevention policy"],
  ["URL features / rules / brands", "30 features, 16 weighted rules, 28 protected brand names"],
  ["URL models", "Logistic Regression + Random Forest (300 trees) + Gradient Boosting (200, depth 3), soft vote 1:2:2"],
  ["Hybrid formula", "risk = 0.70 x ML probability x 100 + 0.30 x rule score; bands ALLOW < 30, WARN 30 to 50, BLOCK/QUARANTINE >= 50"],
  ["Data", "8,000 URLs requested (7,882 unique, 50 % phishing, 13 techniques); 2,400 e-mails (4 families); seed 42"],
  ["Split", "URLs: by registered domain, train 5,865 / test 2,017, zero shared domains. E-mails: 1,800 / 600"],
  ["URL result (production, BLOCK)", "Precision 0.971, recall 0.846, F1 0.904, ROC-AUC 0.988, false-positive rate 2.6 %"],
  ["URL result (WARN + BLOCK)", "Recall 99.1 % of phishing flagged; false-positive rate 8.3 %"],
  ["Rules only / ML only", "Rules: precision 1.00 but recall 0.374. ML: recall 0.972 but false-positive rate 7.4 %"],
  ["E-mail result (full pipeline)", "Precision 1.000, recall 0.990, F1 0.995 (297 TP, 300 TN, 0 FP, 3 FN). Header only F1 0.940, text only F1 0.978"],
  ["Speed", "About 40 ms per URL; whole run_all.sh about 90 seconds"],
  ["Tests", "75 tests, all passing, including quality gates that fail on regression"],
  ["Cross-validation F1 (5-fold)", "LogReg 0.966, Random Forest 0.992, Gradient Boosting 0.993"],
  ["Repository", "github.com/AnupamSingh2004/Phish_Guard (main branch)"]], [2900, 6738], { size: 18, boldFirst: true }));
c.push(sp());

// ---------------- PART 2
c.push(H1("Part 2. Project Phases, from Idea to Delivery"));
c.push(P("This table summarises what was done in each phase. Use it to answer any question of the form 'how did you build it' or 'what changed along the way'."));
c.push(table(["#", "Phase", "What was done", "Outcome"], [
  ["1", "Idea and brainstorming", "Chose phishing as the topic because it is the most common social-engineering attack. Compared four project shapes: URL-only classifier, e-mail filter, browser extension, or a complete toolkit.", "Decided on a complete toolkit covering detection and prevention, with explainability."],
  ["2", "Requirements and scope", "Fixed what must be delivered: URLs, e-mails and pages; explain every verdict; prevention actions; evaluation with proof; tests; logs; a one-command demo.", "Written objectives: Detect, Explain, Prevent, Prove."],
  ["3", "Research and design", "Compared blocklists, heuristics, ML, content/visual analysis and e-mail authentication. Chose a hybrid with static, offline analysis.", "Architecture: analysers, ML, risk fusion, policy engine, REST API."],
  ["4", "Data strategy", "Real feeds need network access and licences, so a deterministic generator of 13 attack techniques and 4 e-mail families was built, with hard cases.", "8,000 URLs and 2,400 e-mails, seed 42, group split without leakage."],
  ["5", "Implementation", "Built in layers: config and logging; URL features and rules; e-mail and HTML analysers; models; detector; prevention; REST API; CLI; evaluation pipeline.", "A Python package with about a dozen modules."],
  ["6", "Evaluation", "Trained on the training split only; measured on unseen domains; compared rules only, ML only and hybrid; measured recall per attack technique.", "Reports, confusion matrices, ROC and importance charts."],
  ["7", "Testing", "Unit, integration, API and model-quality tests; fuzz-like junk input tests; automated run with logs.", "75 passing tests; metric gates that fail the build on regression."],
  ["8", "Modifications and fixes", "Several defects and weaknesses found by tests and results were fixed (see D8).", "Higher recall on typosquats, honest e-mail results, clearer policy."],
  ["9", "Tooling for demonstration", "Master script run_all.sh with six stages and full logging; interactive tool try_it.sh to type your own inputs.", "Everything can be shown live, with every step visible."],
  ["10", "Documentation and delivery", "README, 30-slide presentation, 19-page technical report, this Q&A; code published to GitHub in logical commits.", "Reproducible, documented, version-controlled project."]], [450, 1900, 4400, 2888], { size: 17, center: [0] }));

// ---------------- PART 3
c.push(new Paragraph({ children: [new PageBreak()] }));
c.push(H1("Part 3. Thirty Short-Answer Questions"));
c.push(H2("A. Idea, problem and scope (Q1 to Q4)"));
let n = 1;
const S = (q, a) => c.push(...Q(n++, q, a));
S("What problem does your project solve?", "It automatically decides whether a URL, an e-mail or a web page is phishing, explains why in plain language, and takes a protective action (allow, warn, block or quarantine) so a user is stopped before giving away credentials.");
S("Why did you choose phishing as the topic?", "Phishing is the most common way attackers gain a first foothold because it targets people, not software flaws. It is also a good machine-learning problem with clear technical indicators in URLs, headers and page content.");
S("How is this different from a simple blocklist?", "A blocklist only knows past attacks, and phishing sites live for hours. PhishGuard judges new, never-seen sites from their structure and behaviour, and still supports a blocklist for known-bad domains.");
S("Why do you cover URLs, e-mails and web pages, not just one?", "They are three stages of the same attack: the e-mail is the lure, the URL is the link, the page is the trap. Each stage offers different evidence, and combining them is stronger than any single view.");
c.push(H2("B. Design decisions (Q5 to Q8)"));
S("Why a hybrid of rules and machine learning?", "Rules are explainable and never raised a false alarm in testing (precision 1.00), but caught only 37.4 % of attacks. ML caught 97.2 % but wrongly flagged 7.4 % of good sites. Fusing them gave 97.1 % precision with a 2.6 % false-positive rate, plus reasons for every verdict.");
S("Why is the analysis static and offline?", "We never visit a suspicious site and never run its scripts. This is safe (no infection risk), private (no URL leaves the machine), fast (about 40 ms) and works without internet.");
S("What is the 0 to 100 risk score and why three actions?", "The score combines all evidence. Below 30 is ALLOW, 30 to 50 is WARN, 50 and above is BLOCK (QUARANTINE for e-mail). A middle WARN band avoids wrongly blocking uncertain items, such as shortened links, while still alerting the user.");
S("Why is explainability important?", "Users and analysts must trust and act on a verdict. Every result lists named reasons (for example typosquat, SPF fail) with weights, and each reason maps to a plain-language tip, which also trains users to spot phishing themselves.");
c.push(H2("C. Data and validity (Q9 to Q12)"));
S("Why did you use synthetic data?", "Real feeds such as PhishTank or OpenPhish need network access and licences and change daily, which hurts reproducibility. Our generator reproduces 13 documented attack techniques with a fixed seed, so every result can be repeated exactly. The code can load a real CSV feed with load_urls_csv.");
S("Can results on synthetic data be trusted?", "They show the system works correctly on those techniques and that the method is sound, but real-world accuracy will be lower. We state this openly, added hard cases so scores are not trivial, and designed the pipeline so real data can be swapped in and the same quality gates re-run.");
S("What is data leakage and how did you prevent it?", "Leakage is when test information influences training, giving inflated scores. We split URLs by registered domain so no domain appears in both sets (an assertion checks the overlap is zero), and the e-mail stacker is trained on out-of-fold predictions.");
S("What are the 'hard cases' in your data?", "Clean-looking compromised sites, legitimate login pages and shorteners, tracking-heavy URLs, genuine but alarming service notices (hard negatives), polite phishing with only the link or headers as evidence, and phishing sent with fully passing authentication (hard positives).");
c.push(H2("D. Features and models (Q13 to Q19)"));
S("What features do you use and which matter most?", "30 features in four groups: length and structure, character statistics (entropy, digit ratio), security flags (IP host, '@', punycode, port) and lexical signals (keywords, TLD, brand mismatch, typosquat). The top random-forest importances are keyword count (0.177), brand mismatch (0.144) and host digit ratio (0.079).");
S("Why an ensemble of three models?", "Logistic regression is linear and fast, random forest and gradient boosting capture non-linear combinations. Soft voting averages their probabilities, reducing the weaknesses of any single model. Forest and boosting get double weight because they scored best in cross-validation (F1 0.992 and 0.993 versus 0.966).");
S("How do you detect typosquatting like paypa1.com?", "We fold look-alike characters (1 to l, 0 to o, rn to m, Cyrillic homoglyphs), then compare to 28 brand names with Damerau-Levenshtein distance (at most 1, or 2 for long names). A brand-ownership table avoids flagging the real domains, such as amazonaws.com.");
S("How do you handle homograph (look-alike Unicode) domains?", "Punycode hosts (xn--) are decoded to Unicode, common Cyrillic and Greek letters are folded to ASCII, and the result is compared with brand names. Punycode itself also fires a rule. This is our hardest category: 76.3 % blocked and 86.8 % flagged on the test set.");
S("Why TF-IDF with logistic regression for e-mail text, and not deep learning?", "It is fast, needs little data, is interpretable and reached precision 0.997 on our data. Deep models such as transformers would need far more data and compute, and add little here because headers and links carry much of the signal. They are a sensible future upgrade.");
S("How were hyperparameters chosen?", "We used sound defaults (300 trees, 200 boosting rounds of depth 3, C = 1.0 and 4.0) and compared the models with 5-fold stratified cross-validation. We did not run a large hyperparameter search, and nothing was tuned on the test set. A search on real data is future work.");
S("What is the stacker and why out-of-fold predictions?", "The stacker is a logistic regression that combines six e-mail signals (header score, text probability, highest link risk, link mismatch, attachment risk, link count). It is trained on out-of-fold text probabilities so it never sees predictions the text model made on its own training data, which would overstate its trust in the text model.");
c.push(H2("E. Implementation and prevention (Q20 to Q25)"));
S("How do you check SPF, DKIM and DMARC?", "We parse the Authentication-Results header added by the receiving mail server (pass, fail, softfail, none) and score failures. We do not do our own DNS lookups, which keeps analysis offline. A missing header is itself scored as a weak signal.");
S("How do you catch business e-mail compromise (BEC) that has no link?", "By header and content cues: an executive title used with a free-mail address (+25), display-name spoofing, Reply-To mismatch, urgency, and wire-transfer or gift-card wording, plus the text model. On the test set BEC detection was 100 %.");
S("What does the prevention layer do beyond detection?", "It applies the policy, disables risky links in quarantined mail with a warning banner, defangs indicators (hxxp, [.]), supports allow and block lists, learns from confirmed detections, gives user tips and records every decision in a JSON audit log.");
S("What is the feedback loop and could it be abused?", "With auto_block on, a domain judged BLOCK is added to the blocklist so repeat attempts are blocked instantly. Because an attacker could try to poison a blocklist, it is off by default and only adds domains that scored BLOCK. A production system would add human review.");
S("What is the REST API and is it secure?", "It exposes /scan/url, /scan/email, /scan/html, /health and /stats so a mail gateway or browser extension can use PhishGuard. It limits request size to 2 MB, validates input (400 and 404 errors), and never returns stack traces. Authentication and TLS would be added in production.");
S("What is the Gemini integration and how is the API key handled?", "An optional layer asks Google Gemini for a plain-English explanation of a verdict, sending only the computed result (defanged URL and rule names), never the raw e-mail. The key is read only from the GEMINI_API_KEY environment variable and is never stored in the code or repository. Without it, a local explanation is used.");
c.push(H2("F. Evaluation, testing and the future (Q26 to Q30)"));
S("What accuracy did you achieve?", "URLs (production, BLOCK): accuracy 0.910, precision 0.971, recall 0.846, F1 0.904, AUC 0.988. Counting WARN as a detection, 99.1 % of phishing is flagged. E-mails: F1 0.995 with precision 1.000 and recall 0.990. All measured on unseen test data.");
S("Why do you emphasise precision and false-positive rate over accuracy?", "In security, wrongly blocking legitimate sites trains users to ignore warnings. A 2.6 % false-positive rate with 97.1 % precision means blocks are trustworthy. Plain accuracy can hide this, and recall alone ignores the cost of false alarms.");
S("Where does your system fail?", "Shortened URLs (blocked 5.2 %, flagged 99.3 %) because the destination is hidden, homograph domains (76.3 % blocked), and compromised but clean-looking sites (93.8 % blocked). These are real limits of text-only analysis, and they are routed to WARN instead of being hidden.");
S("How did you test the project?", "75 automated tests: 22 on URL features and rules, 16 on the detector and REST API, 8 on prevention, 7 each on the e-mail analyser, model-quality gates and the interactive tool, 8 on HTML and dataset, all passing in about 2.5 seconds. Quality gates fail the build if AUC, precision or false-positive rate regress.");
S("What would you do next to make it production-ready?", "Train on real feeds (PhishTank, OpenPhish) and real mail; add redirect expansion, domain age (WHOIS), TLS certificate and reputation lookups; add logo and screenshot similarity; sandbox attachments; build a browser extension and mail-gateway plug-in; and monitor model drift.");

// ---------------- PART 4
c.push(new Paragraph({ children: [new PageBreak()] }));
c.push(H1("Part 4. Ten Detailed Questions"));
c.push(P("Each answer can be spoken in two to four minutes. The structure is: short answer first, then the supporting detail."));

// D1
c.push(...DQ(1, "Walk us through the complete life cycle of the project, from idea to final implementation."));
c.push(P([B("Short answer: "), new TextRun("we moved through ten phases: idea, requirements, research and design, data strategy, implementation, evaluation, testing, modifications, demonstration tooling and documentation. Each phase produced something concrete and was checked before the next.")]));
c.push(...BL([
  [B("1. Idea and brainstorming. "), new TextRun("We picked phishing because it is the dominant social-engineering attack. We weighed four project shapes: a URL-only classifier (simple but narrow), an e-mail filter (needs mail data), a browser extension (hard to demonstrate) and a complete toolkit. We chose the toolkit because it shows the whole attack chain, lure, link and page, and allows both detection and prevention.")],
  [B("2. Requirements. "), new TextRun("We fixed four objectives: Detect, Explain, Prevent, Prove. Prove meant measured evaluation, automated tests and complete logs.")],
  [B("3. Research and design. "), new TextRun("We compared blocklists, heuristics, ML, content and visual analysis and e-mail authentication, and concluded no single method suffices. We designed a hybrid: explainable rules, an ML ensemble, e-mail forensics, a policy engine, all running offline for safety and speed.")],
  [B("4. Data strategy. "), new TextRun("Real feeds were not practical, so we built a seeded generator with 13 attack techniques and hard cases, and a leak-free split.")],
  [B("5. Implementation. "), new TextRun("Built bottom-up: configuration and logging; URL features and rules; e-mail and HTML analysers; models and the detector; the prevention engine; the REST API; the CLI; the evaluation pipeline.")],
  [B("6. Evaluation. "), new TextRun("Trained on training data only, measured on unseen domains, compared rules only versus ML only versus hybrid, and broke down recall by attack technique.")],
  [B("7. Testing. "), new TextRun("Unit, integration, API, junk-input and quality-gate tests, run by a script that writes logs.")],
  [B("8. Modifications. "), new TextRun("Tests and results exposed real weaknesses, which we fixed (see D8).")],
  [B("9. Demonstration tooling. "), new TextRun("run_all.sh runs and shows everything; try_it.sh lets anyone type their own input and see every step.")],
  [B("10. Documentation and delivery. "), new TextRun("README, presentation, technical report, this Q&A, and publication to GitHub in logical commits.")]]));

// D2
c.push(...DQ(2, "Explain the architecture and workflow with a worked example."));
c.push(P([B("Short answer: "), new TextRun("input goes through parsing, feature extraction, two parallel evidence paths (rules and ML), a fusion step, list overrides and a policy, and then produces an action, an explanation and an audit record.")]));
c.push(P("Worked example: the URL http://paypa1-secure-login.xyz/verify"));
c.push(table(["Step", "What happens", "Result"], [
  ["1 Parse", "Scheme http, host paypa1-secure-login.xyz, registered domain is the whole host", "The real owner is an unknown .xyz domain"],
  ["2 Features", "30 numbers: 3 keywords, 2 hyphens, suspicious TLD, no HTTPS, typosquat and brand-mismatch flags", "Feature vector"],
  ["3A Rules", "brand_mismatch +35, typosquat +40, suspicious_tld +15, no_https_keywords +15, many_keywords +15", "Rule score 100 (capped)"],
  ["3B ML", "LogReg 1.000, Random Forest 0.990, Gradient Boosting 1.000, soft vote", "P(phishing) = 0.996"],
  ["4 Fusion", "0.70 x 0.996 x 100 + 0.30 x 100", "Risk 99.7"],
  ["5 Lists", "Domain not listed", "No override"],
  ["6 Policy", "99.7 is at least 50", "BLOCK, label phishing"],
  ["7 Output", "Reasons, tips ('1 may replace l'), defanged hxxp://paypa1-secure-login[.]xyz/verify, log and audit entry", "User is stopped and informed"]], [1300, 5100, 3238], { size: 18, boldFirst: true }));
c.push(sp());
c.push(P([B("E-mail and page workflows. "), new TextRun("An e-mail is parsed into headers, text, links and attachments. Header forensics give a header score; the text model gives a probability; every link runs through the URL workflow above; a stacker fuses all signals into one risk; quarantined mail is delivered with links disabled. A page is analysed for off-site forms, hidden iframes and obfuscated scripts, and its score is combined with the risk of its address.")]));

// D3
c.push(...DQ(3, "Why did you combine rules and machine learning, and how did you choose the weights and thresholds?"));
c.push(P([B("Short answer: "), new TextRun("each alone has a different weakness, and the measured results show the combination is better balanced. The weights are a design choice validated by results, not a statistically tuned optimum.")]));
c.push(table(["System", "Precision", "Recall", "F1", "False-positive rate"], [["Rules only", "1.000", "0.374", "0.544", "0.000"], ["ML only", "0.930", "0.972", "0.951", "0.074"], ["Hybrid, BLOCK only (production)", "0.971", "0.846", "0.904", "0.026"], ["Hybrid, WARN or BLOCK", "0.924", "0.991", "0.956", "0.083"]], [3338, 1500, 1500, 1500, 1800], { center: [1, 2, 3, 4], size: 18 }));
c.push(sp());
c.push(...BL([
  [B("Rules: "), new TextRun("transparent and never wrong when they fire, but blind to anything not anticipated. Precision 1.00, recall 0.374.")],
  [B("ML: "), new TextRun("finds subtle combinations, but its 7.4 % false-positive rate came mostly from legitimate shortened and tracking-heavy URLs.")],
  [B("Fusion: "), new TextRun("risk = 0.70 x ML + 0.30 x rules. ML has the larger share because it generalises; rules add explainable evidence and push obvious cases decisively over the line. The weight ML_WEIGHT = 0.70 sits in config.py so it can be changed.")],
  [B("Thresholds: "), new TextRun("50 is the natural midpoint of a probability-like score and defines BLOCK. A WARN band from 30 to 50 holds uncertain items. This design deliberately trades some strict recall (0.846) for trustworthy blocks (precision 0.971), while WARN still flags 99.1 % of phishing.")],
  [B("Honesty point: "), new TextRun("we did not run an optimisation of the weights or thresholds. With real data, they should be tuned on a separate validation set, never the test set.")]]));

// D4
c.push(...DQ(4, "Describe your data and evaluation methodology. Why should the results be believed?"));
c.push(P([B("Short answer: "), new TextRun("the data is synthetic but deliberately hard; the evaluation prevents leakage; metrics are reported per technique; and every number is reproducible. We state clearly that real-world accuracy would be lower.")]));
c.push(...BL([
  [B("Generation. "), new TextRun("A seeded generator (seed 42) produces 8,000 URL samples, 7,882 after removing duplicates. Phishing covers 13 techniques: brand_subdomain, typosquat, combosquat, ip_host, at_symbol, punycode, long_obfuscated, shortener, free_hosting, deep_subdomain, hard_clean, redirect_param and exec_download. Legitimate URLs come from about 120 real-looking domains plus small-business, free-hosting, tracking, shortener, redirect and login-page cases. 2,400 e-mails cover credential phishing, BEC, attachment lures and prize scams, against newsletters, receipts, colleague mail, invoices and genuine security notices.")],
  [B("Hard cases. "), new TextRun("We added them because our first e-mail data produced a suspicious 1.000 on every metric, which showed the data was too easy.")],
  [B("Leakage control. "), new TextRun("URLs are split by registered domain with a hash (train 5,865, test 2,017), and an assertion confirms no shared domains. E-mails use a stratified 75/25 split. The stacker uses out-of-fold predictions. No threshold was tuned on the test set.")],
  [B("Metrics. "), new TextRun("Accuracy, precision, recall, F1, ROC-AUC and false-positive rate, with confusion matrices and recall per attack technique.")],
  [B("Reproducibility. "), new TextRun("Fixed seeds and one command regenerate every number.")],
  [B("Limits. "), new TextRun("Synthetic data cannot capture all real behaviour. The pipeline accepts real CSV feeds so the same evaluation can be repeated on real data.")]]));

// D5
c.push(...DQ(5, "Explain in detail how brand impersonation and typosquatting are detected, and what problems you found."));
c.push(P([B("Short answer: "), new TextRun("we normalise the domain so that disguises collapse back to the brand name, then measure the edit distance to a list of 28 brands, but only flag it when the domain does not truly belong to the brand.")]));
c.push(...BL([
  "Step 1: split the host into subdomain, label, suffix and registered domain, using a built-in table of multi-part suffixes such as co.uk and github.io because the public-suffix list is not available offline.",
  "Step 2: fold look-alikes. Digits become letters (0 to o, 3 to e, 4 to a, 5 to s, 7 to t), rn becomes m, vv becomes w, 1 becomes l or i, and common Cyrillic and Greek homoglyphs become ASCII. Punycode (xn--) hosts are decoded first.",
  "Step 3: compare the label and each hyphen-separated token (5 or more letters) with the brand names using Damerau-Levenshtein distance. A distance of 1 (2 for brand names of 8 or more letters) marks a typosquat.",
  "Step 4: brand mismatch fires when a brand appears in the subdomain, label or path of a domain the brand does not own. The ownership table says, for example, amazon is owned by amazon.com, amazon.in, amazon.co.uk and amazonaws.com, which prevents false alarms on genuine services.",
  "Rule weights: typosquat +40, brand mismatch +35, punycode +25."]));
c.push(P([B("Problems found and fixed. "), new TextRun("(1) The first version missed combination domains like paypa1-secure.xyz and Cyrillic look-alikes, so we added token-level folding and a confusables map. (2) A test showed paypla.com (two letters swapped) was missed, because plain Levenshtein counts a swap as two edits; we switched to Damerau-Levenshtein, where a swap costs one. (3) The HTML brand check used a loose pattern that fired on domains containing the brand name; we replaced it with the ownership table.")]));

// D6
c.push(...DQ(6, "Explain the e-mail pipeline in depth: signals, model, stacking and results."));
c.push(P([B("Short answer: "), new TextRun("four independent signal groups (headers, text, links, attachments) are fused by a learned stacker, and the fusion beats every single signal.")]));
c.push(table(["Signal", "How it is computed", "Test F1 alone"], [["Header forensics", "SPF/DKIM/DMARC results, Reply-To and Return-Path mismatch, display-name spoofing, executive on free-mail, urgency and credential wording, link text versus target, attachments; weights summed and capped at 100", "0.940"], ["Text model", "TF-IDF (1 and 2 grams, min_df 2, sub-linear TF, English stop-words) plus logistic regression C = 4.0", "0.978"], ["Link risk", "Each embedded link passes through the full URL pipeline; highest risk is used", "(input)"], ["Full pipeline", "Logistic-regression stacker (C = 2.0) over six inputs", "0.995"]], [1700, 6638, 1300], { size: 17, boldFirst: true, center: [2] }));
c.push(sp());
c.push(...BL([
  [B("Out-of-fold training: "), new TextRun("text probabilities fed to the stacker come from 5-fold cross-validation, so the stacker never sees a text prediction made on data the text model trained on.")],
  [B("Learned coefficients: "), new TextRun("header_score 6.85, text_prob 6.26, url_max_risk 2.80, attachment_risk 1.69, link_mismatch 0.70, n_urls -4.72.")],
  [B("The negative n_urls coefficient "), new TextRun("is an artefact of the synthetic data: BEC messages have no links but are strongly malicious, so link count is partly anti-correlated with phishing. We report it openly; real data would re-learn it.")],
  [B("Result: "), new TextRun("297 true positives, 300 true negatives, 0 false positives, 3 false negatives on 600 test e-mails. Recall by family: BEC 100 %, attachment lures 100 %, credential 98.8 %, prize 97.3 %.")],
  [B("Prevention: "), new TextRun("quarantined mail is delivered with a warning banner and links replaced by [LINK DISABLED: hxxp://evil[.]com].")]]));

// D7
c.push(...DQ(7, "How did you test the system, and how do you know it is correct?"));
c.push(P([B("Short answer: "), new TextRun("75 automated tests in seven areas, plus quality gates on the measured metrics, run by one script that writes logs. Tests also found real bugs.")]));
c.push(table(["Test file", "Tests", "What it proves"], [["test_url_features", "22", "Host splitting, multi-part suffixes, each rule, '@' trick, leetspeak, homoglyph, transposition typos, official brand domains not flagged, garbage input never crashes"], ["test_detector (incl. API)", "16", "Legitimate URLs allowed, phishing blocked, shorteners warned, JSON schema, defanging, list overrides, feedback loop, e-mail and page verdicts, REST API responses 200, 400 and 404"], ["test_prevention", "8", "List matching (including the good.com@evil.top trick), persistence, policy bands, defang, link neutralisation"], ["test_email_analyzer", "7", "SPF/DKIM/DMARC parsing, spoofing, BEC, double extensions, malformed mail"], ["test_model_quality", "7", "Gates: AUC at least 0.97, precision at least 0.94, false-positive rate at most 5 %, flagged recall at least 0.93, hybrid beats rules by 0.2 F1, e-mail F1 at least 0.95, fusion not worse than any single signal, latency under 250 ms"], ["test_inspector", "7", "Interactive tool prints every step; template e-mail; help, quit, error handling; junk input"], ["test_html_analyzer", "4", "Fake login page scores 100, clean page 0, same-domain login stays low"], ["test_dataset", "4", "Determinism, balance, no train/test domain leakage, generated mail parses"]], [2300, 800, 6538], { size: 17, boldFirst: true, center: [1] }));
c.push(sp());
c.push(...BL([
  [B("Robustness: "), new TextRun("empty strings, 5,000-character URLs, malformed ports, binary garbage, broken HTML and malformed e-mail must not crash the tool.")],
  [B("Security-flavoured tests: "), new TextRun("userinfo tricks cannot borrow an allowlisted domain; the API rejects bad or oversized input.")],
  [B("Regression protection: "), new TextRun("the quality gates fail if a later change lowers key metrics.")],
  [B("Bugs found by tests: "), new TextRun("transposition typos (paypla.com), the HTML brand-check misfire, and a stale-metrics problem that confirmed the gates work.")],
  [B("Evidence: "), new TextRun("logs/tests.log, outputs/02_tests.txt and reports/test_results.json.")]]));

// D8
c.push(...DQ(8, "What problems did you face and what modifications did you make along the way?"));
c.push(P([B("Short answer: "), new TextRun("we made about a dozen significant changes. Most came from tests or results revealing a weakness, which is how an evaluated project should evolve.")]));
c.push(table(["#", "Problem or finding", "Modification", "Effect"], [
  ["1", "Look-alike combinations (paypa1-secure.xyz) and Cyrillic homoglyphs were not flagged", "Token-level leetspeak folding and a confusables map", "Both now flagged as typosquat and brand mismatch"],
  ["2", "Swapped letters (paypla.com) missed", "Replaced Levenshtein with Damerau-Levenshtein", "Transposition typos caught"],
  ["3", "HTML brand check fired on domains containing the brand", "Used the brand-ownership table", "Correct decisions for legitimate and fake pages"],
  ["4", "E-mail metrics were a perfect 1.000, a sign the data was too easy", "Added hard negatives and hard positives (15 % each) plus terse phishing", "Realistic results: text only 0.978, full 0.995"],
  ["5", "Hybrid blocked fewer attacks than ML alone, and shorteners were 0 % blocked", "Reported WARN-inclusive recall; designed shorteners to go to WARN", "99.1 % flagged; trade-off explained honestly"],
  ["6", "Extracted URLs kept trailing punctuation ('page.')", "Strip trailing .,;:!?", "Correct link extraction"],
  ["7", "Stacker could have leaked text-model predictions", "Trained on out-of-fold predictions", "Honest fusion gain"],
  ["8", "Evaluation was slow and the console flooded with per-e-mail logs", "Features computed once; log_it flag", "Cleaner, faster runs"],
  ["9", "pytest and matplotlib were not installed", "Used standard-library unittest and hand-written SVG charts", "No extra dependencies"],
  ["10", "A safety check blocked deleting log files", "run_all.sh truncates logs itself", "Script remains self-contained"],
  ["11", "An API key was shared during the work", "Key only read from an environment variable; verified absent from all commits", "No secret in the repository"],
  ["12", "Users needed to test their own inputs", "Added the analyze and interactive commands and try_it.sh", "Every step visible for any input; tests grew from 68 to 75"],
  ["13", "Everything had to be self-contained and presentable", "Moved into its own PhishGuard folder; wrote README, deck, report; published in logical commits", "Clean, reproducible delivery"]], [450, 3150, 3300, 2738], { size: 16, center: [0] }));

// D9
c.push(...DQ(9, "Describe the prevention engine and the security design of the tool itself."));
c.push(P([B("Short answer: "), new TextRun("detection leads to action. The engine applies a policy, protects the user from the content, learns from confirmed cases and records everything. The tool is built so it cannot be turned against the user.")]));
c.push(...BL([
  [B("Policy: "), new TextRun("ALLOW below 30, WARN from 30 to 50, BLOCK (or QUARANTINE for e-mail) at 50 and above. Thresholds sit in config.py.")],
  [B("Lists: "), new TextRun("allow and block lists match on the real registered domain. A blocklisted domain forces risk 100; an allowlisted one caps risk at 5. The test good.com@evil.top shows the userinfo trick cannot borrow trust, and good.com.evil.org does not match good.com.")],
  [B("Link neutralisation: "), new TextRun("risky URLs in quarantined mail become [LINK DISABLED: hxxp://evil[.]com] and a banner is added.")],
  [B("Defanging: "), new TextRun("indicators are shown as hxxp and [.] in output and logs, so analysts cannot click them accidentally.")],
  [B("Feedback loop: "), new TextRun("domains of confirmed BLOCK verdicts can be auto-added to the blocklist. It is off by default to avoid blocklist poisoning; production would add human review.")],
  [B("Audit trail: "), new TextRun("every decision is appended to logs/audit.jsonl as one JSON object with time, type, target, risk, action and reasons.")],
  [B("Safe analysis: "), new TextRun("pages are parsed but never executed and no site is visited, so scanning cannot infect the machine or reveal the user.")],
  [B("API hardening: "), new TextRun("2 MB request limit, input validation, generic 500 errors without stack traces. A real deployment would add authentication, TLS and rate limiting.")],
  [B("Secrets and privacy: "), new TextRun("the optional Gemini layer reads its key only from the environment and sends only the verdict, never the e-mail body.")]]));

// D10
c.push(...DQ(10, "What are the limitations and threats to validity, and how would you take this to production?"));
c.push(P([B("Short answer: "), new TextRun("the main limitation is synthetic data, followed by the limits of text-only analysis. Each has a concrete mitigation, and the project is designed so that mitigation is a matter of swapping data and adding signals.")]));
c.push(table(["Limitation", "Why it matters", "Mitigation or next step"], [
  ["Synthetic data", "Real traffic is messier; real accuracy will be lower", "Load PhishTank, OpenPhish and a real mail corpus with load_urls_csv; rerun train; the quality gates show whether it holds"],
  ["Shortened and clean-looking compromised URLs", "Cannot be judged from text alone (shorteners blocked 5.2 %, flagged 99.3 %)", "Redirect expansion, domain age, TLS certificate and reputation lookups, page-content analysis"],
  ["E-mail text model learns template vocabulary", "Weaker on real mail; the n_urls coefficient is an artefact", "Retrain on real mail and re-learn the stacker"],
  ["No JavaScript execution or visual analysis", "Misses pages that only reveal behaviour at run time or copy a logo", "Sandboxed rendering, logo and screenshot similarity"],
  ["Static list of 28 brands", "Other brands are not protected from impersonation", "Large, regularly updated brand and ownership list"],
  ["Hand-set fusion weights and thresholds", "Not optimised", "Tune on a validation set of real data; monitor drift and recalibrate"],
  ["Adversarial adaptation", "Attackers change tactics once rules are known", "Periodic retraining, feedback loop with review, ensemble diversity"]], [2500, 3300, 3838], { size: 17, boldFirst: true }));
c.push(sp());
c.push(P([B("Production roadmap. "), new TextRun("(1) Data: real feeds and labelled mail. (2) Signals: WHOIS age, certificate and reputation, redirect expansion. (3) Integration: browser extension and mail-gateway plug-in over the REST API, with authentication and TLS. (4) Operations: monitoring of false-positive rate, a reviewed feedback loop, scheduled retraining. (5) Evaluation: measure on a temporal split, where the test data is newer than the training data, to model real concept drift.")]));

// ---------------- PART 5
c.push(new Paragraph({ children: [new PageBreak()] }));
c.push(H1("Part 5. Tips and Live-Demo Checklist"));
c.push(H2("Tips for answering"));
c.push(...BL([
  "Answer first in one sentence, then give the supporting detail and a number. Evaluators remember numbers.",
  "Never claim real-world accuracy. Say 'on our held-out synthetic test set' and mention the limitation before they ask.",
  "If asked something not covered, say what the system does today and what you would add next. Honest limits earn credibility.",
  "Link every design choice to a measured result: rules only versus ML only versus hybrid is your strongest evidence.",
  "Mention that bugs were found by your own tests. It shows the testing was meaningful.",
  "If asked about teamwork or phases, use the ten-phase table in Part 2."]));
c.push(H2("Live-demo checklist"));
c.push(table(["Step", "Command (from the PhishGuard folder)", "What to point out"], [
  ["1", "./scripts/run_all.sh", "Six stages; the final line ALL STEPS COMPLETE - ALL TESTS PASSED"],
  ["2", "tail -f logs/phishguard.log (second terminal)", "Every decision logged as it happens"],
  ["3", "./scripts/try_it.sh", "Type a phishing-looking URL, then github.com: every step, rule and model vote is shown"],
  ["4", "email samples/phishing_paypal.eml (inside the prompt)", "Header findings, link scoring, quarantine and disabled links"],
  ["5", "html samples/fake_login.html http://secure-paypal-login.xyz/signin", "Page indicators and combined verdict"],
  ["6", "batch samples/urls.txt", "13 URLs in one table: allowed, blocked and the shortener warned"],
  ["7", "python3 -m phishguard serve --port 8765, then curl", "The REST API for integration"],
  ["8", "cat reports/url_confusion_matrix.txt", "TN 975, FP 26, FN 156, TP 860"]], [700, 4600, 4338], { size: 17, center: [0] }));

const doc = new Document({
  creator: "PhishGuard project team", title: "PhishGuard Presentation Q&A",
  styles: { default: { document: { run: { font: "Calibri", size: 22 } } }, paragraphStyles: [
    { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { font: "Cambria", size: 34, bold: true, color: INK }, paragraph: { spacing: { before: 300, after: 140 }, keepNext: true, outlineLevel: 0 } },
    { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { font: "Cambria", size: 26, bold: true, color: TEAL }, paragraph: { spacing: { before: 220, after: 110 }, keepNext: true, outlineLevel: 1 } }] },
  numbering: { config: [{ reference: "bul", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 560, hanging: 360 } } } }] }] },
  sections: [{ properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "PhishGuard Q&A  |  page ", size: 18, color: "5B6B7F" }), new TextRun({ children: [PageNumber.CURRENT], size: 18, color: "5B6B7F" })] })] }) },
    children: c }]
});
Packer.toBuffer(doc).then(b => { fs.writeFileSync("../PhishGuard_Presentation_QA.docx", b); console.log("written", n - 1, "short questions"); });
