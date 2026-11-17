const pptxgen = require("pptxgenjs");
const React = require("react");
const RDS = require("react-dom/server");
const sharp = require("sharp");
const fa = require("react-icons/fa");
const SK = process.env.SKILL_DIR;
const { applyTheme } = require(SK + "/scripts/apply_theme.js");
const U = require("/home/anupam/code/CyberSecurity/PhishGuard/reports/url_metrics.json");
const E = require("/home/anupam/code/CyberSecurity/PhishGuard/reports/email_metrics.json");

const INK = "0E1A2B", PANEL = "17293F", ALERT = "F25C54", TEAL = "1FA99B", GOLD = "E9A93B", LIGHT = "F4F7FA",
  WHITE = "FFFFFF", MUTED = "5B6B7F", TEXT = "1B2A3C", SOFT = "DDE6EE", TEALD = "0F7F74";
const THEME = { name: "PhishGuard", headFontFace: "Cambria", bodyFontFace: "Calibri",
  colors: { dk1: TEXT, lt1: WHITE, dk2: INK, lt2: LIGHT, accent1: ALERT, accent2: TEAL, accent3: GOLD, accent4: PANEL, accent5: MUTED, accent6: TEALD, hlink: TEAL, folHlink: MUTED } };

const pres = new pptxgen();
pres.layout = "LAYOUT_16x9";
pres.theme = { headFontFace: "Cambria", bodyFontFace: "Calibri" };
pres.title = "Phishing Detection and Prevention - PhishGuard";
pres.author = "PhishGuard project team";

const FOOT = { text: { text: "PhishGuard  |  Phishing Detection & Prevention", options: { x: 0.5, y: 5.3, w: 5, h: 0.25, fontSize: 10, color: MUTED, margin: 0, fontFace: "Calibri" } } };
pres.defineSlideMaster({ title: "CONTENT", background: { color: LIGHT }, margin: [0.5, 0.5, 0.5, 0.5],
  objects: [{ placeholder: { options: { name: "title", type: "title", x: 0.5, y: 0.28, w: 9, h: 0.75, fontFace: "Cambria", fontSize: 30, bold: true, color: INK, margin: 0, valign: "middle", align: "left" }, text: "" } }, FOOT],
  slideNumber: { x: 9.0, y: 5.3, w: 0.5, h: 0.25, fontSize: 10, color: MUTED, fontFace: "Calibri", align: "right" } });
pres.defineSlideMaster({ title: "DARK", background: { color: INK },
  objects: [{ placeholder: { options: { name: "title", type: "title", x: 0.7, y: 1.5, w: 8.6, h: 1.4, fontFace: "Cambria", fontSize: 40, bold: true, color: WHITE, margin: 0, valign: "top", align: "left" }, text: "" } }] });

async function icon(Comp, color, size = 256) {
  const svg = RDS.renderToStaticMarkup(React.createElement(Comp, { color: "#" + color, size: String(size) }));
  const buf = await sharp(Buffer.from(svg)).png().toBuffer();
  return "image/png;base64," + buf.toString("base64");
}
const sh = () => ({ type: "outer", color: "000000", opacity: 0.12, blur: 6, offset: 2, angle: 90 });
let SEC = "";
function section(t) { SEC = t; pres.addSection({ title: t }); }
function content(title, notes) { const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: SEC }); s.addText(title, { placeholder: "title" }); if (notes) s.addNotes(notes); return s; }
function card(s, x, y, w, h, fill = WHITE) { s.addShape(pres.shapes.RECTANGLE, { x, y, w, h, fill: { color: fill }, line: { color: SOFT, width: 0.75 }, shadow: sh() }); }
function circ(s, ic, x, y, d, fill) { s.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: fill }, line: { color: fill, width: 0 } }); s.addImage({ data: ic, x: x + d * 0.25, y: y + d * 0.25, w: d * 0.5, h: d * 0.5 }); }
const T = (s, text, o) => s.addText(text, Object.assign({ isTextBox: true, fontFace: "Calibri", color: TEXT, margin: 0, valign: "top" }, o));
const hdr = (text, color = WHITE, fill = INK) => ({ text, options: { bold: true, color, fill: { color: fill }, fontSize: 12, fontFace: "Calibri" } });
const cell = (text, o = {}) => ({ text, options: Object.assign({ fontSize: 11, color: TEXT, fontFace: "Calibri" }, o) });
const TB = { type: "solid", color: SOFT, pt: 0.75 };

(async () => {
  const I = {};
  const want = { mail: fa.FaEnvelope, fish: fa.FaFish, user: fa.FaUserSecret, lock: fa.FaLock, shield: fa.FaShieldAlt, link: fa.FaLink,
    clip: fa.FaPaperclip, brain: fa.FaBrain, globe: fa.FaGlobe, phone: fa.FaPhoneAlt, sms: fa.FaCommentDots, qr: fa.FaQrcode, key: fa.FaKey,
    search: fa.FaSearch, code: fa.FaFileCode, db: fa.FaDatabase, warn: fa.FaExclamationTriangle, check: fa.FaCheckCircle, cog: fa.FaCogs,
    clock: fa.FaClockOne || fa.FaClock, eye: fa.FaEye, ban: fa.FaBan, list: fa.FaListUl, server: fa.FaServer, bug: fa.FaBug, users: fa.FaUsers,
    crown: fa.FaCrown, chart: fa.FaChartBar, flask: fa.FaFlask, tag: fa.FaTags, bell: fa.FaBell, file: fa.FaFileAlt, sync: fa.FaSyncAlt, mask: fa.FaTheaterMasks };
  for (const [k, v] of Object.entries(want)) { I[k] = await icon(v, "FFFFFF"); I[k + "_t"] = await icon(v, TEAL); I[k + "_a"] = await icon(v, ALERT); }

  // 1 ---------------------------------------------------------------- TITLE
  let s = pres.addSlide({ masterName: "DARK" });
  s.addText("Phishing Detection & Prevention", { placeholder: "title" });
  T(s, "PhishGuard: a hybrid machine-learning and rule-based defence for URLs, e-mails and web pages", { x: 0.7, y: 3.0, w: 7.2, h: 0.9, fontSize: 20, color: "BFD0E0" });
  T(s, "Cybersecurity project evaluation  |  November 2026", { x: 0.7, y: 4.7, w: 6, h: 0.3, fontSize: 14, color: TEAL });
  circ(s, I.fish, 0.7, 0.35, 0.95, ALERT);
  s.addNotes("Introduce the topic: phishing is the most common social-engineering attack. This deck first explains the threat (Part A), then our project PhishGuard which detects and prevents it (Part B).");

  // 2 ---------------------------------------------------------------- AGENDA
  s = content("What we will cover", "Two halves: the problem space, then our solution and its measured results.");
  card(s, 0.5, 1.25, 4.3, 3.8); card(s, 5.2, 1.25, 4.3, 3.8);
  circ(s, I.warn, 0.75, 1.45, 0.6, ALERT); T(s, "Part A  |  The threat", { x: 1.5, y: 1.55, w: 3.2, h: 0.4, fontSize: 18, bold: true, color: INK, valign: "middle" });
  T(s, ["What phishing is and how an attack unfolds", "Types of phishing", "URL deception techniques", "Why detection is hard", "Detection approaches", "Prevention layers"].map((t, i, a) => ({ text: t, options: { bullet: true, breakLine: i < a.length - 1 } })), { x: 0.8, y: 2.3, w: 3.8, h: 2.6, fontSize: 14, paraSpaceAfter: 6 });
  circ(s, I.shield, 5.45, 1.45, 0.6, TEAL); T(s, "Part B  |  Our project", { x: 6.2, y: 1.55, w: 3.2, h: 0.4, fontSize: 18, bold: true, color: INK, valign: "middle" });
  T(s, ["Architecture and pipeline", "URL features, rules, ML models and parameters", "E-mail and web-page analysis", "Prevention engine and REST API", "Data, evaluation and results", "Testing, limitations, conclusion"].map((t, i, a) => ({ text: t, options: { bullet: true, breakLine: i < a.length - 1 } })), { x: 5.5, y: 2.3, w: 3.8, h: 2.6, fontSize: 14, paraSpaceAfter: 6 });

  // 3 ---------------------------------------------------------------- WHAT IS
  section("Part A: The threat");
  s = content("What is phishing?", "Define phishing. Emphasise the target is the human, not the software, which is why purely technical controls are insufficient on their own.");
  T(s, [{ text: "Phishing is a social-engineering attack in which an attacker impersonates a trusted entity (a bank, a colleague, a delivery company) to trick a victim into revealing credentials, paying money or running malware.", options: {} }], { x: 0.5, y: 1.25, w: 9, h: 1.0, fontSize: 16 });
  const three = [["mask", "Impersonate", "Spoofed sender, cloned login page, look-alike domain"], ["warn", "Deceive", "Urgency, fear or reward pushes the victim to act without thinking"], ["key", "Exploit", "Stolen passwords, fraudulent transfers, malware foothold"]];
  three.forEach((c, i) => { const x = 0.5 + i * 3.1; card(s, x, 2.5, 2.8, 2.5); circ(s, I[c[0]], x + 0.25, 2.7, 0.7, i === 1 ? ALERT : TEAL); T(s, c[1], { x: x + 0.25, y: 3.55, w: 2.3, h: 0.35, fontSize: 18, bold: true, color: INK }); T(s, c[2], { x: x + 0.25, y: 3.95, w: 2.35, h: 0.95, fontSize: 13, color: MUTED }); });

  // 4 ---------------------------------------------------------------- LIFECYCLE
  s = content("Anatomy of a phishing attack", "Walk left to right. The key message: defenders can intervene at steps 1 to 3, before credentials are harvested. Our system acts at the lure and click stage.");
  const steps = [["Set up", "Register look-alike domain, clone the login page, rent hosting"], ["Lure", "E-mail, SMS or call with a link or attachment"], ["Click", "Victim lands on the fake page"], ["Harvest", "Credentials are posted to the attacker"], ["Exploit", "Account takeover, fraud, lateral movement"]];
  steps.forEach((st, i) => { const x = 0.5 + i * 1.8; s.addShape(pres.shapes.RECTANGLE, { x, y: 1.4, w: 1.65, h: 0.55, fill: { color: i < 3 ? TEAL : ALERT }, line: { color: i < 3 ? TEAL : ALERT, width: 0 } });
    T(s, `${i + 1}. ${st[0]}`, { x, y: 1.4, w: 1.65, h: 0.55, fontSize: 15, bold: true, color: WHITE, align: "center", valign: "middle" });
    card(s, x, 2.05, 1.65, 1.75); T(s, st[1], { x: x + 0.12, y: 2.17, w: 1.4, h: 1.5, fontSize: 13 }); });
  s.addShape(pres.shapes.RECTANGLE, { x: 0.5, y: 4.1, w: 5.4, h: 0.9, fill: { color: TEAL }, line: { color: TEAL, width: 0 } });
  T(s, "Steps 1-3: detection and prevention can stop the attack before any data is lost. This is where PhishGuard works.", { x: 0.7, y: 4.15, w: 5.0, h: 0.8, fontSize: 14, bold: true, color: WHITE, valign: "middle" });
  s.addShape(pres.shapes.RECTANGLE, { x: 6.1, y: 4.1, w: 3.4, h: 0.9, fill: { color: ALERT }, line: { color: ALERT, width: 0 } });
  T(s, "Steps 4-5: damage is done; only response remains", { x: 6.25, y: 4.15, w: 3.1, h: 0.8, fontSize: 14, bold: true, color: WHITE, valign: "middle" });

  // 5 ---------------------------------------------------------------- TYPES
  s = content("Types of phishing", "Our project covers the first three directly (e-mail, targeted/BEC, web pages). SMS, voice and QR variants share the same URL indicators, so the URL engine helps there too.");
  const types = [["mail", "Email phishing", "Mass campaigns posing as banks, shops or IT. Link to a fake login page."], ["user", "Spear phishing", "Tailored to one person or team using personal context."], ["crown", "Whaling and BEC", "Impersonates executives to order wire transfers or gift cards."],
    ["sms", "Smishing", "SMS lures: parcel fees, bank alerts, short links."], ["phone", "Vishing", "Voice calls claiming to be support or the bank."], ["qr", "Quishing", "Malicious QR codes that hide the URL from filters."]];
  types.forEach((t, i) => { const x = 0.5 + (i % 3) * 3.1, y = 1.25 + Math.floor(i / 3) * 1.95; card(s, x, y, 2.8, 1.75); circ(s, I[t[0]], x + 0.2, y + 0.2, 0.55, i < 3 ? TEAL : PANEL); T(s, t[1], { x: x + 0.9, y: y + 0.2, w: 1.8, h: 0.55, fontSize: 15, bold: true, color: INK, valign: "middle" }); T(s, t[2], { x: x + 0.2, y: y + 0.9, w: 2.45, h: 0.8, fontSize: 12, color: MUTED }); });

  // 6 ---------------------------------------------------------------- URL TECHNIQUES
  s = content("How attackers disguise URLs", "These are exactly the 13 attack families our generator produces and our detector is tested against. Highlight that the registered domain (just before the TLD) is what really matters.");
  const rows = [["Typosquatting", "paypa1.com", "1 vs l, swapped or missing letters"], ["Combosquatting", "paypal-secure-login.xyz", "Real brand plus trust words"], ["Brand in subdomain", "paypal.com.verify-now.top", "Reader stops at the first '.com'"],
    ["IP address host", "http://185.220.101.7/login", "No domain to inspect"], ["'@' trick", "paypal.com@evil.tk/signin", "Browser ignores text before '@'"], ["Homograph (IDN)", "xn--pypal-4ve.com", "Cyrillic letters that look Latin"],
    ["URL shortener", "bit.ly/3xYz9Qa", "Hides the destination"], ["Free hosting abuse", "amazon-wallet.pages.dev", "Trusted platform, attacker content"]];
  s.addTable([[hdr("Technique"), hdr("Example"), hdr("Why it works")]].concat(rows.map(r => [cell(r[0], { bold: true }), cell(r[1], { fontFace: "Courier New", fontSize: 11 }), cell(r[2])])),
    { x: 0.5, y: 1.25, w: 9, colW: [2.2, 3.5, 3.3], rowH: 0.4, border: TB, fill: { color: WHITE }, valign: "middle" });

  // 7 ---------------------------------------------------------------- WHY HARD
  s = content("Why detection is hard", "Stress the false-positive cost: blocking a legitimate site is also a failure. This is why we use a three-level policy (allow, warn, block) rather than a single yes/no.");
  const hard = [["clock", "Short-lived", "Phishing sites live for hours. Blocklists lag behind and miss new domains (zero-day)."], ["eye", "Look legitimate", "HTTPS padlocks, cloned branding and clean-looking compromised sites."], ["ban", "False positives hurt", "Legitimate login pages and tracking links resemble phishing. Wrong blocks erode trust."], ["sync", "Adversaries adapt", "Attackers test against filters and change tactics, so static rules decay."]];
  hard.forEach((h, i) => { const x = 0.5 + (i % 2) * 4.6, y = 1.25 + Math.floor(i / 2) * 1.95; card(s, x, y, 4.4, 1.75); circ(s, I[h[0]], x + 0.25, y + 0.3, 0.7, i === 2 ? GOLD : ALERT); T(s, h[1], { x: x + 1.15, y: y + 0.25, w: 3.1, h: 0.4, fontSize: 17, bold: true, color: INK }); T(s, h[2], { x: x + 1.15, y: y + 0.7, w: 3.1, h: 1.0, fontSize: 12.5, color: MUTED }); });

  // 8 ---------------------------------------------------------------- APPROACHES
  s = content("Detection approaches compared", "No single method is enough. Our design is the last row: combine fast explainable rules, a learned model, and protocol-level evidence from e-mail headers.");
  const ap = [["Blocklists", "Lookup of known-bad URLs", "Fast, zero false positives", "Misses new sites"], ["Heuristic rules", "Hand-written URL/page checks", "Explainable, no training", "Brittle, easy to evade"], ["Machine learning", "Classifier on URL/content features", "Generalises to unseen attacks", "Needs data, less transparent"],
    ["Content / visual", "Page text, logos, screenshots", "Catches clean-looking URLs", "Needs fetching, slower, riskier"], ["E-mail authentication", "SPF, DKIM, DMARC results", "Proves sender identity", "Does not judge content"], ["Hybrid (ours)", "Rules + ML + headers + lists", "Accurate and explainable", "Needs maintenance"]];
  s.addTable([[hdr("Approach"), hdr("How"), hdr("Strength"), hdr("Weakness")]].concat(ap.map((r, i) => r.map((c, j) => cell(c, { bold: j === 0, fill: { color: i === 5 ? "D7F3EF" : WHITE } })))),
    { x: 0.5, y: 1.25, w: 9, colW: [1.9, 2.5, 2.4, 2.2], rowH: 0.5, border: TB, valign: "middle" });

  // 9 ---------------------------------------------------------------- PREVENTION LAYERS
  s = content("Layered prevention", "Defence in depth. PhishGuard implements the gateway, filtering, response and user-guidance layers; MFA and SPF/DKIM/DMARC are consumed as signals.");
  const lay = [["server", "Gateway and filtering", "E-mail gateway, DNS and web filtering, attachment sandboxing", true], ["lock", "Identity", "SPF / DKIM / DMARC, MFA, passkeys (FIDO2) make stolen passwords less useful", false], ["shield", "Endpoint and browser", "Safe-browsing warnings, EDR, patching", false], ["users", "People", "Awareness training, one-click report button", true], ["bell", "Response", "Quarantine, blocklist updates, takedown, audit trail", true]];
  lay.forEach((l, i) => { const y = 1.2 + i * 0.78; card(s, 0.5, y, 9, 0.68, l[3] ? "E6F6F4" : WHITE); circ(s, I[l[0]], 0.65, y + 0.09, 0.5, l[3] ? TEAL : PANEL); T(s, l[1], { x: 1.35, y, w: 2.5, h: 0.68, fontSize: 15, bold: true, color: INK, valign: "middle" }); T(s, l[2], { x: 3.9, y, w: 5.45, h: 0.68, fontSize: 12.5, color: TEXT, valign: "middle" }); });
  T(s, "Shaded rows = implemented in PhishGuard", { x: 0.5, y: 5.1, w: 5, h: 0.2, fontSize: 10, color: MUTED, italic: true });

  // 10 --------------------------------------------------------------- DIVIDER
  section("Part B: PhishGuard");
  s = pres.addSlide({ masterName: "DARK", sectionTitle: SEC });
  s.addText("Part B: Our project, PhishGuard", { placeholder: "title" });
  T(s, "Detect, explain and prevent phishing in URLs, e-mails and web pages", { x: 0.7, y: 3.1, w: 7.5, h: 0.6, fontSize: 20, color: "BFD0E0" });
  circ(s, I.shield, 0.7, 0.35, 0.95, TEAL);

  // 11 --------------------------------------------------------------- OVERVIEW
  s = content("Project goals and scope", "Four objectives on the left; the headline numbers on the right are all measured, from our reports and test logs.");
  T(s, [["Detect", "phishing in URLs, e-mails (.eml) and HTML pages"], ["Explain", "every verdict with named reasons and user tips"], ["Prevent", "block, warn or quarantine; disable links; auto-learn"], ["Prove", "held-out evaluation and a 75-test suite with logs"]].map((g, i, a) => ({ text: g[0] + ": ", options: { bold: true, color: TEALD, breakLine: false } })).flatMap((r, i, a) => [r, { text: ["phishing in URLs, e-mails (.eml) and HTML pages", "every verdict with named reasons and user tips", "block, warn or quarantine; disable links; auto-learn", "held-out evaluation and a 75-test suite with logs"][i], options: { breakLine: i < a.length - 1 } }]), { x: 0.5, y: 1.35, w: 4.5, h: 3.4, fontSize: 16, paraSpaceAfter: 14 });
  const stats = [["30", "URL features"], ["16", "explainable rules"], ["75/75", "tests passing"], ["~40 ms", "per URL scan"]];
  stats.forEach((st, i) => { const x = 5.3 + (i % 2) * 2.15, y = 1.3 + Math.floor(i / 2) * 1.85; card(s, x, y, 2.0, 1.65, i === 0 ? INK : WHITE); T(s, st[0], { x, y: y + 0.25, w: 2.0, h: 0.8, fontSize: 36, bold: true, color: i === 0 ? TEAL : INK, align: "center", fontFace: "Cambria" }); T(s, st[1], { x, y: y + 1.0, w: 2.0, h: 0.4, fontSize: 13, color: i === 0 ? "BFD0E0" : MUTED, align: "center" }); });

  // 12 --------------------------------------------------------------- ARCHITECTURE
  s = content("System architecture", "Explain the flow: three inputs, three analysers, learned models, one risk score, then the prevention policy. Everything is local; we never visit the suspicious site.");
  const cols = [["Inputs", [["link", "URL"], ["mail", "E-mail (.eml)"], ["code", "HTML page"]], PANEL], ["Analysis", [["search", "URL features + 16 rules"], ["file", "Header, text, link, attachment forensics"], ["bug", "Form, iframe, script checks"]], TEALD], ["Machine learning", [["brain", "LR + RF + GB ensemble"], ["tag", "TF-IDF text model"], ["cog", "Logistic stacker"]], TEAL], ["Prevention", [["list", "Allow / block lists"], ["shield", "Policy: ALLOW / WARN / BLOCK"], ["bell", "Quarantine, audit log, API"]], ALERT]];
  cols.forEach((c, i) => { const x = 0.5 + i * 2.3; s.addShape(pres.shapes.RECTANGLE, { x, y: 1.2, w: 2.05, h: 0.45, fill: { color: c[2] }, line: { color: c[2], width: 0 } }); T(s, c[0], { x, y: 1.2, w: 2.05, h: 0.45, fontSize: 14, bold: true, color: WHITE, align: "center", valign: "middle" });
    c[1].forEach((it, j) => { const y = 1.8 + j * 1.0; card(s, x, y, 2.05, 0.85); s.addImage({ data: I[it[0] + "_t"], x: x + 0.12, y: y + 0.27, w: 0.3, h: 0.3 }); T(s, it[1], { x: x + 0.52, y, w: 1.48, h: 0.85, fontSize: 11.5, valign: "middle" }); });
    if (i < 3) s.addText(">", { isTextBox: true, x: x + 2.03, y: 2.9, w: 0.3, h: 0.4, fontSize: 22, bold: true, color: MUTED, align: "center", margin: 0 }); });
  s.addShape(pres.shapes.RECTANGLE, { x: 0.5, y: 4.9, w: 9, h: 0.35, fill: { color: INK }, line: { color: INK, width: 0 } });
  T(s, "Risk score 0-100  >  action  >  explanation + advice  >  JSON audit log  >  REST API", { x: 0.5, y: 4.9, w: 9, h: 0.35, fontSize: 12, bold: true, color: WHITE, align: "center", valign: "middle" });

  // 13 --------------------------------------------------------------- 30 FEATURES
  s = content("URL feature engineering (30 features)", "Features are computed from the URL string only, so scanning is private, fast and safe. The security-flag group maps one-to-one to the attack techniques shown earlier.");
  const feats = [["Length and structure (8)", "url_length, host_length, path_length, query_length, label_len, num_dots, num_subdomains, num_params"], ["Character statistics (7)", "digit_ratio_host, digit_ratio_url, num_hyphens_host, host_entropy, path_entropy, num_special_chars, encoded_chars"], ["Security flags (9)", "is_https, has_ip_host, has_at_symbol, has_punycode, non_ascii_host, nonstandard_port, double_slash_in_path, exec_extension, embedded_url_in_query"], ["Brand and lexical (6)", "is_shortener, suspicious_tld, keyword_count, keyword_in_host, brand_mismatch, is_typosquat"]];
  feats.forEach((f, i) => { const y = 1.2 + i * 0.95; card(s, 0.5, y, 9, 0.85); s.addShape(pres.shapes.RECTANGLE, { x: 0.5, y, w: 2.4, h: 0.85, fill: { color: i % 2 ? TEALD : INK }, line: { color: INK, width: 0 } }); T(s, f[0], { x: 0.6, y, w: 2.2, h: 0.85, fontSize: 13.5, bold: true, color: WHITE, valign: "middle" }); T(s, f[1], { x: 3.05, y, w: 6.3, h: 0.85, fontSize: 12, fontFace: "Courier New", valign: "middle" }); });
  T(s, "Entropy = Shannon entropy of the characters; high values suggest machine-generated strings.", { x: 0.5, y: 5.0, w: 9, h: 0.25, fontSize: 11, color: MUTED, italic: true });

  // 14 --------------------------------------------------------------- BRAND ALGORITHM
  s = content("Catching brand impersonation", "This is the most technically interesting part. Walk through the worked example. Damerau-Levenshtein counts a swap of two adjacent letters as one edit, which plain Levenshtein does not; a test caught this for paypla.com.");
  const al = ["Split host into subdomain, label, suffix and registered domain (handles co.uk, github.io)", "Fold look-alikes: 0>o, 3>e, 4>a, 5>s, 7>t, rn>m, vv>w, 1>l or i, plus Cyrillic homoglyphs", "Compare with 28 brand names using Damerau-Levenshtein distance (<=1; <=2 for names of 8+ letters)", "Brand token in subdomain, label or path on a domain the brand does not own = mismatch (ownership table: paypal > paypal.com)"];
  al.forEach((a, i) => { const y = 1.25 + i * 0.95; circ(s, I.check, 0.5, y + 0.1, 0.5, TEAL); s.addText(String(i + 1), { isTextBox: true, x: 0.5, y: y + 0.1, w: 0.5, h: 0.5, fontSize: 16, bold: true, color: WHITE, align: "center", valign: "middle", margin: 0 }); T(s, a, { x: 1.15, y, w: 4.3, h: 0.85, fontSize: 12.5, valign: "middle" }); });
  s.addShape(pres.shapes.RECTANGLE, { x: 5.7, y: 1.25, w: 3.8, h: 3.7, fill: { color: INK }, line: { color: INK, width: 0 }, shadow: sh() });
  T(s, "Worked example", { x: 5.9, y: 1.4, w: 3.4, h: 0.35, fontSize: 14, bold: true, color: TEAL });
  T(s, [["http://paypa1-secure-login.xyz/verify", { color: "FFFFFF", fontFace: "Courier New", fontSize: 11 }], ["token 'paypa1' > 'paypal'", { color: "BFD0E0" }], ["distance = 1  >  typosquat  (+40)", { color: GOLD }], ["brand not owned  >  mismatch  (+35)", { color: GOLD }], [".xyz abused TLD  (+15)", { color: GOLD }], ["HTTP + keywords  (+15)", { color: GOLD }], ["rule score = 100 (capped)", { color: ALERT, bold: true }], ["final risk = 99.1  >  BLOCK", { color: ALERT, bold: true }]].map((r, i, a) => ({ text: r[0], options: Object.assign({ breakLine: i < a.length - 1, fontSize: 12.5, fontFace: "Calibri" }, r[1]) })), { x: 5.9, y: 1.85, w: 3.5, h: 3.0, paraSpaceAfter: 6 });

  // 15 --------------------------------------------------------------- RULES
  s = content("The explainable rule engine", "Each rule has a weight reflecting how strongly it indicates phishing. The sum is capped at 100. Rules alone have perfect precision but only 37% recall, which is why ML is added.");
  const rl = [["Typosquat look-alike", 40], ["Brand on foreign domain", 35], ["IP address host", 35], ["'@' in authority", 30], ["Executable download", 25], ["Punycode / non-ASCII", 25], ["Credential keywords over HTTP", 15], ["Many phishing keywords", 15]];
  const rl2 = [["Deep subdomains (4+)", 15], ["Hyphen-heavy host (3+)", 15], ["Suspicious TLD", 15], ["URL shortener", 10], ["Long URL (>100)", 10], ["Embedded redirect URL", 10], ["Non-standard port", 10], ["Heavy percent-encoding", 8]];
  [[rl, 0.5], [rl2, 5.1]].forEach(([arr, x]) => s.addTable([[hdr("Rule"), hdr("Weight")]].concat(arr.map(r => [cell(r[0], { fontSize: 12 }), cell("+" + r[1], { bold: true, color: ALERT, align: "center", fontSize: 12 })])), { x, y: 1.25, w: 4.4, colW: [3.3, 1.1], rowH: 0.38, border: TB, fill: { color: WHITE }, valign: "middle" }));
  T(s, "rule score = min(100, sum of weights of fired rules)   |   rules-only: precision 1.00, recall 0.37", { x: 0.5, y: 4.75, w: 9, h: 0.35, fontSize: 13, bold: true, color: TEALD });

  // 16 --------------------------------------------------------------- MODELS
  s = content("ML models and parameters", "Three diverse learners are combined by soft voting; the random forest and gradient boosting get double weight because they scored best in cross-validation. The hybrid formula then blends ML with the rules.");
  const ml = [["Logistic Regression", "StandardScaler, C = 1.0, max_iter = 2000", "0.966"], ["Random Forest", "300 trees, min_samples_leaf = 2, seed 42", "0.992"], ["Gradient Boosting", "200 estimators, max_depth = 3, seed 42", "0.993"], ["Soft-voting ensemble", "probability average, weights 1 : 2 : 2", "final model"]];
  s.addTable([[hdr("Model"), hdr("Key parameters"), hdr("5-fold CV F1")]].concat(ml.map((r, i) => r.map((c, j) => cell(c, { bold: j === 0, fill: { color: i === 3 ? "D7F3EF" : WHITE }, fontSize: 12 })))), { x: 0.5, y: 1.25, w: 9, colW: [2.4, 4.9, 1.7], rowH: 0.42, border: TB, valign: "middle" });
  card(s, 0.5, 3.5, 9, 1.5, INK);
  T(s, "Hybrid risk score", { x: 0.75, y: 3.6, w: 3, h: 0.3, fontSize: 14, bold: true, color: TEAL });
  T(s, "risk = 0.70 x P(phishing | ML) x 100  +  0.30 x rule score", { x: 0.75, y: 3.95, w: 8.5, h: 0.45, fontSize: 20, bold: true, color: WHITE, fontFace: "Cambria" });
  T(s, "Allow-listed domain: capped at 5.  Block-listed domain: forced to 100.  Training: 5,865 URLs, 5-fold stratified cross-validation, seed 42.", { x: 0.75, y: 4.45, w: 8.5, h: 0.5, fontSize: 12, color: "BFD0E0" });

  // 17 --------------------------------------------------------------- IMPORTANCE
  s = content("What the model relies on", "Feature importance from the random forest. Keyword count and brand mismatch dominate, followed by character statistics. This matches intuition and the literature.");
  const fi = Object.entries(U.feature_importances).slice(0, 10).reverse();
  s.addChart(pres.charts.BAR, [{ name: "Importance", labels: fi.map(x => x[0]), values: fi.map(x => +x[1].toFixed(3)) }], { x: 0.5, y: 1.2, w: 5.6, h: 3.9, barDir: "bar", chartColors: [TEAL], showTitle: true, title: "Top 10 features (random forest importance)", titleFontSize: 13, titleColor: INK, titleFontFace: "Calibri",
    showValue: true, dataLabelFontSize: 10, dataLabelColor: TEXT, dataLabelFormatCode: "0.000", catAxisLabelFontSize: 10, catAxisLabelColor: TEXT, catAxisLabelFontFace: "Calibri", valAxisLabelFontSize: 10, valAxisLabelColor: MUTED, valAxisLabelFontFace: "Calibri", valGridLine: { color: SOFT, size: 0.5 }, catGridLine: { style: "none" }, showLegend: false, barGapWidthPct: 40 });
  card(s, 6.3, 1.25, 3.2, 3.75);
  T(s, "Reading the chart", { x: 6.5, y: 1.4, w: 2.8, h: 0.35, fontSize: 15, bold: true, color: INK });
  T(s, ["Keywords and brand mismatch carry the most signal", "Typosquat flag ranks 5th", "Entropy and digit ratios expose random-looking hosts", "Rules and ML overlap, which makes the ensemble robust"].map((t, i, a) => ({ text: t, options: { bullet: true, breakLine: i < a.length - 1 } })), { x: 6.5, y: 1.85, w: 2.85, h: 3.0, fontSize: 12.5, paraSpaceAfter: 8 });

  // 18 --------------------------------------------------------------- EMAIL FORENSICS
  s = content("E-mail forensics (header score)", "Weights shown are what the analyser adds to the header score (capped at 100). The header score is one input to the final stacker, not the verdict.");
  const em = [["Authentication", "key", [["SPF fail", "+20"], ["SPF soft-fail", "+12"], ["DKIM fail", "+15"], ["DMARC fail", "+20"], ["No auth header", "+10"]]], ["Sender spoofing", "mask", [["Display name spoofs brand", "+25"], ["Executive title on free-mail", "+25"], ["Reply-To domain differs", "+15"], ["Return-Path differs", "+10"]]], ["Content and files", "clip", [["Link text vs real target", "+30"], ["Dangerous attachment", "+35"], ["Credential request", "+15"], ["Urgency / threats", "+12"], ["Double extension", "+15"]]]];
  em.forEach((c, i) => { const x = 0.5 + i * 3.1; card(s, x, 1.25, 2.8, 3.75); circ(s, I[c[1]], x + 0.2, 1.4, 0.5, i === 1 ? ALERT : TEAL); T(s, c[0], { x: x + 0.85, y: 1.4, w: 1.9, h: 0.5, fontSize: 14, bold: true, color: INK, valign: "middle" });
    c[2].forEach((r, j) => { const y = 2.1 + j * 0.56; T(s, r[0], { x: x + 0.2, y, w: 1.95, h: 0.5, fontSize: 11.5, valign: "middle" }); T(s, r[1], { x: x + 2.05, y, w: 0.6, h: 0.5, fontSize: 13, bold: true, color: ALERT, align: "right", valign: "middle" }); }); });

  // 19 --------------------------------------------------------------- EMAIL ML
  s = content("E-mail ML: text model and stacker", "Key methodological point: the stacker is trained on out-of-fold text probabilities, so it never sees a prediction the text model made on its own training data. Mention the negative n_urls coefficient is an artefact of synthetic data, discussed in limitations.");
  card(s, 0.5, 1.25, 4.3, 3.75);
  T(s, "Text classifier", { x: 0.7, y: 1.35, w: 3.9, h: 0.35, fontSize: 15, bold: true, color: INK });
  T(s, ["TF-IDF on subject + body", "Uni- and bi-grams, min_df = 2", "Sub-linear TF, English stop-words", "Logistic Regression, C = 4.0", "Test: precision 0.997, recall 0.960"].map((t, i, a) => ({ text: t, options: { bullet: true, breakLine: i < a.length - 1 } })), { x: 0.7, y: 1.8, w: 3.9, h: 1.9, fontSize: 12.5, paraSpaceAfter: 5 });
  T(s, "Trained with 5-fold out-of-fold predictions to prevent leakage into the stacker.", { x: 0.7, y: 3.8, w: 3.9, h: 1.0, fontSize: 12, color: MUTED, italic: true });
  const co = [["header_score", "6.85"], ["text_prob", "6.26"], ["url_max_risk", "2.80"], ["attachment_risk", "1.69"], ["link_mismatch", "0.70"], ["n_urls", "-4.72"]];
  s.addTable([[hdr("Stacker input (logistic regression)"), hdr("Coefficient")]].concat(co.map(r => [cell(r[0], { fontFace: "Courier New", fontSize: 11.5 }), cell(r[1], { bold: true, align: "center", color: r[1].startsWith("-") ? ALERT : TEALD })])), { x: 5.1, y: 1.25, w: 4.4, colW: [3.0, 1.4], rowH: 0.4, border: TB, fill: { color: WHITE }, valign: "middle" });
  T(s, "Output: P(phishing) x 100 = e-mail risk. Every link inside is also scanned by the URL engine, and the highest link risk (url_max_risk) is fed in.", { x: 5.1, y: 4.1, w: 4.4, h: 0.9, fontSize: 12, color: TEXT });

  // 20 --------------------------------------------------------------- HTML
  s = content("Web-page (HTML) analysis", "Static analysis only: we parse the HTML but never execute scripts or load resources, so analysis is safe. The page score is combined with the URL risk for the final decision.");
  const ht = [["External form action", "+40"], ["Brand on foreign domain", "+25"], ["Hidden iframe", "+25"], ["Obfuscated JS (eval, atob)", "+20"], ["Password field", "+15"], ["Insecure (HTTP) form", "+15"], ["Status-bar spoofing", "+15"], ["Right-click disabled", "+10"], ["Meta-refresh redirect", "+10"], ["Mostly off-site links", "+10"]];
  s.addTable([[hdr("Indicator"), hdr("Weight")]].concat(ht.map(r => [cell(r[0], { fontSize: 11.5 }), cell(r[1], { bold: true, color: ALERT, align: "center" })])), { x: 0.5, y: 1.2, w: 4.6, colW: [3.5, 1.1], rowH: 0.33, border: TB, fill: { color: WHITE }, valign: "middle" });
  card(s, 5.4, 1.2, 4.1, 3.8, INK);
  T(s, "Fake PayPal page (sample)", { x: 5.6, y: 1.35, w: 3.7, h: 0.35, fontSize: 14, bold: true, color: TEAL });
  T(s, "Password form posts to collector.evil-host.tk, hidden iframe, eval(atob(...)), context-menu disabled, meta-refresh, 4 off-site links", { x: 5.6, y: 1.8, w: 3.7, h: 1.4, fontSize: 12.5, color: "BFD0E0" });
  T(s, "Page score + URL risk  >", { x: 5.6, y: 3.3, w: 3.7, h: 0.3, fontSize: 12.5, color: WHITE });
  T(s, "risk 100  >  BLOCK", { x: 5.6, y: 3.7, w: 3.7, h: 0.6, fontSize: 24, bold: true, color: ALERT, fontFace: "Cambria" });
  T(s, "A clean docs page scores 0.1  >  ALLOW", { x: 5.6, y: 4.4, w: 3.7, h: 0.4, fontSize: 12.5, color: TEAL });

  // 21 --------------------------------------------------------------- PREVENTION
  s = content("Prevention engine", "Detection alone does not protect anyone. These are the actions taken once a risk score exists. The auto-block feedback loop turns each detection into protection against the next attempt.");
  const bands = [[0, 3.0, TEAL, "ALLOW", "risk < 30"], [3.0, 2.0, GOLD, "WARN", "30 - 50"], [5.0, 4.0, ALERT, "BLOCK / QUARANTINE", "risk >= 50"]];
  bands.forEach(b => { s.addShape(pres.shapes.RECTANGLE, { x: 0.5 + b[0] * 1.0 * 1, y: 1.25, w: b[1] * 1.0 * 1, h: 0.75, fill: { color: b[2] }, line: { color: b[2], width: 0 } }); });
  bands.forEach(b => { T(s, [{ text: b[3], options: { bold: true, fontSize: 13, breakLine: true } }, { text: b[4], options: { fontSize: 11 } }], { x: 0.5 + b[0], y: 1.25, w: b[1], h: 0.75, color: WHITE, align: "center", valign: "middle" }); });
  const pv = [["list", "Allow / block lists", "Matched on the real registered domain; 'good.com@evil.top' cannot borrow trust"], ["ban", "Link neutralisation", "Risky URLs in quarantined mail become [LINK DISABLED: hxxp://evil[.]com]"], ["eye", "Defanging", "Indicators shown as hxxp and [.] so nobody clicks by accident"], ["sync", "Feedback loop", "Confirmed phishing domains are auto-added to the blocklist"], ["file", "Audit trail", "Every decision logged as JSON lines with reasons"], ["server", "REST API", "/scan/url, /scan/email, /scan/html for gateways and extensions"]];
  pv.forEach((p, i) => { const x = 0.5 + (i % 3) * 3.1, y = 2.3 + Math.floor(i / 3) * 1.4; card(s, x, y, 2.8, 1.25); circ(s, I[p[0]], x + 0.15, y + 0.12, 0.45, PANEL); T(s, p[1], { x: x + 0.7, y: y + 0.12, w: 2.0, h: 0.45, fontSize: 13, bold: true, color: INK, valign: "middle" }); T(s, p[2], { x: x + 0.15, y: y + 0.64, w: 2.55, h: 0.6, fontSize: 10.5, color: MUTED }); });

  // 22 --------------------------------------------------------------- DATA
  s = content("Data and evaluation method", "Be upfront that the data is synthetic and why. The important rigour point is the group split by registered domain, enforced by an assertion, so the test set measures generalisation to unseen sites.");
  const dm = [["8,000", "URLs generated (7,882 unique), 50% phishing"], ["13", "phishing techniques + legitimate hard cases"], ["2,400", "e-mails: BEC, credential, prize, attachment"], ["0", "domains shared by train and test"]];
  dm.forEach((d, i) => { const y = 1.25 + i * 0.95; card(s, 0.5, y, 4.4, 0.82); T(s, d[0], { x: 0.6, y, w: 1.3, h: 0.82, fontSize: 26, bold: true, color: TEALD, fontFace: "Cambria", valign: "middle", align: "center" }); T(s, d[1], { x: 2.0, y, w: 2.85, h: 0.82, fontSize: 12.5, valign: "middle" }); });
  card(s, 5.2, 1.25, 4.3, 3.7);
  T(s, "Method", { x: 5.4, y: 1.35, w: 3.9, h: 0.35, fontSize: 15, bold: true, color: INK });
  T(s, ["URLs: group split by registered domain, train 5,865 / test 2,017", "E-mails: stratified split, train 1,800 / test 600", "Hard cases: clean-looking compromised sites, legit login pages, alarming-sounding genuine notices, polite phishing", "Positive class = phishing; threshold risk >= 50", "Fixed seed 42, fully reproducible"].map((t, i, a) => ({ text: t, options: { bullet: true, breakLine: i < a.length - 1 } })), { x: 5.4, y: 1.8, w: 3.95, h: 3.1, fontSize: 12, paraSpaceAfter: 6 });

  // 23 --------------------------------------------------------------- URL RESULTS
  s = content("Results: URL detection", "Held-out test set, 2,017 URLs. Hybrid blocking has the highest precision (0.971) and lowest false-positive rate of the learning systems; including warnings raises recall to 99.1%. Rules alone are precise but miss most attacks.");
  const sy = ["rules_only", "ml_only", "HYBRID (production)", "HYBRID flagged (WARN+BLOCK)"], nm = ["Rules only", "ML only", "Hybrid: block", "Hybrid: warn+block"];
  s.addChart(pres.charts.BAR, ["precision", "recall", "f1"].map((k, i) => ({ name: ["Precision", "Recall", "F1"][i], labels: nm, values: sy.map(y => +U.systems[y][k].toFixed(3)) })), { x: 0.4, y: 1.15, w: 6.2, h: 3.95, barDir: "col", barGrouping: "clustered", chartColors: [TEALD, GOLD, ALERT], showLegend: true, legendPos: "b", legendFontSize: 11, legendColor: TEXT, legendFontFace: "Calibri",
    showValue: true, dataLabelFontSize: 9, dataLabelColor: TEXT, dataLabelFormatCode: "0.00", dataLabelPosition: "outEnd", catAxisLabelFontSize: 10, catAxisLabelColor: TEXT, catAxisLabelFontFace: "Calibri", valAxisLabelFontSize: 10, valAxisLabelColor: MUTED, valAxisLabelFontFace: "Calibri", valAxisMaxVal: 1.1, valAxisMinVal: 0, valGridLine: { color: SOFT, size: 0.5 }, catGridLine: { style: "none" }, showTitle: true, title: "Test set: 2,017 URLs", titleFontSize: 13, titleColor: INK, titleFontFace: "Calibri" });
  [["97.1%", "precision (block)"], ["2.6%", "false-positive rate"], ["99.1%", "phishing flagged"], ["0.988", "ROC-AUC"]].forEach((c, i) => { const y = 1.2 + i * 0.97; card(s, 6.8, y, 2.7, 0.85, i % 2 ? WHITE : INK); T(s, c[0], { x: 6.9, y, w: 1.2, h: 0.85, fontSize: 22, bold: true, color: i % 2 ? TEALD : TEAL, fontFace: "Cambria", valign: "middle" }); T(s, c[1], { x: 8.05, y, w: 1.4, h: 0.85, fontSize: 11.5, color: i % 2 ? MUTED : "BFD0E0", valign: "middle" }); });

  // 24 --------------------------------------------------------------- TECHNIQUES
  s = content("Results: recall by attack technique", "Most techniques are blocked 100%. The weak spots are honest limitations: shorteners cannot be judged from the link text, so they are warned rather than blocked, and homograph domains are harder.");
  const tq = Object.entries(U.recall_by_technique).sort((a, b) => a[1].detected - b[1].detected).reverse();
  s.addChart(pres.charts.BAR, [{ name: "Blocked", labels: tq.map(x => x[0].replace("_", " ")), values: tq.map(x => +(x[1].detected * 100).toFixed(1)) }, { name: "Flagged (warn + block)", labels: tq.map(x => x[0].replace("_", " ")), values: tq.map(x => +(x[1].flagged * 100).toFixed(1)) }],
    { x: 0.4, y: 1.15, w: 6.3, h: 3.95, barDir: "bar", barGrouping: "clustered", chartColors: [TEALD, GOLD], showLegend: true, legendPos: "b", legendFontSize: 11, legendColor: TEXT, legendFontFace: "Calibri", catAxisOrientation: "maxMin", showValue: false, catAxisLabelFontSize: 10, catAxisLabelColor: TEXT, catAxisLabelFontFace: "Calibri", valAxisLabelFontSize: 10, valAxisLabelColor: MUTED, valAxisLabelFontFace: "Calibri", valAxisMaxVal: 100, valAxisMinVal: 0, valGridLine: { color: SOFT, size: 0.5 }, catGridLine: { style: "none" }, barGapWidthPct: 35, showTitle: true, title: "% of phishing URLs per technique (held-out test)", titleFontSize: 13, titleColor: INK, titleFontFace: "Calibri" });
  card(s, 6.9, 1.25, 2.6, 3.75);
  T(s, "Blocked / flagged", { x: 7.05, y: 1.35, w: 2.3, h: 0.3, fontSize: 14, bold: true, color: INK });
  [["10 techniques", "100% / 100%"], ["Hard clean", "94% / 100%"], ["Typosquat", "91% / 98%"], ["Homograph", "76% / 87%"], ["Shortener", "5% / 99%"]].forEach((r, i) => { const y = 1.8 + i * 0.62; T(s, r[0], { x: 7.05, y, w: 2.3, h: 0.25, fontSize: 12, color: MUTED }); T(s, r[1], { x: 7.05, y: y + 0.24, w: 2.3, h: 0.3, fontSize: 15, bold: true, color: i === 4 ? ALERT : TEALD }); });

  // 25 --------------------------------------------------------------- EMAIL RESULTS
  s = content("Results: e-mail detection", "Fusion beats any single signal and a test enforces that. The perfect AUC should be read with care because the data is synthetic; the headline lesson is that combining signals is better than any one.");
  const es = ["header_rules_only", "text_model_only", "FULL PIPELINE"], en = ["Header rules", "Text model", "Full pipeline"];
  s.addChart(pres.charts.BAR, ["precision", "recall", "f1"].map((k, i) => ({ name: ["Precision", "Recall", "F1"][i], labels: en, values: es.map(y => +E.systems[y][k].toFixed(3)) })), { x: 0.4, y: 1.15, w: 6.0, h: 3.95, barDir: "col", barGrouping: "clustered", chartColors: [TEALD, GOLD, ALERT], showLegend: true, legendPos: "b", legendFontSize: 11, legendColor: TEXT, legendFontFace: "Calibri",
    showValue: true, dataLabelFontSize: 9, dataLabelColor: TEXT, dataLabelFormatCode: "0.00", dataLabelPosition: "outEnd", catAxisLabelFontSize: 10, catAxisLabelColor: TEXT, catAxisLabelFontFace: "Calibri", valAxisLabelFontSize: 10, valAxisLabelColor: MUTED, valAxisLabelFontFace: "Calibri", valAxisMaxVal: 1.1, valAxisMinVal: 0, valGridLine: { color: SOFT, size: 0.5 }, catGridLine: { style: "none" }, showTitle: true, title: "Test set: 600 e-mails", titleFontSize: 13, titleColor: INK, titleFontFace: "Calibri" });
  s.addTable([[hdr("Full pipeline"), hdr("Count")]].concat([["True positives", "297"], ["True negatives", "300"], ["False positives", "0"], ["False negatives", "3"]].map(r => [cell(r[0], { fontSize: 12 }), cell(r[1], { bold: true, align: "center", fontSize: 12 })])), { x: 6.7, y: 1.3, w: 2.8, colW: [1.9, 0.9], rowH: 0.42, border: TB, fill: { color: WHITE }, valign: "middle" });
  T(s, "Recall by family: BEC 100%, attachment lures 100%, credential 98.8%, prize 97.3%", { x: 6.7, y: 3.65, w: 2.8, h: 1.0, fontSize: 12, color: MUTED });

  // 26 --------------------------------------------------------------- TESTING
  s = content("Testing: 75 of 75 pass", "Tests cover unit, integration, API and model-quality gates. Two real bugs were found by these tests during development (transposition typos and the HTML brand check). Logs are saved in logs/tests.log.");
  card(s, 0.5, 1.25, 2.6, 3.75, INK); T(s, "75", { x: 0.5, y: 1.6, w: 2.6, h: 1.2, fontSize: 72, bold: true, color: TEAL, align: "center", fontFace: "Cambria" }); T(s, "tests run", { x: 0.5, y: 2.85, w: 2.6, h: 0.4, fontSize: 16, color: WHITE, align: "center" }); T(s, "0 failures  |  0 errors  |  0 skipped", { x: 0.6, y: 3.4, w: 2.4, h: 0.7, fontSize: 12, color: "BFD0E0", align: "center" }); T(s, "Runtime about 2 s", { x: 0.5, y: 4.3, w: 2.6, h: 0.4, fontSize: 12, color: TEAL, align: "center" });
  const tt = [["URL features and rules", "22", "Parsing, every rule, evasion tricks, garbage input"], ["Detector and REST API", "16", "End-to-end verdicts, lists, feedback loop, 200/400/404"], ["Prevention", "8", "Lists, policy bands, defang, neutralise"], ["E-mail analyser", "7", "SPF/DKIM/DMARC, BEC, attachments, malformed"], ["Model quality gates", "7", "AUC, precision, FPR, fusion beats single signals"], ["HTML and dataset", "8", "Fake login, determinism, no domain leakage"], ["Interactive inspector", "7", "Step-by-step output for URL, e-mail, HTML, batch and bad input"]];
  s.addTable([[hdr("Area"), hdr("Tests"), hdr("What is checked")]].concat(tt.map(r => [cell(r[0], { bold: true }), cell(r[1], { align: "center", bold: true, color: TEALD }), cell(r[2], { fontSize: 10.5 })])), { x: 3.3, y: 1.25, w: 6.2, colW: [1.8, 0.7, 3.7], rowH: 0.44, border: TB, fill: { color: WHITE }, valign: "middle" });

  // 27 --------------------------------------------------------------- DEMO
  s = content("Live demo output", "These lines are real output from scripts/run_all.sh (saved in outputs/03_demo.txt). Run the script during the presentation to show all stages with logging.");
  s.addShape(pres.shapes.RECTANGLE, { x: 0.5, y: 1.2, w: 9, h: 2.75, fill: { color: INK }, line: { color: INK, width: 0 } });
  const dl = [["ALLOW      risk=  3.0  hxxps://www[.]wikipedia[.]org/wiki/Phishing", TEAL], ["ALLOW      risk=  6.4  hxxps://www[.]paypal[.]com/signin", TEAL], ["WARN       risk= 44.6  hxxps://bit[.]ly/3xYz9Qa   [shortener]", GOLD], ["BLOCK      risk= 99.1  hxxp://paypa1-secure-login[.]xyz/verify/account", ALERT], ["BLOCK      risk= 88.0  hxxps://paypal[.]com[.]account-verify[.]top/login", ALERT], ["BLOCK      risk= 98.5  hxxp://185[.]220[.]101[.]7:8080/chase/login[.]php", ALERT], ["QUARANTINE risk= 96.8  e-mail 'Request'  [exec_freemail, urgency, financial_lure]", ALERT], ["QUARANTINE risk= 94.6  e-mail 'Invoice_4471'  [dangerous_attachment, double_extension]", ALERT]];
  T(s, dl.map((l, i) => ({ text: l[0], options: { color: l[1], breakLine: i < dl.length - 1 } })), { x: 0.7, y: 1.35, w: 8.6, h: 2.8, fontSize: 11.5, fontFace: "Courier New", paraSpaceAfter: 5 });
  T(s, "Run everything with:  ./scripts/run_all.sh   (about 90 s; saves logs/, outputs/, reports/)", { x: 0.5, y: 4.3, w: 9, h: 0.4, fontSize: 15, bold: true, color: TEALD });

  // 28 --------------------------------------------------------------- LIMITS
  s = content("Limitations and future work", "Being candid about limits builds credibility. The synthetic-data point is the most important one for an evaluator.");
  card(s, 0.5, 1.25, 4.4, 3.75); card(s, 5.1, 1.25, 4.4, 3.75);
  circ(s, I.warn, 0.7, 1.4, 0.5, ALERT); T(s, "Limitations", { x: 1.35, y: 1.4, w: 3.4, h: 0.5, fontSize: 16, bold: true, color: INK, valign: "middle" });
  T(s, ["Data is synthetic; real-world accuracy will be lower", "Shortened or compromised-but-clean URLs cannot be judged lexically (routed to WARN)", "E-mail text model learns template vocabulary", "No JavaScript execution or visual similarity"].map((t, i, a) => ({ text: t, options: { bullet: true, breakLine: i < a.length - 1 } })), { x: 0.7, y: 2.1, w: 4.0, h: 2.8, fontSize: 12.5, paraSpaceAfter: 7 });
  circ(s, I.flask, 5.3, 1.4, 0.5, TEAL); T(s, "Future work", { x: 5.95, y: 1.4, w: 3.4, h: 0.5, fontSize: 16, bold: true, color: INK, valign: "middle" });
  T(s, ["Train on PhishTank / OpenPhish feeds", "Redirect expansion, domain age, TLS certificate and reputation lookups", "Screenshot and logo similarity", "Browser extension and mail-gateway plug-in", "Optional LLM explanations (Gemini hook included)"].map((t, i, a) => ({ text: t, options: { bullet: true, breakLine: i < a.length - 1 } })), { x: 5.3, y: 2.1, w: 4.0, h: 2.8, fontSize: 12.5, paraSpaceAfter: 7 });

  // 29 --------------------------------------------------------------- CONCLUSION
  s = pres.addSlide({ masterName: "DARK", sectionTitle: SEC });
  s.addText("Conclusion", { placeholder: "title" });
  s.addNotes("Close with the three takeaways and invite questions. Offer to run the demo script live.");
  [["Layered detection works", "Rules, ML and e-mail forensics together beat any single method."], ["Explainability builds trust", "Every verdict lists reasons and teaches the user what to look for."], ["Detection plus prevention", "Warn, block, quarantine, neutralise links and learn from each catch."]].forEach((c, i) => { const y = 2.35 + i * 0.8; circ(s, I.check, 0.7, y, 0.55, TEAL); T(s, c[0], { x: 1.5, y, w: 3.4, h: 0.55, fontSize: 17, bold: true, color: WHITE, valign: "middle" }); T(s, c[1], { x: 4.9, y, w: 4.6, h: 0.55, fontSize: 13, color: "BFD0E0", valign: "middle" }); });
  T(s, "Thank you. Questions?", { x: 0.7, y: 4.85, w: 6, h: 0.5, fontSize: 18, color: TEAL, bold: true });

  // 30 --------------------------------------------------------------- REFERENCES
  s = content("References", "Standards and papers behind the techniques used.");
  T(s, ["Sahoo, Liu, Hoi. Malicious URL Detection using Machine Learning: A Survey. arXiv:1701.07179, 2017.", "Kitterman. RFC 7208, Sender Policy Framework (SPF). 2014.", "Crocker et al. RFC 6376, DomainKeys Identified Mail (DKIM) Signatures. 2011.", "Kucherawy, Zwicky. RFC 7489, DMARC. 2015.", "Anti-Phishing Working Group (APWG). Phishing Activity Trends Reports.", "Breiman. Random Forests. Machine Learning 45, 2001.", "Friedman. Greedy Function Approximation: A Gradient Boosting Machine. Annals of Statistics, 2001.", "Damerau. A technique for computer detection and correction of spelling errors. CACM 7(3), 1964.", "Pedregosa et al. Scikit-learn: Machine Learning in Python. JMLR 12, 2011.", "PhishTank (phishtank.com) and OpenPhish (openphish.com): community phishing feeds."].map((t, i, a) => ({ text: t, options: { breakLine: i < a.length - 1 } })).map((r, i) => (r.text = (i + 1) + ".  " + r.text, r)), { x: 0.5, y: 1.25, w: 9, h: 3.8, fontSize: 12.5, paraSpaceAfter: 6 });

  await pres.writeFile({ fileName: "../PhishGuard_Presentation.pptx" });
  await applyTheme("../PhishGuard_Presentation.pptx", THEME);
  console.log("written");
})();
