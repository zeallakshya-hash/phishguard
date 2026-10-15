# PhishGuard System Architecture & Operation Manual

## 1. Overview
PhishGuard is a real-time, heuristic-based phishing detection engine. Instead of relying solely on static blocklists, the system actively analyzes a URL across three distinct vectors: **URL Architecture**, **Domain & Reputation**, and **Content Integrity**. It uses a weighted scoring engine to evaluate the likelihood that a provided URL is attempting a phishing attack.

---

## 2. System Workflow
1. **User Input:** A URL is submitted via the UI dashboard.
2. **Preprocessing:** The backend API ensures the URL is properly formatted and includes a valid scheme (e.g., prepends `http://` if missing).
3. **Parallel Analysis:** The system invokes four specialized analyzer modules simultaneously.
4. **Score Aggregation:** The `calculate_score` engine aggregates the results, applying weighted risk points to triggered heuristic rules.
5. **Verdict Generation:** The final score determines the classification (SAFE, SUSPICIOUS, or PHISHING).
6. **Explainable Output:** The backend returns a detailed JSON object outlining exactly *why* the URL received its score, which is rendered dynamically on the frontend.

---

## 3. Analyzer Modules & Heuristics

### 3.1. Threat Intelligence & Allowlist Filter
- **Verified Global Allowlist (Tranco Top 10k) (0 pts / Bypass):** Verified enterprise root domains (`google.com`, `adobe.com`, `flipkart.com`, `amazon.com`, etc.) bypass heuristic risk penalties.
- **Google Safe Browsing (+100 pts):** Flagged by Google Safe Browsing API v4.
- **VirusTotal Malicious (+100 pts):** Multiple security engines flag target as malicious on VirusTotal v3.

### 3.2. URL Analyzer (`rules/url_analyzer.py`)
This module evaluates the structural composition and lexical features of the URL.
- **Excessive Length (+5 pts):** Total URL length exceeding 75 characters.
- **Credential-Harvesting Semantic Keywords (+10 pts per word):** Words like `login`, `verify`, `account`, `banking`, `security`, `signin`, `update`.
- **Random/Generated Subdomain (+10 pts):** High-entropy strings or algorithmic subdomain patterns.
- **URL Shorteners (+10 pts):** Bit.ly, tinyurl, t.co masking final destination.
- **Hyphenated Domain Correlation (+10 pts):** Multiple hyphens, or a single hyphen on a domain < 90 days old.
- **At-Symbol `x@y.com` (+15 pts):** Used to disguise the true landing host in browser address bars.
- **Excessive Subdomains (+15 pts):** Three or more subdomains (e.g. `login.secure.update.paypal.com`).
- **High-Risk TLD (+15 pts):** High-abuse top-level domains (`.top`, `.xyz`, `.tk`, `.ml`, `.cf`, etc.).
- **Non-Standard Port (+15 pts):** Ports other than 80 or 443 (e.g. `:8080`, `:8888`, `:2082`, `:8443`).
- **Obfuscated / Encoded IP (+20 pts):** DWORD, Hex, Octal, or zero-width unicode encoded IP addresses.
- **URL Concatenation / Glued Protocols (+25 pts):** Multiple embedded URLs/protocols or `@` redirect spoofing.
- **IP Address as Hostname (+30 pts):** Raw numeric IP used instead of a registered domain.
- **IDN Homograph / Punycode (+30 pts):** Lookalike Cyrillic/Greek characters or `xn--` Punycode spoofing.
- **Suspicious Tunneling/Temporary Host (+30 pts):** Cloudflare Tunnels (`trycloudflare.com`), Ngrok, etc.

### 3.3. Domain Analyzer (`rules/domain_analyzer.py`)
This module queries external WHOIS/RDAP records and DNS infrastructure.
- **Domain Age:**
  - `< 90 days old` = +10 pts
  - `< 30 days old` = +15 pts
  - `< 7 days old` = +25 pts
- **Missing / Invalid MX Records (+10 pts):** Absence of corporate mail exchange DNS records.
- **WHOIS Anomalies (+15 pts):** Missing or masked registrar and creation/expiration records.
- **Abuse of Free PaaS / Cloud Storage (+20 pts):** Hosted on free tiers of Firebase, Supabase, Vercel, Netlify, Render, GitHub Pages.
- **Dynamic DNS (+20 pts):** DuckDNS, No-IP, DynDNS frequently used for transient hosting.
- **Fast-Flux DNS (+20 pts):** Rapidly cycling IP addresses with low TTL (< 300s).
- **SSL Issues (+25 pts):** Non-HTTPS traffic or invalid/self-signed SSL certificates.

### 3.4. Content Analyzer (`rules/content_analyzer.py`)
This module scrapes and inspects the live DOM and scripts of the page.
- **Mismatched Favicon (+10 pts):** Favicon loaded directly from an external targeted brand server.
- **Anti-Analysis Blocking (+15 pts):** Script loops disabling devtools, inspection, or debuggers.
- **Right-Click Blocked (+15 pts):** Context menu disabled to impede manual inspection.
- **Client-Side Redirect (+15 pts):** Immediate JavaScript or meta refresh bounce.
- **Content Unreachable (+15 pts):** Server connection timeout or active geoblocking.
- **Hidden iFrames (+20 pts):** Invisible zero-size or `display:none` frames loading unauthorized content.
- **Obfuscated JavaScript (+20 pts):** High-entropy packed scripts, hex encodings, `eval()`, `unescape()`.
- **Decoy Captcha / Fake Turnstile (+25 pts):** Fake Cloudflare/Turnstile overlay to thwart automated crawlers.
- **External Form Target (+30 pts):** `<form action="...">` transmitting credentials to a third-party domain.
- **Password Field on HTTP (+35 pts):** Password input field on unencrypted HTTP page.
- **Highly Sensitive Inputs (+35 pts):** Demanding CVV, SSN, ATM PIN, or OTP credentials.
- **Connection Blocked by Antivirus (+100 pts):** Local endpoint security or firewall intercepted request.

### 3.5. Cloaking Analyzer (`rules/cloaking_analyzer.py`)
- **Cloaking Detected (+30 pts):** Distinct HTML delivered to security scanners vs normal desktop browsers.
- **Visual Logo Mismatch (+35 pts):** Authentic corporate brand logo found on an unrelated domain.

---

## 4. Scoring Engine (`engine/scoring.py`)
The scoring engine acts as the central brain. It takes the detailed outputs from all analyzers and aggregates the points.

**Verdict Thresholds:**
- **0 – 29 Points:** SAFE (`Legitimate`)
- **30 – 59 Points:** SUSPICIOUS
- **60 – 100 Points:** PHISHING

The final score is hard-capped at 100. The engine also categorizes the score into *URL Architecture*, *Domain & Reputation*, and *Content Integrity* to drive the visual telemetry charts in the UI.

---

## 5. UI & Explainability
PhishGuard is built with a focus on explainability. Instead of a black-box result, the frontend (`index.html` & `script.js`) parses the `reasons` and `technical_details` generated by the engine. 

When a scan is complete, the UI populates:
1. **Threat Telemetry Breakdown:** A Polar Area chart showing risk distribution.
2. **Detection Reasons:** Human-readable explanations for triggered rules (e.g., "Temporary tunnel hosting detected: Cloudflare Quick Tunnel").
3. **Technical Details:** Exact metrics such as the parsed registered domain name and precise domain age in days.
