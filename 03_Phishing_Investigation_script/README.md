
# Phishing Header Analyzer

A Python tool I built to parse raw email headers, extract indicators of
compromise (IOCs), and score messages against a weighted phishing-detection
rubric. It reads real `.eml` files exported from Gmail or Outlook and
produces a risk score, a verdict, and a breakdown of exactly which findings
triggered.

## How it works

The project is split into three files, each with a distinct job:

| File | Purpose |
|---|---|
| `parser.py` | Core logic — parsing, IOC extraction, and the scoring rubric. Never run directly; only imported. |
| `analyze_email.py` | Reads a real `.eml` file from disk and runs it through the full pipeline. This is the file you actually run. |
| `test_parser.py` | Regression tests against known synthetic cases. Run this after any change to `parser.py` to confirm nothing broke. |

### 1. Parsing headers

`analyze_email.py` reads the raw source of an `.eml` file and hands it to
Python's built-in `email` module, which turns it into a structured message
object you can query by header name (`From`, `Reply-To`, `Return-Path`,
`Authentication-Results`, `Received`, etc.).

From there, `parser.py` provides:

- **`domain_of(address)`** — pulls just the domain out of an address field,
  stripping any display name first (e.g. `"PayPal Security"
  <security@paypa1-support.com>` → `paypa1-support.com`).
- **`is_mismatch(domain_a, domain_b)`** — compares two domains (ignoring
  subdomains) to detect sender-identity misalignment, e.g. a `From` domain
  that doesn't match the `Reply-To` domain.
- **`parse_auth_results(auth_header_text)`** — extracts SPF, DKIM, and
  DMARC verdicts from the `Authentication-Results` header. Uses
  `re.findall()` rather than `re.search()` so it catches **every**
  spf=/dkim=/dmarc= entry in the header (real headers from third-party
  ESPs — e.g. a brand using Mailgun — often contain more than one DKIM
  result), and flags `fail` if it appears *anywhere*, not just in the
  first match found.
- **`extract_ip(received_line)`** / **`extract_all_ips(received_lines)`**
  — pull IPv4 addresses out of the `Received` relay chain. The full chain
  (not just the first/most-recent hop) is used so the origin server —
  not just the last internal routing hop — is captured.
- **`is_brand_spoof(display_name, from_domain)`** — flags a display name
  that references a known brand (PayPal, Microsoft, Amazon, etc.) while
  the actual sending domain does not belong to that brand — the classic
  typosquat/impersonation pattern (e.g. `"PayPal Security"` sent from
  `paypa1-support.com`).

### 2. Scoring rubric

Each finding contributes points on a 1–3 scale, combined into a single
score with a verdict:

| Finding | Points |
|---|---|
| SPF, DKIM, or DMARC failed (any of the three; flat, not stacked) | +3 |
| Reply-To domain mismatches From domain | +2 |
| Return-Path domain mismatches From domain | +2 |
| Origin IP present in the relay chain | +1 |
| Display-name brand impersonation | +3 |

**Verdict thresholds:**
- 0–3 → **Low Risk**
- 4–7 → **Suspicious**
- 8+ → **Likely Phishing**

The weights reflect how hard each signal is to fake: authentication
failure and brand impersonation are the strongest, hardest-to-fake
signals and are weighted highest; a bare IP address in the relay chain is
common in legitimate mail and is weighted lowest.

## Testing methodology

I validated the rubric against two kinds of data before trusting it:

**Synthetic test cases** (`test_parser.py`), each with a known expected
score, so any future change to `parser.py` can be checked for regressions
in seconds:
- **Malicious** — a fabricated PayPal-impersonation email (spoofed
  display name, failed auth, mismatched Reply-To) → 9, Likely Phishing
- **Clean** — a real recruiting email from `ntiva.com` with no anomalies
  → 1, Low Risk
- **Ambiguous** — a legitimate email using a third-party Reply-To domain
  (a pattern common with recruiting/ATS platforms) with clean
  authentication → 3, Low Risk
- **Multi-DKIM** — a synthetic case with two separate DKIM results in one
  header, one passing and one failing, to prove the `re.findall()` fix
  actually catches a failure that `re.search()` alone would have missed
  → 4, Suspicious


  ## Results

**Real-world validation**, run through `analyze_email.py` against actual
downloaded `.eml` files:

- **A real Outlier AI email** (`no-reply@outlier.ai`), received as part of
  a `recruiting@ntiva.com` correspondence — this was the source of the
  "Ambiguous" synthetic test case above. Confirming this legitimate,
  real-world Reply-To pattern scored Low Risk (rather than being
  over-flagged) was an important check against false positives.
- **Three additional real Gmail downloads** (a Google account-sharing
  notification, a Jimmy John's promotional email, and an Outlier AI
  email) — all correctly scored Low Risk with zero false positives, each
  only triggering the weakest rule (an IP simply present in the relay
  chain).
- **A real phishing sample pulled from a public GitHub phishing-sample
  repository** — a classic advance-fee ("419") scam email impersonating a
  diplomatic agent. This scored 6, Suspicious: SPF failed, DKIM/DMARC
  were unconfigured, and the Reply-To routed to a free Gmail address
  instead of the claimed sending domain. It did **not** reach "Likely
  Phishing," which is expected and explained below under Limitations.

  [Output of the phishing sample](./screenshots/phishing-sample-output.png)

  [Output of the outlier_AI email](./screenshots/Outlier.AI-email-output.png)

## Usage

```
python analyze_email.py path\to\email.eml
```

Download any email as `.eml`:
- **Gmail:** open the email → ⋮ menu → **Download message**
- **Outlook:** open the email → File → **Save As** → choose `.eml`


## Known limitations

- **Static header analysis only.** No live DNS/WHOIS lookups, IP
  geolocation, sender reputation checks, threat-intelligence API
  correlation, or sandbox detonation of links. No inspection of the
  message body or attachments — everything is derived from headers alone.
- **Scoped to sender-identity spoofing and brand impersonation.** The
  rubric was built around a specific phishing pattern: mismatched
  authentication, misaligned Reply-To/Return-Path, and brand
  impersonation in display names. It does **not** include keyword-based
  detection for narrative social-engineering scams (advance-fee/419
  fraud, romance scams, lottery scams, etc.), which rely on the *content*
  of the message rather than identity spoofing. Such messages may still
  score in the "Suspicious" range due to authentication and Reply-To
  anomalies (as seen in the real GitHub phishing sample above), but are
  not guaranteed to reach "Likely Phishing" without a dedicated
  content-based ruleset — a deliberate scope decision, not an oversight.
- **`Received` chain parsing is best-effort.** Some hops (particularly
  Gmail-internal routing lines) don't contain a dotted IPv4 address at
  all and are simply skipped rather than causing an error.
- **Domain comparison uses a simplified "last two labels" heuristic**
  (e.g. `mail.paypal.com` vs `paypal.com` are treated as the same base
  domain), which is not fully correct for multi-part TLDs like `.co.uk`.

## Possible future improvements

- Add a scam-keyword ruleset for advance-fee/social-engineering-style
  phishing, as a separate rule from brand impersonation
- Expand `KNOWN_BRANDS` beyond the current starter list
- Wire in the Markdown analyst-report generator to run automatically from
  `analyze_email.py`'s output
- Replace the "last two labels" domain comparison with a proper
  public-suffix-list-aware comparison
