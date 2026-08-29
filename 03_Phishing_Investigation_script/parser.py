import re
from email.utils import parseaddr

KNOWN_BRANDS = ["paypal", "microsoft", "apple", "amazon", "chase", "netflix", "irs"]


def domain_of(address):
    """Extract the domain from an email address string (handles display names)."""
    if address is None:
        return None
    display_name, clean_address = parseaddr(address)
    if not clean_address or "@" not in clean_address:
        return None
    return clean_address.split("@")[1]


def is_mismatch(domain_a, domain_b):
    """Compare two domains, ignoring subdomains. Returns False if either is missing."""
    if domain_a is None or domain_b is None:
        return False
    base_a = domain_a.lower().split(".")[-2:]
    base_b = domain_b.lower().split(".")[-2:]
    return base_a != base_b


def parse_auth_results(auth_header_text):
    """
    Parse an Authentication-Results header into {"spf": ..., "dkim": ..., "dmarc": ...}.
    Handles headers with multiple dkim=/spf=/dmarc= entries (common with third-party
    ESPs) by flagging "fail" if it appears anywhere, rather than only checking the
    first match.
    """
    if auth_header_text is None:
        return {}

    spf_matches = re.findall(r'spf=(\w+)', auth_header_text)
    dkim_matches = re.findall(r'dkim=(\w+)', auth_header_text)
    dmarc_matches = re.findall(r'dmarc=(\w+)', auth_header_text)

    def pick_verdict(matches):
        if "fail" in matches:
            return "fail"
        elif len(matches) > 0:
            return matches[0]
        else:
            return None

    return {
        "spf": pick_verdict(spf_matches),
        "dkim": pick_verdict(dkim_matches),
        "dmarc": pick_verdict(dmarc_matches),
    }


def extract_ip(received_line):
    """Extract the first IPv4 address found in a single Received header line."""
    if received_line is None:
        return None
    match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', received_line)
    return match.group() if match else None


def extract_all_ips(received_lines):
    """
    Extract IPs from a LIST of Received header lines (the full relay chain,
    e.g. from msg.get_all("Received")), not just the first/most recent hop.
    Returns a list of IPs found, in the same order as the input lines.
    Some hops (e.g. Gmail-internal routing) won't contain a dotted IP at all,
    and are simply skipped.
    """
    if not received_lines:
        return []
    ips = []
    for line in received_lines:
        ip = extract_ip(line)
        if ip:
            ips.append(ip)
    return ips


def is_brand_spoof(display_name, from_domain):
    """
    Check whether a known brand is referenced in the display name but the
    From domain does not belong to that brand (typosquat/impersonation pattern).
    """
    if display_name is None or from_domain is None:
        return False
    display_name = display_name.lower()
    from_domain = from_domain.lower()
    for brand in KNOWN_BRANDS:
        if brand in display_name and brand not in from_domain:
            return True
    return False


def score_email(auth_results, from_domain, reply_to_domain, return_path_domain, origin_ip, display_name):
    """
    Apply the weighted phishing rubric and return (score, verdict).

    Rubric:
      - SPF/DKIM/DMARC: any failure         -> +3 (flat, not stacked per-check)
      - Reply-To domain mismatches From      -> +2
      - Return-Path domain mismatches From   -> +2
      - Origin IP present in relay chain     -> +1
      - Display-name brand impersonation     -> +3

    Verdict thresholds:
      0-3  = Low Risk
      4-7  = Suspicious
      8+   = Likely Phishing
    """
    score = 0

    if "fail" in auth_results.values():
        score += 3

    if is_mismatch(from_domain, reply_to_domain):
        score += 2

    if is_mismatch(from_domain, return_path_domain):
        score += 2

    if origin_ip is not None:
        score += 1

    if is_brand_spoof(display_name, from_domain):
        score += 3

    if score >= 8:
        verdict = "Likely Phishing"
    elif score >= 4:
        verdict = "Suspicious"
    else:
        verdict = "Low Risk"

    return score, verdict