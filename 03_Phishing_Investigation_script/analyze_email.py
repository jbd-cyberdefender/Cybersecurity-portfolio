import email
from email import policy
from email.utils import parseaddr

from parser import (
    domain_of,
    is_mismatch,
    parse_auth_results,
    extract_ip,
    extract_all_ips,
    is_brand_spoof,
    score_email,
)


def analyze_email(filepath):
    """
    Reads a real .eml file (as downloaded from Gmail or Outlook) and runs it
    through the full phishing-detection pipeline. Returns a dict with the
    parsed fields, the score, the verdict, and which rules were triggered.
    """
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    msg = email.message_from_string(raw, policy=policy.default)

    display_name, from_address = parseaddr(msg.get("From", ""))
    from_domain = domain_of(msg.get("From"))
    reply_to_domain = domain_of(msg.get("Reply-To"))
    return_path_domain = domain_of(msg.get("Return-Path"))

    auth_text = msg.get("Authentication-Results")
    auth_results = parse_auth_results(auth_text)

    # Use the FULL Received chain, not just the first hop
    all_received = msg.get_all("Received", [])
    all_ips = extract_all_ips(all_received)
    origin_ip = all_ips[-1] if all_ips else None  # last hop = closest to true origin

    score, verdict = score_email(
        auth_results,
        from_domain,
        reply_to_domain,
        return_path_domain,
        origin_ip,
        display_name,
    )

    # Record which specific rules fired, for the report
    triggered = []
    if "fail" in auth_results.values():
        triggered.append(f"Authentication failure ({auth_results})")
    if is_mismatch(from_domain, reply_to_domain):
        triggered.append(f"Reply-To mismatch (From={from_domain}, Reply-To={reply_to_domain})")
    if is_mismatch(from_domain, return_path_domain):
        triggered.append(f"Return-Path mismatch (From={from_domain}, Return-Path={return_path_domain})")
    if origin_ip is not None:
        triggered.append(f"Origin IP present ({origin_ip})")
    if is_brand_spoof(display_name, from_domain):
        triggered.append(f"Brand impersonation in display name ('{display_name}' vs {from_domain})")

    return {
        "filepath": filepath,
        "subject": msg.get("Subject"),
        "display_name": display_name,
        "from_address": from_address,
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "auth_results": auth_results,
        "all_ips_in_chain": all_ips,
        "origin_ip": origin_ip,
        "score": score,
        "verdict": verdict,
        "triggered_findings": triggered,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python analyze_email.py path/to/email.eml")
        sys.exit(1)

    result = analyze_email(sys.argv[1])
    print(f"\nFile: {result['filepath']}")
    print(f"Subject: {result['subject']}")
    print(f"From: {result['display_name']} <{result['from_address']}>")
    print(f"Score: {result['score']}  ->  {result['verdict']}")
    print("Triggered findings:")
    if result["triggered_findings"]:
        for f in result["triggered_findings"]:
            print(f"  - {f}")
    else:
        print("  (none)")
