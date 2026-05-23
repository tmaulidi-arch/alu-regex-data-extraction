import re
import json
from pathlib import Path

# File locations
INPUT_FILE  = Path(__file__).parent.parent / "input" / "raw-text.txt"
OUTPUT_FILE = Path(__file__).parent.parent / "output" / "sample-output.json"

# These are known attack strings - if we find any of these in our data, we reject it
DANGEROUS_PATTERNS = [
    re.compile(r"<script.*?>.*?</script>",         re.IGNORECASE | re.DOTALL),
    re.compile(r"javascript\s*:",                  re.IGNORECASE),
    re.compile(r"vbscript\s*:",                    re.IGNORECASE),
    re.compile(r"data\s*:\s*text/html",            re.IGNORECASE),
    re.compile(r"file:///",                        re.IGNORECASE),
    re.compile(r"(DROP|DELETE|INSERT|SELECT|UPDATE)\s+\w+", re.IGNORECASE),
    re.compile(r"document\.(cookie|location|write)", re.IGNORECASE),
]

def is_dangerous(value):
    for pattern in DANGEROUS_PATTERNS:
        if pattern.search(value):
            return True
    return False

# Hide most of the card number and email before saving, so private info is never fully exposed
def mask_credit_card(number):
    digits = re.sub(r"\D", "", number)
    masked = "*" * (len(digits) - 4) + digits[-4:]
    return " ".join(masked[i:i+4] for i in range(0, len(masked), 4))

def mask_email(email):
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = "*" * len(local)
    else:
        masked_local = local[:2] + "***"
    return f"{masked_local}@{domain}"

# The Luhn algorithm is a standard bank check that catches fake card numbers
def luhn_check(number):
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    digits.reverse()
    total = 0
    for i, digit in enumerate(digits):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


# Regex patterns - each one describes the shape of the data we are looking for

EMAIL_PATTERN = re.compile(
    r"(?<!\S)"
    r"([a-zA-Z0-9._%+\-]+)"
    r"@"
    r"([a-zA-Z0-9.\-]+)"
    r"\."
    r"([a-zA-Z]{2,6})"
    r"(?!\S)"
)

ALU_OFFICIAL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+\-]+@alueducation\.com$",        re.IGNORECASE)
ALU_ALUMNI_PATTERN   = re.compile(r"^[a-zA-Z0-9._%+\-]+@alumni\.alueducation\.com$", re.IGNORECASE)
ALU_SI_PATTERN       = re.compile(r"^[a-zA-Z0-9._%+\-]+@si\.alueducation\.com$",    re.IGNORECASE)

def classify_email(email):
    if ALU_ALUMNI_PATTERN.match(email):
        return "alu_alumni"
    elif ALU_SI_PATTERN.match(email):
        return "alu_si"
    elif ALU_OFFICIAL_PATTERN.match(email):
        return "alu_official"
    else:
        return "external"

URL_PATTERN = re.compile(
    r"\b"
    r"(https?|ftp)"
    r"://"
    r"([a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)"
    r"\b"
)

PHONE_PATTERN = re.compile(
    r"(?<!\d)"
    r"(\+\d{1,3}[\s\-]?)"
    r"(\(?\d{1,4}\)?[\s\-]?)?"
    r"\d{2,4}"
    r"[\s\-]"
    r"\d{2,4}"
    r"([\s\-]\d{2,4})?"
    r"(?!\d)"
    r"|"
    r"(?<!\d)"
    r"0\d{2,3}"
    r"[\s\-]"
    r"\d{3,4}"
    r"([\s\-]\d{3,4})?"
    r"(?!\d)"
)

CREDIT_CARD_PATTERN = re.compile(
    r"\b"
    r"("
    r"\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}"
    r"|"
    r"\d{4}[\s\-]\d{6}[\s\-]\d{5}"
    r")"
    r"\b"
)

TIME_12H_PATTERN = re.compile(
    r"\b(1[0-2]|0?[1-9])"
    r":"
    r"([0-5][0-9])"
    r"\s?"
    r"([AaPp][Mm])"
    r"\b"
)

TIME_24H_PATTERN = re.compile(
    r"\b([01]\d|2[0-3])"
    r":"
    r"([0-5][0-9])"
    r"(?!\s?[AaPp][Mm])"
    r"\b"
)

HTML_TAG_PATTERN = re.compile(
    r"<"
    r"(/?)?"
    r"([a-zA-Z][a-zA-Z0-9]*)"
    r"([^>]{0,200})"
    r"(/?)?"
    r">"
)

HASHTAG_PATTERN = re.compile(
    r"(?<!\w)"
    r"#"
    r"(?=[a-zA-Z])"
    r"([a-zA-Z0-9_]{1,139})"
    r"(?!\w)"
)

CURRENCY_PATTERN = re.compile(
    r"(-?)"
    r"([$])"
    r"(\d{1,3}(?:,\d{3})*"
    r"(?:\.\d{1,2})?)"
)


def extract_all(text):
    results = {
        "emails":        {"alu_official": [], "alu_alumni": [], "alu_si": [], "external": [], "rejected": []},
        "urls":          {"valid": [], "rejected": []},
        "phone_numbers": {"valid": []},
        "credit_cards":  {"valid": [], "invalid_luhn": [], "rejected": []},
        "times":         {"12_hour": [], "24_hour": []},
        "html_tags":     {"found": []},
        "hashtags":      {"valid": [], "rejected": []},
        "currency":      {"found": []},
    }

    for match in EMAIL_PATTERN.finditer(text):
        email = match.group(0).strip()
        if is_dangerous(email):
            results["emails"]["rejected"].append({"value": "[REDACTED]", "reason": "injection pattern found"})
            continue
        if re.search(r'[;<>\'"\\]', email):
            results["emails"]["rejected"].append({"value": "[REDACTED]", "reason": "suspicious special characters"})
            continue
        category = classify_email(email)
        results["emails"][category].append(mask_email(email))

    for match in URL_PATTERN.finditer(text):
        url = match.group(0).strip()
        if re.search(r"(192\.168\.|10\.\d+\.\d+\.|127\.0\.0\.1|localhost)", url, re.IGNORECASE):
            results["urls"]["rejected"].append({"value": url, "reason": "private IP address"})
            continue
        if is_dangerous(url):
            results["urls"]["rejected"].append({"value": "[REDACTED]", "reason": "dangerous content"})
            continue
        results["urls"]["valid"].append(url)

    seen_phones = set()
    for match in PHONE_PATTERN.finditer(text):
        phone = match.group(0).strip()
        digits = re.sub(r"\D", "", phone)
        if not (7 <= len(digits) <= 15):
            continue
        if digits not in seen_phones:
            seen_phones.add(digits)
            results["phone_numbers"]["valid"].append(phone)

    for match in CREDIT_CARD_PATTERN.finditer(text):
        card = match.group(0).strip()
        if is_dangerous(card):
            results["credit_cards"]["rejected"].append({"value": "[REDACTED]", "reason": "dangerous content"})
            continue
        digits = re.sub(r"\D", "", card)
        if len(set(digits)) == 1:
            results["credit_cards"]["rejected"].append({"value": mask_credit_card(card), "reason": "all identical digits"})
            continue
        if luhn_check(card):
            results["credit_cards"]["valid"].append({
                "masked":  mask_credit_card(card),
                "length":  len(digits),
                "network": "Amex" if len(digits) == 15 else "Visa / Mastercard / Discover"
            })
        else:
            results["credit_cards"]["invalid_luhn"].append({"masked": mask_credit_card(card), "reason": "failed Luhn check"})

    seen_times = set()
    for match in TIME_12H_PATTERN.finditer(text):
        time_str = match.group(0).strip()
        if time_str not in seen_times:
            seen_times.add(time_str)
            results["times"]["12_hour"].append(time_str)

    for match in TIME_24H_PATTERN.finditer(text):
        time_str = match.group(0).strip()
        if time_str not in seen_times:
            seen_times.add(time_str)
            results["times"]["24_hour"].append(time_str)

    seen_tags = set()
    for match in HTML_TAG_PATTERN.finditer(text):
        tag = match.group(0)
        tag_name = match.group(2).lower() if match.group(2) else ""
        if tag_name == "script":
            continue
        if tag not in seen_tags:
            seen_tags.add(tag)
            results["html_tags"]["found"].append(tag)

    for match in HASHTAG_PATTERN.finditer(text):
        hashtag = "#" + match.group(1)
        if len(hashtag) < 3:
            results["hashtags"]["rejected"].append({"value": hashtag, "reason": "too short"})
            continue
        results["hashtags"]["valid"].append(hashtag)

    for match in CURRENCY_PATTERN.finditer(text):
        sign   = match.group(1)
        symbol = match.group(2)
        amount = match.group(3)
        results["currency"]["found"].append({"display": f"{sign}{symbol}{amount}", "symbol": symbol, "negative": sign == "-"})

    return results


def print_summary(results):
    print("\n" + "=" * 50)
    print("  RESULTS")
    print("=" * 50)
    e = results["emails"]
    print(f"\nEmails:  Official={len(e['alu_official'])}  Alumni={len(e['alu_alumni'])}  SI={len(e['alu_si'])}  External={len(e['external'])}  Rejected={len(e['rejected'])}")
    print(f"URLs:    Valid={len(results['urls']['valid'])}  Rejected={len(results['urls']['rejected'])}")
    print(f"Phones:  {len(results['phone_numbers']['valid'])} found")
    cc = results["credit_cards"]
    print(f"Cards:   Valid={len(cc['valid'])}  Failed Luhn={len(cc['invalid_luhn'])}  Rejected={len(cc['rejected'])}")
    t = results["times"]
    print(f"Times:   12hr={len(t['12_hour'])}  24hr={len(t['24_hour'])}")
    print(f"HTML tags: {len(results['html_tags']['found'])}")
    print(f"Hashtags:  {len(results['hashtags']['valid'])} valid")
    print(f"Currency:  {len(results['currency']['found'])} amounts")
    print("=" * 50 + "\n")


def main():
    print("Reading file...")
    try:
        raw_text = INPUT_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"ERROR: File not found at {INPUT_FILE}")
        return

    # Stop if the file is suspiciously large
    if len(raw_text) > 500_000:
        print("ERROR: File is too large. Stopping.")
        return

    results = extract_all(raw_text)
    print_summary(results)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"Saved to {OUTPUT_FILE}\n")


if __name__ == "__main__":
    main()
