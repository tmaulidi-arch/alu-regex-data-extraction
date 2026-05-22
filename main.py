import re
import json

with open("input/raw-text.txt", "r") as file:
    text = file.read()
    # Extract all email addresses from the text
email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
emails = re.findall(email_pattern, text)
# ALU specific email validation
alu_official = [e for e in emails if e.endswith('@alueducation.com')]
alu_alumni = [e for e in emails if e.endswith('@alumni.alueducation.com')]
alu_si = [e for e in emails if e.endswith('@si.alueducation.com')]
# Extract URLs from the text
url_pattern = r'https?://[a-zA-Z0-9./?=&_%-]+'
urls = re.findall(url_pattern, text)
# Extract phone numbers from the text   
phone_pattern = r'\+?[\d]{1,3}?[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{3,4}'
phones = re.findall(phone_pattern, text)
# Extract credit card numbers from the text
card_pattern = r'\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b'
cards = re.findall(card_pattern, text)
# Mask credit card numbers for security so they are not fully exposed in output
masked_cards = []
for card in cards:
    digits = card.replace(" ", "").replace("-", "")
    masked = "**** **** **** " + digits[-4:]
    masked_cards.append(masked)
    # Security check - reject suspicious or malicious input
dangerous_patterns = [
    r'<script.*?>',
    r'DROP\s+TABLE',
    r'javascript:',
    r'--',
]

flagged = []
for pattern in dangerous_patterns:
    matches = re.findall(pattern, text, re.IGNORECASE)
    if matches:
        flagged.append(pattern)
        # Build the final results dictionary
results = {
    "emails": {
        "all": emails,
        "alu_official": alu_official,
        "alu_alumni": alu_alumni,
        "alu_si": alu_si
    },
    "urls": urls,
    "phone_numbers": phones,
    "credit_cards": masked_cards,
    "security_flags": flagged
}
# Save the results to the output JSON file
with open("output/sample-output.json", "w") as output_file:
    json.dump(results, output_file, indent=4)

print("Extraction complete. Results saved to output/sample-output.json")